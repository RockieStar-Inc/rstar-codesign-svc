package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/auth"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/jobs"
)

// Chunked uploads exist because proxies such as Cloudflare refuse request
// bodies over 100 MB. The client announces size and SHA-256, gets a queue
// slot and a disk reservation, PUTs fixed-size parts into one preallocated
// file, then completes the upload, which creates the job.

var (
	uploadIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sha256Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type upload struct {
	id        string
	identity  auth.Identity
	profile   string
	size      int64
	sha256    string
	partSize  int64
	path      string
	tokenHash string
	ticket    *jobs.Ticket

	mu       sync.Mutex
	received []bool
	inflight int
	lastSeen time.Time
	closed   bool // completed, aborted or expired
}

func (u *upload) parts() int64 { return (u.size + u.partSize - 1) / u.partSize }

func (u *upload) partLen(n int64) int64 {
	if n == u.parts()-1 {
		return u.size - n*u.partSize
	}
	return u.partSize
}

type uploadStore struct {
	mu sync.Mutex
	m  map[string]*upload
}

type createUploadRequest struct {
	Profile string `json:"profile"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

type createUploadResponse struct {
	UploadID    string `json:"upload_id"`
	UploadToken string `json:"upload_token"`
	PartSize    int64  `json:"part_size"`
	Parts       int64  `json:"parts"`
}

// createUpload admits an upload. The full allowlist check, including the
// profile, runs before anything is reserved.
func (s *Server) createUpload(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var req createUploadRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON body: "+err.Error())
		return
	}
	req.SHA256 = strings.ToLower(req.SHA256)
	switch {
	case !sha256Re.MatchString(req.SHA256):
		writeErr(w, http.StatusBadRequest, "sha256 must be 64 hex characters")
		return
	case req.Size <= 0:
		writeErr(w, http.StatusBadRequest, "size must be positive")
		return
	case req.Size > s.cfg.MaxUploadBytes:
		writeErr(w, http.StatusRequestEntityTooLarge, "upload is too large")
		return
	}
	if _, ok := s.cfg.Profile(req.Profile); !ok {
		writeErr(w, http.StatusForbidden, "profile "+req.Profile+" is not allowed")
		return
	}
	if ok, reason := auth.Allowed(s.cfg.Allow, id, req.Profile); !ok {
		log.Printf("denied %s %s@%s profile=%s: %s", id.Issuer, id.Repo, id.Ref, req.Profile, reason)
		writeErr(w, http.StatusForbidden, reason)
		return
	}
	ticket, ok := s.admit(w, id, req.Size)
	if !ok {
		return
	}
	u, token, err := s.newUpload(id, req, ticket)
	if err != nil {
		ticket.Release()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("upload %s started: %s %s@%s profile=%s size=%d parts=%d", u.id, id.Issuer, id.Repo, id.Ref, req.Profile, req.Size, u.parts())
	writeJSON(w, http.StatusCreated, createUploadResponse{UploadID: u.id, UploadToken: token, PartSize: u.partSize, Parts: u.parts()})
}

func (s *Server) newUpload(id auth.Identity, req createUploadRequest, ticket *jobs.Ticket) (*upload, string, error) {
	rb := make([]byte, 16+32)
	if _, err := rand.Read(rb); err != nil {
		return nil, "", err
	}
	u := &upload{
		id: hex.EncodeToString(rb[:16]), identity: id, profile: req.Profile,
		size: req.Size, sha256: req.SHA256, partSize: s.cfg.UploadPartBytes, ticket: ticket,
		lastSeen: s.now(),
	}
	token := base64.RawURLEncoding.EncodeToString(rb[16:])
	u.tokenHash = hashHex(token)
	u.received = make([]bool, u.parts())
	u.path = filepath.Join(s.jobs.UploadDir(), "chunked-"+u.id+".zip")
	f, err := os.OpenFile(u.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, "", err
	}
	err = f.Truncate(u.size)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(u.path)
		return nil, "", err
	}
	s.uploads.mu.Lock()
	s.uploads.m[u.id] = u
	s.uploads.mu.Unlock()
	return u, token, nil
}

// lookupUpload finds an open upload by id and upload token. Unknown id,
// wrong token and closed upload all look the same.
func (s *Server) lookupUpload(w http.ResponseWriter, r *http.Request) (*upload, bool) {
	tok, _ := bearer(r)
	id := r.PathValue("id")
	var u *upload
	if uploadIDRe.MatchString(id) && tok != "" {
		s.uploads.mu.Lock()
		u = s.uploads.m[id]
		s.uploads.mu.Unlock()
	}
	if u == nil || subtle.ConstantTimeCompare([]byte(hashHex(tok)), []byte(u.tokenHash)) != 1 {
		writeErr(w, http.StatusNotFound, "upload not found")
		return nil, false
	}
	return u, true
}

// putPart writes part n at offset n*part_size. Re-sending a part overwrites
// it. Every part except the last must be exactly part_size bytes.
func (s *Server) putPart(w http.ResponseWriter, r *http.Request) {
	u, ok := s.lookupUpload(w, r)
	if !ok {
		return
	}
	n, err := strconv.ParseInt(r.PathValue("n"), 10, 64)
	if err != nil || n < 0 || n >= u.parts() {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("part number must be 0 to %d", u.parts()-1))
		return
	}
	want := u.partLen(n)
	switch {
	case r.ContentLength < 0:
		writeErr(w, http.StatusLengthRequired, "Content-Length is required")
		return
	case r.ContentLength > u.partSize:
		writeErr(w, http.StatusRequestEntityTooLarge, "part is larger than part_size")
		return
	case r.ContentLength != want:
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("part %d must be %d bytes", n, want))
		return
	}

	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		writeErr(w, http.StatusNotFound, "upload not found")
		return
	}
	u.inflight++
	u.received[n] = false
	u.lastSeen = s.now()
	u.mu.Unlock()

	err = s.writePart(w, r, u, n, want)

	u.mu.Lock()
	u.inflight--
	u.lastSeen = s.now()
	if err == nil {
		u.received[n] = true
	}
	u.mu.Unlock()
	if err != nil {
		writeBodyErr(w, err, "write part")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writePart(w http.ResponseWriter, r *http.Request, u *upload, n, want int64) error {
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(s.cfg.UploadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	body := http.MaxBytesReader(w, r.Body, u.partSize)
	f, err := os.OpenFile(u.path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	written, err := io.Copy(io.NewOffsetWriter(f, n*u.partSize), io.LimitReader(body, want))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && written != want {
		err = fmt.Errorf("part %d: got %d bytes, want %d", n, written, want)
	}
	return err
}

// completeUpload checks that every part arrived and the file matches the
// announced size and SHA-256, then creates the job like POST /v1/jobs.
func (s *Server) completeUpload(w http.ResponseWriter, r *http.Request) {
	u, ok := s.lookupUpload(w, r)
	if !ok {
		return
	}
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		writeErr(w, http.StatusNotFound, "upload not found")
		return
	}
	if u.inflight > 0 {
		u.mu.Unlock()
		writeErr(w, http.StatusConflict, "parts are still being written")
		return
	}
	var missing []string
	for i, ok := range u.received {
		if !ok {
			missing = append(missing, strconv.Itoa(i))
		}
	}
	if len(missing) > 0 {
		u.mu.Unlock()
		if len(missing) > 20 {
			missing = append(missing[:20], "...")
		}
		writeErr(w, http.StatusConflict, "missing parts: "+strings.Join(missing, ","))
		return
	}
	u.closed = true // no more parts; the token dies with this call
	u.mu.Unlock()

	sum, size, err := fileSHA256(u.path)
	switch {
	case err != nil:
		s.abortUpload(u, "hash: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	case size != u.size:
		s.abortUpload(u, "size mismatch")
		writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("upload is %d bytes, announced %d", size, u.size))
		return
	case sum != u.sha256:
		s.abortUpload(u, "sha256 mismatch")
		writeErr(w, http.StatusUnprocessableEntity, "sha256 does not match the announced value")
		return
	}
	s.forgetUpload(u)
	job, token, err := s.jobs.Submit(u.ticket, u.identity, u.profile, u.path, sum)
	if err != nil {
		u.ticket.Release()
		os.Remove(u.path)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("job %s queued from upload %s: %s %s@%s profile=%s", job.ID, u.id, u.identity.Issuer, u.identity.Repo, u.identity.Ref, u.profile)
	writeJSON(w, http.StatusAccepted, createResponse{ID: job.ID, JobToken: token})
}

func (s *Server) forgetUpload(u *upload) {
	s.uploads.mu.Lock()
	delete(s.uploads.m, u.id)
	s.uploads.mu.Unlock()
}

// abortUpload drops an upload: its slot, reservation and file.
func (s *Server) abortUpload(u *upload, reason string) {
	s.forgetUpload(u)
	u.ticket.Release()
	if err := os.Remove(u.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("upload %s: remove: %v", u.id, err)
	}
	log.Printf("upload %s aborted: %s", u.id, reason)
}

// SweepUploads aborts uploads with no activity for upload_timeout.
func (s *Server) SweepUploads() {
	now := s.now()
	s.uploads.mu.Lock()
	var stale []*upload
	for _, u := range s.uploads.m {
		u.mu.Lock()
		if !u.closed && u.inflight == 0 && now.Sub(u.lastSeen) > s.cfg.UploadTimeout {
			u.closed = true
			stale = append(stale, u)
		}
		u.mu.Unlock()
	}
	s.uploads.mu.Unlock()
	for _, u := range stale {
		s.abortUpload(u, "expired")
	}
}

// Run sweeps abandoned uploads until ctx ends. Uploads left from a previous
// run are deleted by jobs.New, and their reservations never existed.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SweepUploads()
		}
	}
}

func fileSHA256(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func hashHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
