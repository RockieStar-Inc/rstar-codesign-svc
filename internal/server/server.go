// Package server is the HTTP API.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/auth"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/jobs"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/sign"
)

// Authenticator turns a bearer token into an identity.
type Authenticator interface {
	Verify(ctx context.Context, raw string) (auth.Identity, error)
}

type Server struct {
	cfg     *config.Config
	auth    Authenticator
	jobs    *jobs.Manager
	replay  *auth.ReplayCache
	script  []byte
	uploads uploadStore
	now     func() time.Time
}

// New builds the server. script is the client script served at
// /client/sign.sh (may be nil).
func New(cfg *config.Config, a Authenticator, m *jobs.Manager, script []byte) *Server {
	return &Server{cfg: cfg, auth: a, jobs: m, replay: auth.NewReplayCache(), script: script,
		uploads: uploadStore{m: map[string]*upload{}}, now: time.Now}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /client/sign.sh", func(w http.ResponseWriter, r *http.Request) {
		if s.script == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Write(s.script)
	})
	mux.HandleFunc("POST /v1/jobs", s.createJob)
	mux.HandleFunc("POST /v1/uploads", s.createUpload)
	mux.HandleFunc("PUT /v1/uploads/{id}/parts/{n}", s.putPart)
	mux.HandleFunc("POST /v1/uploads/{id}/complete", s.completeUpload)
	mux.HandleFunc("GET /v1/jobs/{id}", s.getJob)
	mux.HandleFunc("GET /v1/jobs/{id}/artifact", s.getArtifact)
	return mux
}

type createResponse struct {
	ID       string `json:"id"`
	JobToken string `json:"job_token"`
}

// createJob checks the token and admission before it reads the body. The
// multipart body must send the "profile" field before the "file" field, so
// the allowlist is checked before the upload is stored.
func (s *Server) createJob(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if r.ContentLength < 0 {
		writeErr(w, http.StatusLengthRequired, "Content-Length is required")
		return
	}
	maxBody := s.cfg.MaxUploadBytes + 1<<20
	if r.ContentLength > maxBody {
		writeErr(w, http.StatusRequestEntityTooLarge, "upload is too large")
		return
	}
	ticket, ok := s.admit(w, id, r.ContentLength)
	if !ok {
		return
	}
	defer ticket.Release()

	// A stalled upload must not hold the slot forever.
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(s.cfg.UploadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "expected multipart/form-data")
		return
	}
	part, err := mr.NextPart()
	if err != nil {
		writeBodyErr(w, err, `the first form field must be "profile"`)
		return
	}
	if part.FormName() != "profile" {
		writeErr(w, http.StatusBadRequest, `the first form field must be "profile"`)
		return
	}
	pb, err := io.ReadAll(io.LimitReader(part, 257))
	if err != nil || len(pb) > 256 {
		writeBodyErr(w, err, "bad profile field")
		return
	}
	profile := strings.TrimSpace(string(pb))
	if _, ok := s.cfg.Profile(profile); !ok {
		writeErr(w, http.StatusForbidden, "profile "+profile+" is not allowed")
		return
	}
	if ok, reason := auth.Allowed(s.cfg.Allow, id, profile); !ok {
		log.Printf("denied %s %s@%s profile=%s: %s", id.Issuer, id.Repo, id.Ref, profile, reason)
		writeErr(w, http.StatusForbidden, reason)
		return
	}

	part, err = mr.NextPart()
	if err != nil {
		writeBodyErr(w, err, `the second form field must be "file"`)
		return
	}
	if part.FormName() != "file" {
		writeErr(w, http.StatusBadRequest, `the second form field must be "file"`)
		return
	}
	upload, sum, err := s.saveUpload(part)
	if err != nil {
		writeBodyErr(w, err, "read upload")
		return
	}
	job, token, err := s.jobs.Submit(ticket, id, profile, upload, sum)
	if err != nil {
		os.Remove(upload)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("job %s queued: %s %s@%s profile=%s", job.ID, id.Issuer, id.Repo, id.Ref, profile)
	writeJSON(w, http.StatusAccepted, createResponse{ID: job.ID, JobToken: token})
}

func (s *Server) saveUpload(part io.Reader) (string, string, error) {
	f, err := os.CreateTemp(s.jobs.UploadDir(), "upload-*.zip")
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(part, s.cfg.MaxUploadBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > s.cfg.MaxUploadBytes {
		err = &http.MaxBytesError{Limit: s.cfg.MaxUploadBytes}
	}
	if err == nil && n == 0 {
		err = errors.New("empty file")
	}
	if err != nil {
		os.Remove(f.Name())
		return "", "", err
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

type statusResponse struct {
	ID        string                    `json:"id"`
	Status    jobs.Status               `json:"status"`
	Error     string                    `json:"error,omitempty"`
	Profile   string                    `json:"profile"`
	BundleID  string                    `json:"bundle_id,omitempty"`
	Artifacts map[string]*jobs.Artifact `json:"artifacts"`
	// SigningReport lists every signed path, its type and entitlements file.
	SigningReport []sign.ReportItem `json:"signing_report,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// authorizeJob checks the job token. Unknown job and wrong token look the same.
func (s *Server) authorizeJob(w http.ResponseWriter, r *http.Request) (jobs.Job, bool) {
	tok, _ := bearer(r)
	j, ok := s.jobs.Authorize(r.PathValue("id"), tok)
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
	}
	return j, ok
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	j, ok := s.authorizeJob(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{
		ID: j.ID, Status: j.Status, Error: j.Error, Profile: j.Profile, BundleID: j.BundleID,
		Artifacts: j.Artifacts, SigningReport: j.SigningReport, CreatedAt: j.CreatedAt, UpdatedAt: j.UpdatedAt,
	})
}

func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	j, ok := s.authorizeJob(w, r)
	if !ok {
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "zip"
	}
	if kind != "zip" && kind != "dmg" {
		writeErr(w, http.StatusBadRequest, "kind must be zip or dmg")
		return
	}
	if j.Status != jobs.Done {
		writeErr(w, http.StatusConflict, "job is "+string(j.Status))
		return
	}
	p, ok := s.jobs.ArtifactPath(j, kind)
	if !ok {
		writeErr(w, http.StatusNotFound, "no "+kind+" artifact for this job")
		return
	}
	f, err := os.Open(p)
	if err != nil {
		writeErr(w, http.StatusNotFound, "artifact is gone")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(p)}))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", st.ModTime(), f)
}

// authenticate checks the bearer token, the identity part of the allowlist
// and (read-only) replay. Nothing is reserved yet.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (auth.Identity, bool) {
	raw, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing bearer token")
		return auth.Identity{}, false
	}
	id, err := s.auth.Verify(r.Context(), raw)
	if err != nil {
		status := http.StatusUnauthorized
		if !errors.Is(err, auth.ErrUnauthorized) {
			status = http.StatusBadGateway
		}
		log.Printf("auth failed: %v", err)
		writeErr(w, status, err.Error())
		return auth.Identity{}, false
	}
	if ok, reason := auth.AllowedAny(s.cfg.Allow, id); !ok {
		log.Printf("denied %s %s@%s: %s", id.Issuer, id.Repo, id.Ref, reason)
		writeErr(w, http.StatusForbidden, reason)
		return auth.Identity{}, false
	}
	if err := s.replay.Check(id); err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return auth.Identity{}, false
	}
	return id, true
}

// admit takes a queue slot and reserves disk for an upload of uploadBytes:
// the upload plus up to max_expanded_bytes for each of the unpacked app, the
// notary and output zips, and the DMG staging copy plus DMG. Only then is the
// token burned, so a 429 or 503 leaves it usable. The caller releases the
// ticket unless it hands it to a job.
func (s *Server) admit(w http.ResponseWriter, id auth.Identity, uploadBytes int64) (*jobs.Ticket, bool) {
	ticket, err := s.jobs.Reserve(uploadBytes + 3*s.cfg.MaxExpandedBytes)
	switch {
	case errors.Is(err, jobs.ErrQueueFull):
		writeErr(w, http.StatusTooManyRequests, err.Error())
		return nil, false
	case errors.Is(err, jobs.ErrDiskLow):
		writeErr(w, http.StatusServiceUnavailable, err.Error())
		return nil, false
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	if err := s.replay.Use(id); err != nil {
		ticket.Release()
		writeErr(w, http.StatusUnauthorized, err.Error())
		return nil, false
	}
	return ticket, true
}

// writeBodyErr maps a request body error to a status.
func writeBodyErr(w http.ResponseWriter, err error, msg string) {
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		writeErr(w, http.StatusRequestEntityTooLarge, "upload is too large")
	case errors.Is(err, os.ErrDeadlineExceeded):
		writeErr(w, http.StatusRequestTimeout, "upload timed out")
	case err != nil:
		writeErr(w, http.StatusBadRequest, msg+": "+err.Error())
	default:
		writeErr(w, http.StatusBadRequest, msg)
	}
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		tok, ok = strings.CutPrefix(h, "bearer ")
	}
	tok = strings.TrimSpace(tok)
	return tok, ok && tok != ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
