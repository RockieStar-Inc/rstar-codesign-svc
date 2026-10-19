// Package jobs keeps the job queue and runs one job at a time.
package jobs

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
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/audit"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/auth"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/sign"
)

type Status string

const (
	Queued     Status = "queued"
	Signing    Status = "signing"
	Notarizing Status = "notarizing"
	Done       Status = "done"
	Failed     Status = "failed"
)

func (s Status) Finished() bool { return s == Done || s == Failed }

var (
	ErrQueueFull = errors.New("queue is full")
	ErrDiskLow   = errors.New("not enough free disk space")
)

// Artifact is one result file.
type Artifact struct {
	SHA256   string `json:"sha256"`
	NotaryID string `json:"notary_id,omitempty"`
}

// Job is persisted as job.json in its directory.
type Job struct {
	ID        string        `json:"id"`
	Status    Status        `json:"status"`
	Error     string        `json:"error,omitempty"`
	Profile   string        `json:"profile"`
	Issuer    string        `json:"issuer"`
	Repo      string        `json:"repo"`
	Identity  auth.Identity `json:"identity"`
	TokenHash string        `json:"token_hash"`
	// ReservedBytes is the disk space promised to this job until it finishes.
	ReservedBytes int64 `json:"reserved_bytes,omitempty"`
	// reserved is true while ReservedBytes is counted in Manager.reserved.
	reserved    bool
	Name        string `json:"name,omitempty"`
	BundleID    string `json:"bundle_id,omitempty"`
	InputSHA256 string `json:"input_sha256"`
	// Stage and NotarySubmission let a restart resume notary polling.
	Stage            string               `json:"stage,omitempty"`
	NotarySubmission string               `json:"notary_submission,omitempty"`
	Artifacts        map[string]*Artifact `json:"artifacts,omitempty"`
	// SigningReport lists every signed item with its type and entitlements.
	SigningReport []sign.ReportItem `json:"signing_report,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	StartedAt     time.Time         `json:"started_at,omitzero"`
	FinishedAt    time.Time         `json:"finished_at,omitzero"`
}

func (j *Job) clone() Job {
	c := *j
	c.SigningReport = slices.Clone(j.SigningReport)
	c.Artifacts = map[string]*Artifact{}
	for k, v := range j.Artifacts {
		a := *v
		c.Artifacts[k] = &a
	}
	return c
}

// Manager owns all jobs.
type Manager struct {
	cfg    *config.Config
	run    runner.Runner
	audit  *audit.Logger
	pwFile string

	// FreeBytes reports free disk space; tests replace it.
	FreeBytes func(dir string) (uint64, error)
	// PollInterval is the wait between notarytool info calls.
	PollInterval time.Duration
	now          func() time.Time
	retryDelay   time.Duration
	resume       []string // jobs to resume first, after a restart

	mu       sync.Mutex
	jobs     map[string]*Job
	reserved int64         // disk promised to admitted, unfinished jobs
	slots    chan struct{} // one per queued or reserved job
	queue    chan string
}

// New loads saved jobs from work_dir. Jobs that were running when the
// service stopped are marked failed.
func New(cfg *config.Config, r runner.Runner, al *audit.Logger) (*Manager, error) {
	m := &Manager{
		cfg:          cfg,
		run:          r,
		audit:        al,
		pwFile:       os.Getenv("CODESIGN_KEYCHAIN_PASSWORD_FILE"),
		FreeBytes:    freeBytes,
		PollInterval: 20 * time.Second,
		now:          time.Now,
		retryDelay:   5 * time.Second,
		jobs:         map[string]*Job{},
		slots:        make(chan struct{}, cfg.QueueSize),
		queue:        make(chan string, cfg.QueueSize),
	}
	if err := checkWorkDir(cfg.WorkDir); err != nil {
		return nil, err
	}
	for _, d := range []string{m.jobsDir(), m.uploadsDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	// Uploads that never became jobs.
	if ents, err := os.ReadDir(m.uploadsDir()); err == nil {
		for _, e := range ents {
			os.RemoveAll(filepath.Join(m.uploadsDir(), e.Name()))
		}
	}
	ents, err := os.ReadDir(m.jobsDir())
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !ValidID(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.jobsDir(), e.Name(), "job.json"))
		if err != nil {
			log.Printf("skip job dir %s: %v", e.Name(), err)
			continue
		}
		var j Job
		if err := json.Unmarshal(b, &j); err != nil || j.ID != e.Name() {
			log.Printf("skip job dir %s: bad job.json", e.Name())
			continue
		}
		if j.Artifacts == nil {
			j.Artifacts = map[string]*Artifact{}
		}
		m.jobs[j.ID] = &j
		if j.Status.Finished() {
			continue
		}
		if j.Status == Notarizing && j.NotarySubmission != "" {
			m.reserved += j.ReservedBytes
			j.reserved = true
			log.Printf("job %s: resuming notarization %s", j.ID, j.NotarySubmission)
			m.resume = append(m.resume, j.ID)
			continue
		}
		m.finish(&j, fmt.Errorf("interrupted by service restart while %s", j.Status))
	}
	return m, nil
}

func (m *Manager) jobsDir() string          { return filepath.Join(m.cfg.WorkDir, "jobs") }
func (m *Manager) uploadsDir() string       { return filepath.Join(m.cfg.WorkDir, "uploads") }
func (m *Manager) dir(id string) string     { return filepath.Join(m.jobsDir(), id) }
func (m *Manager) workDir(id string) string { return filepath.Join(m.dir(id), "work") }
func (m *Manager) outDir(id string) string  { return filepath.Join(m.dir(id), "out") }

// UploadDir is where the server writes uploads before they become jobs.
func (m *Manager) UploadDir() string { return m.uploadsDir() }

// Ticket holds one queue slot and a disk reservation between admission
// and submit.
type Ticket struct {
	m        *Manager
	estimate int64
	once     sync.Once
	used     bool
}

// Reserve takes a queue slot and reserves estimate bytes of disk. Free space
// minus every reservation must stay at or above min_free_bytes. Call it
// before reading the upload; release the ticket if the upload fails.
func (m *Manager) Reserve(estimate int64) (*Ticket, error) {
	free, err := m.FreeBytes(m.cfg.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("check free disk: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if int64(min(free, 1<<62))-m.reserved-estimate < m.cfg.MinFreeBytes {
		return nil, ErrDiskLow
	}
	select {
	case m.slots <- struct{}{}:
		m.reserved += estimate
		return &Ticket{m: m, estimate: estimate}, nil
	default:
		return nil, ErrQueueFull
	}
}

// Release gives the slot and the reservation back. It does nothing after Submit.
func (t *Ticket) Release() {
	t.once.Do(func() {
		if !t.used {
			<-t.m.slots
			t.m.mu.Lock()
			t.m.reserved -= t.estimate
			t.m.mu.Unlock()
		}
	})
}

// Reserved returns the disk space promised to unfinished jobs.
func (m *Manager) Reserved() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reserved
}

// Submit turns an upload into a queued job. It returns the job and the job
// token; only the token's SHA-256 is stored.
func (m *Manager) Submit(t *Ticket, id auth.Identity, profile, upload, inputSHA string) (Job, string, error) {
	jobID, err := randomString(16, hex.EncodeToString)
	if err != nil {
		return Job{}, "", err
	}
	token, err := randomString(32, base64.RawURLEncoding.EncodeToString)
	if err != nil {
		return Job{}, "", err
	}
	if err := os.MkdirAll(m.workDir(jobID), 0o700); err != nil {
		return Job{}, "", err
	}
	if err := os.Rename(upload, filepath.Join(m.workDir(jobID), "input.zip")); err != nil {
		os.RemoveAll(m.dir(jobID))
		return Job{}, "", err
	}
	now := m.now().UTC()
	j := &Job{
		ID: jobID, Status: Queued, Profile: profile,
		Issuer: id.Issuer, Repo: id.Repo, Identity: id,
		TokenHash: hashToken(token), InputSHA256: inputSHA, ReservedBytes: t.estimate, reserved: true,
		Artifacts: map[string]*Artifact{}, CreatedAt: now, UpdatedAt: now,
	}
	m.mu.Lock()
	m.jobs[jobID] = j
	m.save(j)
	out := j.clone() // the worker may change j once it is queued
	m.mu.Unlock()

	t.once.Do(func() { t.used = true })
	m.queue <- jobID // never blocks: the ticket holds a slot
	return out, token, nil
}

var jobIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidID reports whether id has the job id format.
func ValidID(id string) bool { return jobIDRe.MatchString(id) }

// Authorize returns the job when token is its job token.
func (m *Manager) Authorize(id, token string) (Job, bool) {
	if !ValidID(id) {
		return Job{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok || token == "" {
		return Job{}, false
	}
	if subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(j.TokenHash)) != 1 {
		return Job{}, false
	}
	return j.clone(), true
}

// ArtifactPath returns the file for a finished job's artifact.
func (m *Manager) ArtifactPath(j Job, kind string) (string, bool) {
	if j.Status != Done || j.Artifacts[kind] == nil {
		return "", false
	}
	p := filepath.Join(m.outDir(j.ID), j.Name+"."+kind)
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, true
}

// Start runs the worker and the cleanup loop until ctx ends.
func (m *Manager) Start(ctx context.Context) {
	resume := m.resume
	m.resume = nil
	go func() {
		for _, id := range resume {
			if ctx.Err() != nil {
				return
			}
			m.process(ctx, id)
		}
		for {
			select {
			case <-ctx.Done():
				return
			case id := <-m.queue:
				<-m.slots
				m.process(ctx, id)
			}
		}
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Sweep()
			}
		}
	}()
}

// Sweep deletes finished jobs older than the TTL, then the oldest finished
// jobs over max_retained_jobs.
func (m *Manager) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var finished []*Job
	for _, j := range m.jobs {
		if !j.Status.Finished() {
			continue
		}
		if now.Sub(j.FinishedAt) > m.cfg.ResultTTL {
			m.remove(j)
			continue
		}
		finished = append(finished, j)
	}
	slices.SortFunc(finished, func(a, b *Job) int { return a.FinishedAt.Compare(b.FinishedAt) })
	for len(finished) > m.cfg.MaxRetainedJobs {
		m.remove(finished[0])
		finished = finished[1:]
	}
}

func (m *Manager) remove(j *Job) {
	if err := os.RemoveAll(m.dir(j.ID)); err != nil {
		log.Printf("job %s: cleanup: %v", j.ID, err)
		return
	}
	delete(m.jobs, j.ID)
}

func (m *Manager) setStatus(j *Job, s Status) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j.Status = s
	j.UpdatedAt = m.now().UTC()
	m.save(j)
}

func (m *Manager) update(j *Job, f func(*Job)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(j)
	j.UpdatedAt = m.now().UTC()
	m.save(j)
}

// finish records the result, deletes the input and work tree, and writes
// the audit line.
func (m *Manager) finish(j *Job, err error) {
	if rmErr := os.RemoveAll(m.workDir(j.ID)); rmErr != nil {
		log.Printf("job %s: remove work dir: %v", j.ID, rmErr)
	}
	m.update(j, func(j *Job) {
		if j.reserved {
			m.reserved -= j.ReservedBytes
			j.reserved = false
		}
		j.ReservedBytes = 0
		j.Status = Done
		if err != nil {
			j.Status = Failed
			j.Error = err.Error()
		}
		j.FinishedAt = m.now().UTC()
	})
	rec := audit.Record{
		JobID: j.ID, Issuer: j.Issuer, Repo: j.Repo, Ref: j.Identity.Ref, SHA: j.Identity.SHA,
		Event: j.Identity.Event, RunID: j.Identity.RunID, RunURL: j.Identity.RunURL,
		KeyID: j.Identity.KeyID, KeyName: j.Identity.KeyName,
		Profile: j.Profile, BundleID: j.BundleID, InputSHA256: j.InputSHA256,
		Result: string(j.Status), Error: j.Error,
	}
	if a := j.Artifacts["zip"]; a != nil {
		rec.OutputSHA256 = a.SHA256
	}
	if a := j.Artifacts["dmg"]; a != nil {
		rec.DMGSHA256 = a.SHA256
	}
	if m.audit != nil {
		if err := m.audit.Write(rec); err != nil {
			log.Printf("job %s: audit: %v", j.ID, err)
		}
	}
	log.Printf("job %s: %s %s@%s profile=%s: %s %s", j.ID, j.Issuer, j.Repo, j.Identity.Ref, j.Profile, j.Status, j.Error)
}

// save writes job.json. Caller holds m.mu.
func (m *Manager) save(j *Job) {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		log.Printf("job %s: marshal: %v", j.ID, err)
		return
	}
	p := filepath.Join(m.dir(j.ID), "job.json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		log.Printf("job %s: save: %v", j.ID, err)
	}
}

// checkWorkDir creates the work dir with mode 0700 and refuses one that
// other users can write.
func checkWorkDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("work_dir %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("work_dir %s is writable by others (mode %o); chmod 700 it", dir, fi.Mode().Perm())
	}
	return nil
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func randomString(n int, enc func([]byte) string) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return enc(b), nil
}

func freeBytes(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
