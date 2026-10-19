// Package audit writes one JSON line per finished job.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Record struct {
	Time         time.Time `json:"time"`
	JobID        string    `json:"job_id"`
	Issuer       string    `json:"issuer"`
	Repo         string    `json:"repo"`
	Ref          string    `json:"ref"`
	SHA          string    `json:"sha,omitempty"`
	Event        string    `json:"event,omitempty"`
	RunID        string    `json:"run_id,omitempty"`
	RunURL       string    `json:"run_url,omitempty"`
	KeyID        string    `json:"key_id,omitempty"`
	KeyName      string    `json:"key_name,omitempty"`
	Profile      string    `json:"profile"`
	BundleID     string    `json:"bundle_id,omitempty"`
	InputSHA256  string    `json:"input_sha256,omitempty"`
	OutputSHA256 string    `json:"output_sha256,omitempty"`
	DMGSHA256    string    `json:"dmg_sha256,omitempty"`
	Result       string    `json:"result"`
	Error        string    `json:"error,omitempty"`
}

type Logger struct {
	mu sync.Mutex
	f  *os.File
}

func Open(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f}, nil
}

func (l *Logger) Write(r Record) error {
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.f.Write(append(b, '\n'))
	return err
}

func (l *Logger) Close() error { return l.f.Close() }
