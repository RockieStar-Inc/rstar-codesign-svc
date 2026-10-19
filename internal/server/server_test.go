package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/audit"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/auth"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/jobs"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/testutil"
)

const gh = config.GitHubIssuer

type fakeAuth map[string]auth.Identity

func (f fakeAuth) Verify(ctx context.Context, raw string) (auth.Identity, error) {
	if id, ok := f[raw]; ok {
		return id, nil
	}
	return auth.Identity{}, fmt.Errorf("%w: bad token", auth.ErrUnauthorized)
}

func identity(jti string) auth.Identity {
	return auth.Identity{Issuer: gh, Kind: config.KindGitHub, Repo: "example/app", Ref: "refs/heads/main",
		RefProtected: true, Event: "push", JTI: jti, SHA: "abc123", RunID: "1"}
}

type env struct {
	srv    *httptest.Server
	api    *Server
	m      *jobs.Manager
	r      *testutil.FakeRunner
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc
}

func newEnv(t *testing.T, queue int, start bool) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		WorkDir: filepath.Join(dir, "work"), AuditLog: filepath.Join(dir, "audit.jsonl"),
		QueueSize: queue, ResultTTL: time.Hour, JobTimeout: time.Minute, UploadTimeout: time.Minute,
		MaxUploadBytes: 1 << 20, UploadPartBytes: 4096, MaxExpandedBytes: 1 << 24, MaxFiles: 1000,
		MinFreeBytes: 1, MaxRetainedJobs: 20,
		Allow: []config.Rule{{Issuer: gh, Repo: "example/app", Refs: []string{"refs/heads/main"}, Profiles: []string{"release"}}},
		Profiles: []config.Profile{{
			Name: "release", Identity: "Developer ID Application: Example Corp (TEAMID1234)",
			Keychain: "/k/signing.keychain-db", TeamID: testutil.TeamID,
			AllowedBundleIDs: []string{"com.example.app"}, Entitlements: "/k/main.plist",
			Notary: config.Notary{APIKeyPath: "/k/AuthKey.p8", KeyID: "ABCDE12345", IssuerID: "6053b7fe-68a8-4acb-89be-165aa6465141"},
			DMG:    true, VolumeName: "Example",
		}},
	}
	al, err := audit.Open(cfg.AuditLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	r := &testutil.FakeRunner{NotaryStatuses: []string{"In Progress", "Accepted"}}
	m, err := jobs.New(cfg, r, al)
	if err != nil {
		t.Fatal(err)
	}
	m.PollInterval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if start {
		m.Start(ctx)
	}
	fa := fakeAuth{}
	for _, j := range []string{"t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8"} {
		fa[j] = identity("jti-" + j)
	}
	other := identity("jti-other")
	other.Ref = "refs/heads/dev"
	fa["dev-branch"] = other
	prt := identity("jti-prt")
	prt.Event = "pull_request_target"
	fa["prt"] = prt
	unprot := identity("jti-unprot")
	unprot.RefProtected = false
	fa["unprotected"] = unprot
	nojti := identity("")
	fa["no-jti"] = nojti
	fa["key-release"] = auth.Identity{Issuer: auth.KeyIssuer, Kind: auth.KindKey, KeyID: "k1", KeyName: "ci", KeyProfiles: []string{"release"}}
	fa["key-other"] = auth.Identity{Issuer: auth.KeyIssuer, Kind: auth.KindKey, KeyID: "k2", KeyName: "ci2", KeyProfiles: []string{"other"}}
	fa["client-secret-zq9"] = identity("jti-client")
	api := New(cfg, fa, m, []byte("#!/bin/sh\n"))
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &env{srv: srv, api: api, m: m, r: r, cfg: cfg, ctx: ctx, cancel: cancel}
}

func appZip(t *testing.T, topID string) []byte {
	return testutil.Zip(t, testutil.ElectronLikeApp(topID))
}

// post sends profile first, then file, like clients/sign.sh.
func (e *env) post(t *testing.T, token, profile string, zip []byte, fileFirst bool) (*http.Response, map[string]string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	writeFile := func() {
		fw, _ := mw.CreateFormFile("file", "Example.zip")
		fw.Write(zip)
	}
	if fileFirst {
		writeFile()
	}
	mw.WriteField("profile", profile)
	if !fileFirst {
		writeFile()
	}
	mw.Close()
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/jobs", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]string{}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (e *env) get(t *testing.T, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

type status struct {
	Status    string `json:"status"`
	Error     string `json:"error"`
	BundleID  string `json:"bundle_id"`
	Artifacts map[string]struct {
		SHA256   string `json:"sha256"`
		NotaryID string `json:"notary_id"`
	} `json:"artifacts"`
	SigningReport []struct {
		Path, Type, Entitlements, Warning string
	} `json:"signing_report"`
}

func (e *env) wait(t *testing.T, id, token string) status {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, b := e.get(t, "/v1/jobs/"+id, token)
		if resp.StatusCode != 200 {
			t.Fatalf("status %d: %s", resp.StatusCode, b)
		}
		var s status
		json.Unmarshal(b, &s)
		if s.Status == "done" || s.Status == "failed" {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return status{}
}

func TestEndToEnd(t *testing.T) {
	e := newEnv(t, 5, true)
	resp, out := e.post(t, "t1", "release", appZip(t, "com.example.app"), false)
	if resp.StatusCode != http.StatusAccepted || out["id"] == "" || len(out["job_token"]) < 40 {
		t.Fatalf("POST: %d %v", resp.StatusCode, out)
	}
	id, tok := out["id"], out["job_token"]
	s := e.wait(t, id, tok)
	if s.Status != "done" {
		t.Fatalf("job failed: %s", s.Error)
	}
	if s.BundleID != "com.example.app" || s.Artifacts["zip"].NotaryID != testutil.SubmissionID || s.Artifacts["dmg"].SHA256 == "" {
		t.Fatalf("status: %+v", s)
	}
	report := map[string]string{}
	for _, ri := range s.SigningReport {
		report[ri.Path] = ri.Type + "|" + ri.Entitlements + "|" + ri.Warning
	}
	if report["."] != "app-bundle|main.plist|" || !strings.HasPrefix(report["Contents/Resources/node/bin/node"], "executable||hardened") {
		t.Fatalf("signing report: %v", report)
	}
	for kind, a := range s.Artifacts {
		resp, b := e.get(t, "/v1/jobs/"+id+"/artifact?kind="+kind, tok)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", kind, resp.StatusCode)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != a.SHA256 {
			t.Fatalf("%s sha mismatch", kind)
		}
		if !strings.Contains(resp.Header.Get("Content-Disposition"), "Example."+kind) {
			t.Fatalf("disposition %q", resp.Header.Get("Content-Disposition"))
		}
	}

	// Only the job token reads the job.
	for _, tok := range []string{"", "t1", "wrong", strings.Repeat("A", 43)} {
		if resp, _ := e.get(t, "/v1/jobs/"+id, tok); resp.StatusCode != 404 {
			t.Fatalf("token %q: %d", tok, resp.StatusCode)
		}
		if resp, _ := e.get(t, "/v1/jobs/"+id+"/artifact", tok); resp.StatusCode != 404 {
			t.Fatalf("artifact token %q: %d", tok, resp.StatusCode)
		}
	}

	// The input and work tree are gone; outputs stay.
	jobDir := filepath.Join(e.cfg.WorkDir, "jobs", id)
	if _, err := os.Stat(filepath.Join(jobDir, "work")); !os.IsNotExist(err) {
		t.Fatal("work dir kept")
	}
	b, _ := os.ReadFile(filepath.Join(jobDir, "job.json"))
	if strings.Contains(string(b), tok) {
		t.Fatal("job token stored in clear")
	}

	cmds := e.r.Commands()
	assertOrder(t, cmds,
		"plutil -extract CFBundleIdentifier",
		"codesign --force --timestamp --options runtime --sign Developer ID Application: Example Corp (TEAMID1234) --keychain /k/signing.keychain-db /",
		"--entitlements /k/main.plist",
		"codesign --verify --deep --strict",
		"notarytool submit",
		"notarytool info",
		"stapler staple",
		"spctl -a -t exec",
		"hdiutil create -volname Example",
		"spctl -a -t open --context context:primary-signature",
	)
	for _, c := range cmds {
		if strings.HasPrefix(c, "codesign --force") && strings.Contains(c, "libffmpeg.dylib") && strings.Contains(c, "--entitlements") {
			t.Fatal("dylib got entitlements")
		}
	}

	// Audit line.
	al, _ := os.ReadFile(e.cfg.AuditLog)
	sc := bufio.NewScanner(bytes.NewReader(al))
	var rec audit.Record
	for sc.Scan() {
		json.Unmarshal(sc.Bytes(), &rec)
	}
	if rec.JobID != id || rec.Result != "done" || rec.Repo != "example/app" || rec.SHA != "abc123" || rec.OutputSHA256 != s.Artifacts["zip"].SHA256 || rec.InputSHA256 == "" {
		t.Fatalf("audit: %+v", rec)
	}
}

func assertOrder(t *testing.T, cmds []string, wants ...string) {
	t.Helper()
	i := 0
	for _, c := range cmds {
		if i < len(wants) && strings.Contains(c, wants[i]) {
			i++
		}
	}
	if i != len(wants) {
		t.Fatalf("command %q not found in order; commands:\n%s", wants[i], strings.Join(cmds, "\n"))
	}
}

func TestJobFailures(t *testing.T) {
	cases := map[string]struct {
		zip  func(t *testing.T) []byte
		prep func(e *env)
		want string
	}{
		"bundle id not allowed": {zip: func(t *testing.T) []byte { return appZip(t, "com.evil.app") }, want: "not allowed"},
		"notary invalid": {zip: func(t *testing.T) []byte { return appZip(t, "com.example.app") },
			prep: func(e *env) { e.r.NotaryStatuses = []string{"Invalid"} }, want: "secure timestamp"},
		"traversal": {zip: func(t *testing.T) []byte {
			return testutil.Zip(t, []testutil.Entry{{Path: "../evil", Data: []byte("x")}})
		}, want: "unsafe path"},
		"wrong team": {zip: func(t *testing.T) []byte { return appZip(t, "com.example.app") },
			prep: func(e *env) { e.cfg.Profiles[0].TeamID = "OTHERTEAM1" }, want: "team id"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 5, true)
			if c.prep != nil {
				c.prep(e)
			}
			resp, out := e.post(t, "t1", "release", c.zip(t), false)
			if resp.StatusCode != http.StatusAccepted {
				t.Fatalf("POST %d %v", resp.StatusCode, out)
			}
			s := e.wait(t, out["id"], out["job_token"])
			if s.Status != "failed" || !strings.Contains(s.Error, c.want) {
				t.Fatalf("got %s %q, want failed with %q", s.Status, s.Error, c.want)
			}
			if resp, _ := e.get(t, "/v1/jobs/"+out["id"]+"/artifact", out["job_token"]); resp.StatusCode != http.StatusConflict {
				t.Fatalf("artifact of failed job: %d", resp.StatusCode)
			}
		})
	}
}

// postRaw sends a request with an explicit body and length (-1: chunked).
func (e *env) postRaw(t *testing.T, token string, body io.Reader, length int64, ctype string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/jobs", body)
	req.ContentLength = length
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestAdmissionOrder fills the queue first. Requests that fail identity,
// replay or length checks must get their own error, not 429, which proves
// those checks run before a slot is taken.
func TestAdmissionOrder(t *testing.T) {
	e := newEnv(t, 1, false)
	zip := appZip(t, "com.example.app")
	if resp, out := e.post(t, "t1", "release", zip, false); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("fill: %d %v", resp.StatusCode, out)
	}
	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"no token", "", 401},
		{"bad token", "nope", 401},
		{"ref not allowed", "dev-branch", 403},
		{"pull_request_target", "prt", 403},
		{"unprotected ref", "unprotected", 403},
		{"replayed token", "t1", 401},
		{"token without jti", "no-jti", 401},
		{"allowed but queue full", "t2", 429},
		{"access key, queue full", "key-release", 429},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if resp, out := e.post(t, c.token, "release", zip, false); resp.StatusCode != c.want {
				t.Fatalf("%d %v, want %d", resp.StatusCode, out, c.want)
			}
		})
	}
	t.Run("no content length", func(t *testing.T) {
		if code := e.postRaw(t, "t3", io.MultiReader(bytes.NewReader(zip)), -1, "multipart/form-data; boundary=x"); code != http.StatusLengthRequired {
			t.Fatalf("%d", code)
		}
	})
	t.Run("declared length too big", func(t *testing.T) {
		big := e.cfg.MaxUploadBytes + 2<<20
		if code := e.postRaw(t, "t4", io.LimitReader(zeroReader{}, big), big, "multipart/form-data; boundary=x"); code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%d", code)
		}
	})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// TestRefusalKeepsToken: a 429 or 503 must not burn the OIDC token, so the
// same token works once the service has room, and only once.
func TestRefusalKeepsToken(t *testing.T) {
	cases := []struct {
		name    string
		block   func(e *env)
		unblock func(e *env)
		want    int
	}{
		{"queue full",
			func(e *env) { e.post(t, "t1", "release", appZip(t, "com.example.app"), false) },
			func(e *env) { e.m.Start(e.ctx) },
			http.StatusTooManyRequests},
		{"low disk",
			func(e *env) { e.m.FreeBytes = func(string) (uint64, error) { return 0, nil } },
			func(e *env) { e.m.FreeBytes = func(string) (uint64, error) { return 1 << 62, nil } },
			http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, 1, false)
			zip := appZip(t, "com.example.app")
			c.block(e)
			if resp, _ := e.post(t, "t2", "release", zip, false); resp.StatusCode != c.want {
				t.Fatalf("blocked: %d, want %d", resp.StatusCode, c.want)
			}
			c.unblock(e)
			deadline := time.Now().Add(5 * time.Second)
			for {
				resp, out := e.post(t, "t2", "release", zip, false)
				if resp.StatusCode == http.StatusAccepted {
					break
				}
				if resp.StatusCode != c.want || time.Now().After(deadline) {
					t.Fatalf("retry with the same token: %d %v", resp.StatusCode, out)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if resp, _ := e.post(t, "t2", "release", zip, false); resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("second accepted use: %d, want 401", resp.StatusCode)
			}
			if c.want == http.StatusServiceUnavailable {
				e.m.Start(e.ctx)
			}
			for e.m.Reserved() > 0 { // let the jobs finish before cleanup
				if time.Now().After(deadline) {
					t.Fatal("jobs did not finish")
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

func TestQueueFull(t *testing.T) {
	e := newEnv(t, 2, false) // worker not started
	zip := appZip(t, "com.example.app")
	for _, tok := range []string{"t1", "t2"} {
		if resp, out := e.post(t, tok, "release", zip, false); resp.StatusCode != http.StatusAccepted {
			t.Fatalf("%s: %d %v", tok, resp.StatusCode, out)
		}
	}
	if resp, _ := e.post(t, "t3", "release", zip, false); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third: %d", resp.StatusCode)
	}
	ents, _ := os.ReadDir(filepath.Join(e.cfg.WorkDir, "uploads"))
	if len(ents) != 0 {
		t.Fatalf("uploads left: %d", len(ents))
	}
}

// TestAfterReserve covers checks that need the body. Each must give the slot
// back: the queue holds one job and every case runs on the same server.
func TestAfterReserve(t *testing.T) {
	e := newEnv(t, 1, false)
	zip := appZip(t, "com.example.app")
	cases := []struct {
		name      string
		token     string
		profile   string
		fileFirst bool
		body      []byte
		want      int
	}{
		{"unknown profile", "t1", "debug", false, zip, 403},
		{"file before profile", "t2", "release", true, zip, 400},
		{"empty file", "t3", "release", false, []byte{}, 400},
		{"too large", "t4", "release", false, make([]byte, e.cfg.MaxUploadBytes+10), 413},
		{"access key without the profile", "key-other", "release", false, zip, 403},
		{"ok", "t5", "release", false, zip, 202},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if resp, out := e.post(t, c.token, c.profile, c.body, c.fileFirst); resp.StatusCode != c.want {
				t.Fatalf("%d %v, want %d", resp.StatusCode, out, c.want)
			}
		})
	}
	if r := e.m.Reserved(); r < int64(len(zip))+3*e.cfg.MaxExpandedBytes {
		t.Fatalf("queued job reserves %d bytes, want upload + 3x max_expanded_bytes", r)
	}
}

func TestDiskAccounting(t *testing.T) {
	e := newEnv(t, 5, false)
	zip := appZip(t, "com.example.app")
	// Room for one job (upload + 3x max_expanded_bytes), not two.
	e.m.FreeBytes = func(string) (uint64, error) {
		return uint64(e.cfg.MinFreeBytes) + 4*uint64(e.cfg.MaxExpandedBytes), nil
	}
	if resp, out := e.post(t, "t1", "release", zip, false); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("first: %d %v", resp.StatusCode, out)
	}
	if resp, _ := e.post(t, "t2", "release", zip, false); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second: %d", resp.StatusCode)
	}
	e.m.FreeBytes = func(string) (uint64, error) { return 0, nil }
	if resp, _ := e.post(t, "t3", "release", zip, false); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no disk: %d", resp.StatusCode)
	}
}

// TestStalledUpload: a client that stops sending must lose its slot after
// upload_timeout, so the next client gets in.
func TestStalledUpload(t *testing.T) {
	e := newEnv(t, 1, false)
	e.cfg.UploadTimeout = 200 * time.Millisecond
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	head := "--b\r\nContent-Disposition: form-data; name=\"profile\"\r\n\r\nrelease\r\n--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.zip\"\r\n\r\nPK"
	fmt.Fprintf(conn, "POST /v1/jobs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t1\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: 100000\r\n\r\n%s", head)
	// While the stalled upload holds the slot, the queue is full.
	time.Sleep(50 * time.Millisecond)
	if resp, _ := e.post(t, "t2", "release", appZip(t, "com.example.app"), false); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("during stall: %d", resp.StatusCode)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.Contains(line, "408") {
		t.Fatalf("stalled upload got %q", line)
	}
	if resp, out := e.post(t, "t3", "release", appZip(t, "com.example.app"), false); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("after stall: %d %v", resp.StatusCode, out)
	}
}

func TestJobTokenExpires(t *testing.T) {
	e := newEnv(t, 5, true)
	_, out := e.post(t, "t1", "release", appZip(t, "com.example.app"), false)
	if s := e.wait(t, out["id"], out["job_token"]); s.Status != "done" {
		t.Fatal(s.Error)
	}
	e.cfg.ResultTTL = time.Nanosecond
	e.m.Sweep()
	for _, path := range []string{"/v1/jobs/" + out["id"], "/v1/jobs/" + out["id"] + "/artifact"} {
		if resp, _ := e.get(t, path, out["job_token"]); resp.StatusCode != 404 {
			t.Fatalf("%s after TTL: %d", path, resp.StatusCode)
		}
	}
}

func TestArtifactKinds(t *testing.T) {
	e := newEnv(t, 5, true)
	e.cfg.Profiles[0].DMG = false
	_, out := e.post(t, "t1", "release", appZip(t, "com.example.app"), false)
	e.wait(t, out["id"], out["job_token"])
	cases := []struct {
		kind string
		want int
	}{{"", 200}, {"zip", 200}, {"dmg", 404}, {"exe", 400}}
	for _, c := range cases {
		if resp, _ := e.get(t, "/v1/jobs/"+out["id"]+"/artifact?kind="+c.kind, out["job_token"]); resp.StatusCode != c.want {
			t.Errorf("kind %q: %d, want %d", c.kind, resp.StatusCode, c.want)
		}
	}
}

func TestHealthAndScript(t *testing.T) {
	e := newEnv(t, 1, false)
	if resp, _ := e.get(t, "/healthz", ""); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if resp, b := e.get(t, "/client/sign.sh", ""); resp.StatusCode != 200 || !bytes.HasPrefix(b, []byte("#!")) {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.get(t, "/v1/jobs/../../etc", "x"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}
