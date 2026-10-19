package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/auth"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/sign"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/testutil"
)

func testConfig(t *testing.T) *config.Config {
	return &config.Config{
		WorkDir: filepath.Join(t.TempDir(), "work"), QueueSize: 2, ResultTTL: time.Hour, JobTimeout: time.Minute,
		MaxExpandedBytes: 1 << 24, MaxFiles: 1000, MinFreeBytes: 1, MaxRetainedJobs: 20,
		Profiles: []config.Profile{{
			Name: "release", Identity: "Developer ID Application: Example Corp (TEAMID1234)",
			Keychain: "/k/signing.keychain-db", TeamID: testutil.TeamID, DMG: true,
			Notary: config.Notary{KeychainProfile: "notary", Keychain: "/k/signing.keychain-db"},
		}},
	}
}

const jobID = "0123456789abcdef0123456789abcdef"

func writeJob(t *testing.T, cfg *config.Config, j Job, withApp bool) {
	t.Helper()
	dir := filepath.Join(cfg.WorkDir, "jobs", j.ID)
	if withApp {
		testutil.WriteTree(t, filepath.Join(dir, "work", "src"), testutil.ElectronLikeApp("com.example.app"))
	}
	os.MkdirAll(filepath.Join(dir, "out"), 0o700)
	b, _ := json.Marshal(j)
	if err := os.WriteFile(filepath.Join(dir, "job.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitDone(t *testing.T, m *Manager, id, token string) Job {
	t.Helper()
	for range 2000 {
		if j, ok := m.Authorize(id, token); ok && j.Status.Finished() {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return Job{}
}

func TestResumeNotarization(t *testing.T) {
	cfg := testConfig(t)
	os.MkdirAll(cfg.WorkDir, 0o700)
	writeJob(t, cfg, Job{
		ID: jobID, Status: Notarizing, Profile: "release", Name: "Example", BundleID: "com.example.app",
		TokenHash: hashToken("tok"), Stage: stageApp, NotarySubmission: testutil.SubmissionID,
		Artifacts: map[string]*Artifact{}, StartedAt: time.Now(),
	}, true)
	r := &testutil.FakeRunner{}
	m, err := New(cfg, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.PollInterval = time.Millisecond
	pw := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pw, []byte("pw"), 0o600)
	m.pwFile = pw
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	j := waitDone(t, m, jobID, "tok")
	if j.Status != Done || j.Artifacts["zip"] == nil || j.Artifacts["dmg"] == nil {
		t.Fatalf("job: %+v %s", j, j.Error)
	}
	cmds := r.Commands()
	if !strings.HasPrefix(cmds[0], "security -i") || !strings.HasPrefix(cmds[1], "security show-keychain-info") {
		t.Fatalf("resume did not unlock first: %q", cmds[:2])
	}
	if !strings.Contains(cmds[2], "notarytool info "+testutil.SubmissionID) {
		t.Fatalf("command %q; want a poll of the saved submission", cmds[2])
	}
	submits := 0
	for _, c := range cmds {
		if strings.Contains(c, "notarytool submit") {
			submits++
			if !strings.HasSuffix(strings.Fields(c)[3], ".dmg") {
				t.Fatalf("app was submitted again: %s", c)
			}
		}
	}
	if submits != 1 {
		t.Fatalf("submits = %d", submits)
	}
}

func TestRestartReservations(t *testing.T) {
	id := func(n int) string { return fmt.Sprintf("%032x", n) }
	cases := []struct {
		name     string
		jobs     []Job
		withApp  bool
		want     int64
		afterRun int64
	}{
		{"only interrupted jobs", []Job{
			{ID: id(1), Status: Queued, ReservedBytes: 100},
			{ID: id(2), Status: Signing, ReservedBytes: 200},
		}, false, 0, 0},
		{"one resumed job counts", []Job{
			{ID: id(1), Status: Queued, ReservedBytes: 100},
			{ID: id(2), Status: Notarizing, Stage: stageApp, NotarySubmission: testutil.SubmissionID, Name: "Example", ReservedBytes: 50},
			{ID: id(3), Status: Done, ReservedBytes: 0},
		}, true, 50, 0},
		{"notarizing without submission is interrupted", []Job{
			{ID: id(1), Status: Notarizing, ReservedBytes: 70},
		}, false, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := testConfig(t)
			os.MkdirAll(cfg.WorkDir, 0o700)
			for _, j := range c.jobs {
				j.Profile, j.TokenHash, j.StartedAt = "release", hashToken("tok"+j.ID), time.Now()
				writeJob(t, cfg, j, c.withApp && j.Status == Notarizing)
			}
			m, err := New(cfg, &testutil.FakeRunner{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			m.PollInterval = time.Millisecond
			if got := m.Reserved(); got != c.want {
				t.Fatalf("reserved after load = %d, want %d", got, c.want)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m.Start(ctx)
			for _, j := range c.jobs {
				waitDone(t, m, j.ID, "tok"+j.ID)
			}
			if got := m.Reserved(); got != c.afterRun {
				t.Fatalf("reserved after run = %d, want %d", got, c.afterRun)
			}
		})
	}
}

func TestInterruptedJobFails(t *testing.T) {
	cfg := testConfig(t)
	os.MkdirAll(cfg.WorkDir, 0o700)
	writeJob(t, cfg, Job{ID: jobID, Status: Signing, Profile: "release", TokenHash: hashToken("tok"), Artifacts: map[string]*Artifact{}}, true)
	m, err := New(cfg, &testutil.FakeRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	j, ok := m.Authorize(jobID, "tok")
	if !ok || j.Status != Failed || !strings.Contains(j.Error, "interrupted") {
		t.Fatalf("job: %+v", j)
	}
	if _, err := os.Stat(filepath.Join(cfg.WorkDir, "jobs", jobID, "work")); !os.IsNotExist(err) {
		t.Fatal("work dir kept")
	}
}

func TestSweep(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxRetainedJobs = 2
	os.MkdirAll(cfg.WorkDir, 0o700)
	now := time.Now()
	ids := []string{
		"00000000000000000000000000000001", // expired
		"00000000000000000000000000000002", // oldest kept candidate, over cap
		"00000000000000000000000000000003",
		"00000000000000000000000000000004",
		"00000000000000000000000000000005", // queued: never swept
	}
	ages := []time.Duration{2 * time.Hour, 30 * time.Minute, 20 * time.Minute, 10 * time.Minute, 0}
	for i, id := range ids {
		st := Done
		if i == 4 {
			st = Queued
		}
		writeJob(t, cfg, Job{ID: id, Status: st, TokenHash: hashToken("tok"), FinishedAt: now.Add(-ages[i]), Artifacts: map[string]*Artifact{}}, false)
	}
	m, err := New(cfg, &testutil.FakeRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The queued job was failed as interrupted on load; give it a fresh time.
	m.jobs[ids[4]].FinishedAt = now
	m.Sweep()
	for i, id := range ids {
		_, ok := m.jobs[id]
		_, err := os.Stat(filepath.Join(cfg.WorkDir, "jobs", id))
		want := i >= 3
		if ok != want || (err == nil) != want {
			t.Errorf("job %d: in memory %v, on disk %v, want %v", i, ok, err == nil, want)
		}
	}
}

func TestWorkDirPermissions(t *testing.T) {
	cfg := testConfig(t)
	os.MkdirAll(cfg.WorkDir, 0o700)
	os.Chmod(cfg.WorkDir, 0o777)
	if _, err := New(cfg, &testutil.FakeRunner{}, nil); err == nil {
		t.Fatal("world-writable work dir accepted")
	}
}

func TestReserveAccounting(t *testing.T) {
	const minFree = 1000
	cases := []struct {
		name      string
		free      uint64
		estimates []int64 // each Reserve in order
		want      []error
	}{
		{"fits", 2000, []int64{1000}, []error{nil}},
		{"exactly at the floor", 2000, []int64{1000, 0}, []error{nil, nil}},
		{"second does not fit", 2500, []int64{1000, 1000}, []error{nil, ErrDiskLow}},
		{"already below floor", 900, []int64{0}, []error{ErrDiskLow}},
		{"queue full before disk", 1 << 40, []int64{1, 1, 1}, []error{nil, nil, ErrQueueFull}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.MinFreeBytes = minFree
			m, err := New(cfg, &testutil.FakeRunner{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			m.FreeBytes = func(string) (uint64, error) { return c.free, nil }
			var tickets []*Ticket
			var sum int64
			for i, est := range c.estimates {
				tk, err := m.Reserve(est)
				if err != c.want[i] {
					t.Fatalf("reserve %d: err = %v, want %v", i, err, c.want[i])
				}
				if tk != nil {
					tickets = append(tickets, tk)
					sum += est
				}
			}
			if m.Reserved() != sum {
				t.Fatalf("reserved %d, want %d", m.Reserved(), sum)
			}
			for _, tk := range tickets {
				tk.Release()
				tk.Release() // twice is safe
			}
			if m.Reserved() != 0 {
				t.Fatalf("reserved %d after release", m.Reserved())
			}
			if _, err := m.Reserve(0); c.free >= minFree && err != nil {
				t.Fatalf("slot leaked: %v", err)
			}
		})
	}
}

func TestReserveFreeBytesError(t *testing.T) {
	m, err := New(testConfig(t), &testutil.FakeRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.FreeBytes = func(string) (uint64, error) { return 0, os.ErrPermission }
	if _, err := m.Reserve(1); err == nil {
		t.Fatal("no error")
	}
}

// runJob submits a fixture app and waits for the result.
func runJob(t *testing.T, cfg *config.Config, r *testutil.FakeRunner, setup func(m *Manager)) (Job, *Manager) {
	t.Helper()
	m, err := New(cfg, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.PollInterval = time.Millisecond
	m.retryDelay = 0
	if setup != nil {
		setup(m)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m.Start(ctx)
	up := filepath.Join(m.UploadDir(), "u.zip")
	if err := os.WriteFile(up, testutil.Zip(t, testutil.ElectronLikeApp("com.example.app")), 0o600); err != nil {
		t.Fatal(err)
	}
	tk, err := m.Reserve(100)
	if err != nil {
		t.Fatal(err)
	}
	j, tok, err := m.Submit(tk, testIdentity(), "release", up, "sha")
	if err != nil {
		t.Fatal(err)
	}
	j = waitDone(t, m, j.ID, tok)
	if m.Reserved() != 0 {
		t.Fatalf("reservation kept after finish: %d", m.Reserved())
	}
	return j, m
}

func TestPipelineOutcomes(t *testing.T) {
	busy := func(n int) func(c runner.Cmd) (runner.Result, error, bool) {
		calls := 0
		return func(c runner.Cmd) (runner.Result, error, bool) {
			if c.Name != "hdiutil" {
				return runner.Result{}, nil, false
			}
			calls++
			if calls <= n {
				return runner.Result{Stderr: []byte("hdiutil: create failed - Resource busy")}, errors.New("hdiutil: exit status 1: create failed - Resource busy"), true
			}
			return runner.Result{}, nil, false
		}
	}
	cases := []struct {
		name     string
		r        *testutil.FakeRunner
		want     Status
		errHas   string
		hdiutils int
	}{
		{"accepted", &testutil.FakeRunner{NotaryStatuses: []string{"In Progress", "Accepted"}}, Done, "", 1},
		{"invalid", &testutil.FakeRunner{NotaryStatuses: []string{"Invalid"}}, Failed, "secure timestamp", 0},
		{"rejected", &testutil.FakeRunner{NotaryStatuses: []string{"Rejected"}}, Failed, "Rejected", 0},
		{"unknown status", &testutil.FakeRunner{NotaryStatuses: []string{"Exploded"}}, Failed, "unexpected status", 0},
		{"dmg busy once then ok", &testutil.FakeRunner{Hook: busy(1)}, Done, "", 2},
		{"dmg busy twice then ok", &testutil.FakeRunner{Hook: busy(2)}, Done, "", 3},
		{"dmg busy three times fails", &testutil.FakeRunner{Hook: busy(3)}, Failed, "Resource busy", 3},
		{"dmg other error not retried", &testutil.FakeRunner{Fail: map[string]string{"hdiutil": "no space left"}}, Failed, "no space", 1},
		{"codesign fails", &testutil.FakeRunner{Fail: map[string]string{"libffmpeg.dylib": "boom"}}, Failed, "sign Contents/Frameworks", 0},
		{"staple fails", &testutil.FakeRunner{Fail: map[string]string{"stapler staple": "no ticket"}}, Failed, "staple", 0},
		{"spctl fails", &testutil.FakeRunner{Fail: map[string]string{"spctl -a -t exec": "rejected"}}, Failed, "spctl", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j, _ := runJob(t, testConfig(t), c.r, nil)
			if j.Status != c.want || !strings.Contains(j.Error, c.errHas) {
				t.Fatalf("status %s error %q, want %s with %q", j.Status, j.Error, c.want, c.errHas)
			}
			n := 0
			for _, cmd := range c.r.Commands() {
				if strings.HasPrefix(cmd, "hdiutil create") {
					n++
				}
			}
			if n != c.hdiutils {
				t.Fatalf("hdiutil calls = %d, want %d", n, c.hdiutils)
			}
		})
	}
}

func TestPipelineRejects(t *testing.T) {
	cases := []struct {
		name   string
		prep   func(cfg *config.Config)
		errHas string
	}{
		{"bundle id not allowed", func(c *config.Config) { c.Profiles[0].AllowedBundleIDs = []string{"com.other"} }, "not allowed"},
		{"wrong team", func(c *config.Config) { c.Profiles[0].TeamID = "OTHERTEAM1" }, "team id"},
		{"profile removed", func(c *config.Config) { c.Profiles[0].Name = "gone" }, "no longer exists"},
		{"zip too big", func(c *config.Config) { c.MaxExpandedBytes = 10 }, "unzip"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Profiles[0].AllowedBundleIDs = []string{"com.example.app"}
			c.prep(cfg)
			j, _ := runJob(t, cfg, &testutil.FakeRunner{}, nil)
			if j.Status != Failed || !strings.Contains(j.Error, c.errHas) {
				t.Fatalf("status %s error %q", j.Status, j.Error)
			}
		})
	}
}

func TestSigningReportInJob(t *testing.T) {
	cfg := testConfig(t)
	j, _ := runJob(t, cfg, &testutil.FakeRunner{}, nil)
	if j.Status != Done {
		t.Fatal(j.Error)
	}
	var node *sign.ReportItem
	for i := range j.SigningReport {
		if j.SigningReport[i].Path == "Contents/Resources/node/bin/node" {
			node = &j.SigningReport[i]
		}
	}
	if node == nil || node.Type != sign.KindExecutable || node.Warning == "" {
		t.Fatalf("node report: %+v", node)
	}
	cfg = testConfig(t)
	cfg.Profiles[0].InheritEntitlements = "/k/inherit.plist"
	j, _ = runJob(t, cfg, &testutil.FakeRunner{}, nil)
	for _, ri := range j.SigningReport {
		if ri.Path == "Contents/Resources/node/bin/node" && (ri.Entitlements != "inherit.plist" || ri.Warning != "") {
			t.Fatalf("node with inherit: %+v", ri)
		}
	}
}

func TestUnlockBeforeSigning(t *testing.T) {
	cfg := testConfig(t)
	pw := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pw, []byte("pw"), 0o600)
	r := &testutil.FakeRunner{}
	j, _ := runJob(t, cfg, r, func(m *Manager) { m.pwFile = pw })
	if j.Status != Done {
		t.Fatal(j.Error)
	}
	if cmds := r.Commands(); !strings.HasPrefix(cmds[0], "security -i") {
		t.Fatalf("first command %q", cmds[0])
	}
}

func testIdentity() auth.Identity {
	return auth.Identity{Issuer: config.GitHubIssuer, Kind: config.KindGitHub, Repo: "example/app", Ref: "refs/heads/main"}
}

func TestReserveReleases(t *testing.T) {
	cfg := testConfig(t)
	m, err := New(cfg, &testutil.FakeRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		tk, err := m.Reserve(0)
		if err != nil {
			t.Fatal(err)
		}
		tk.Release()
		tk.Release()
	}
}
