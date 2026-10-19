package notary

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/testutil"
)

var apiCreds = config.Notary{APIKeyPath: "/k/AuthKey_ABCDE12345.p8", KeyID: "ABCDE12345", IssuerID: "6053b7fe-68a8-4acb-89be-165aa6465141"}

func TestSubmitAndWait(t *testing.T) {
	ctx := context.Background()
	r := &testutil.FakeRunner{NotaryStatuses: []string{"In Progress", "In Progress", "Accepted"}}
	id, err := Submit(ctx, r, apiCreds, "/w/a.zip")
	if err != nil || id != testutil.SubmissionID {
		t.Fatalf("%q %v", id, err)
	}
	if err := Wait(ctx, r, apiCreds, id, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	cmds := r.Commands()
	if !strings.Contains(cmds[0], "submit /w/a.zip --no-wait") || !strings.Contains(cmds[0], "--key /k/AuthKey_ABCDE12345.p8 --key-id ABCDE12345 --issuer ") {
		t.Fatalf("submit: %s", cmds[0])
	}
	if strings.Contains(cmds[0], "--wait ") {
		t.Fatal("used --wait")
	}
	if len(cmds) != 4 {
		t.Fatalf("calls: %q", cmds)
	}
}

func TestKeychainCreds(t *testing.T) {
	r := &testutil.FakeRunner{}
	n := config.Notary{KeychainProfile: "notary", Keychain: "/k/signing.keychain-db"}
	if _, err := Submit(context.Background(), r, n, "/a.zip"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Commands()[0], "--keychain-profile notary --keychain /k/signing.keychain-db") {
		t.Fatal(r.Commands()[0])
	}
}

func TestWaitStatusMapping(t *testing.T) {
	flaky := func() *testutil.FakeRunner {
		n := 0
		return &testutil.FakeRunner{Hook: func(c runner.Cmd) (runner.Result, error, bool) {
			if len(c.Args) > 1 && c.Args[1] == "info" {
				n++
				if n == 1 {
					return runner.Result{}, errors.New("network down"), true
				}
			}
			return runner.Result{}, nil, false
		}}
	}
	cases := []struct {
		name   string
		r      *testutil.FakeRunner
		errHas string // "" means success
		logged bool
	}{
		{"accepted", &testutil.FakeRunner{NotaryStatuses: []string{"Accepted"}}, "", false},
		{"in progress then accepted", &testutil.FakeRunner{NotaryStatuses: []string{"In Progress", "In Progress", "Accepted"}}, "", false},
		{"invalid with log", &testutil.FakeRunner{NotaryStatuses: []string{"Invalid"}}, "secure timestamp", true},
		{"rejected with log", &testutil.FakeRunner{NotaryStatuses: []string{"Rejected"}}, "Rejected", true},
		{"unknown status", &testutil.FakeRunner{NotaryStatuses: []string{"Exploded"}}, "unexpected status", false},
		{"poll error is retried", flaky(), "", false},
		{"log fetch fails", &testutil.FakeRunner{NotaryStatuses: []string{"Invalid"}, Fail: map[string]string{"notarytool log": "boom"}}, "could not fetch notary log", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Wait(context.Background(), c.r, apiCreds, testutil.SubmissionID, time.Millisecond)
			if c.errHas == "" && err != nil || c.errHas != "" && (err == nil || !strings.Contains(err.Error(), c.errHas)) {
				t.Fatalf("err = %v, want %q", err, c.errHas)
			}
			logged := false
			for _, cmd := range c.r.Commands() {
				if strings.Contains(cmd, "notarytool log "+testutil.SubmissionID+" --key") {
					logged = true
				}
			}
			if logged != c.logged {
				t.Fatalf("log fetched = %v", logged)
			}
		})
	}
}

func TestSummarizeCapsIssues(t *testing.T) {
	var lr logResult
	for range 15 {
		lr.Issues = append(lr.Issues, struct {
			Severity string `json:"severity"`
			Path     string `json:"path"`
			Message  string `json:"message"`
		}{"error", "p", "m"})
	}
	if got := summarize(lr); !strings.Contains(got, "and 5 more") {
		t.Fatal(got)
	}
}

func TestStapleAndAssess(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		fail string
		fn   func(r runner.Runner) error
	}{
		{"staple", "stapler staple", func(r runner.Runner) error { return Staple(ctx, r, "/a.app") }},
		{"validate", "stapler validate", func(r runner.Runner) error { return Staple(ctx, r, "/a.app") }},
		{"assess app", "-t exec", func(r runner.Runner) error { return AssessApp(ctx, r, "/a.app") }},
		{"assess dmg", "-t open", func(r runner.Runner) error { return AssessDMG(ctx, r, "/a.dmg") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(&testutil.FakeRunner{}); err != nil {
				t.Fatal(err)
			}
			if err := c.fn(&testutil.FakeRunner{Fail: map[string]string{c.fail: "x"}}); err == nil {
				t.Fatal("failure not reported")
			}
		})
	}
}

func TestSubmitBadID(t *testing.T) {
	r := &testutil.FakeRunner{Hook: func(c runner.Cmd) (runner.Result, error, bool) {
		return runner.Result{Stdout: []byte(`{"id":"--key=/etc/passwd"}`)}, nil, true
	}}
	if _, err := Submit(context.Background(), r, apiCreds, "/a.zip"); err == nil {
		t.Fatal("bad id accepted")
	}
	if err := Wait(context.Background(), r, apiCreds, "../x", time.Millisecond); err == nil {
		t.Fatal("bad id accepted by Wait")
	}
}

func TestWaitDeadline(t *testing.T) {
	r := &testutil.FakeRunner{NotaryStatuses: []string{"In Progress"}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := Wait(ctx, r, apiCreds, testutil.SubmissionID, time.Millisecond); err == nil {
		t.Fatal("no error at deadline")
	}
}
