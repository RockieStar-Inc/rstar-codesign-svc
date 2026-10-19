package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/testutil"
)

// TestClientScript runs clients/sign.sh against the test server. On macOS
// the script zips with the real ditto (so our unzip must accept ditto
// archives) and verifies the result with the real codesign, which must
// reject the fake-signed fixture.
func TestClientScript(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}
	mac := runtime.GOOS == "darwin"
	script, _ := filepath.Abs("../../clients/sign.sh")
	cases := []struct {
		name    string
		macOnly bool
		env     []string
		ok      bool
		output  string
		pidFile bool   // the smoke shell writes its pid (= its process group id) to $PIDFILE; the group must be empty after
		proxy   string // put a proxy in front: see proxyFor
	}{
		{"downloads, verify off", false, []string{"CODESIGN_VERIFY=0"}, true, "Example.dmg", false, ""},
		{"verify catches an unsigned app", true, []string{"CODESIGN_VERIFY=1"}, false, "not signed", false, ""},
		{"smoke command passes", true, []string{"CODESIGN_VERIFY=0", `CODESIGN_SMOKE_CMD=test -x "$APP/Contents/Resources/node/bin/node"`}, true, "smoke test passed", false, ""},
		{"smoke command fails the step", true, []string{"CODESIGN_VERIFY=0", "CODESIGN_SMOKE_CMD=exit 3"}, false, "smoke test failed (exit 3)", false, ""},
		// The sleeps hold stdout; if any survived, the test would wait 60 s.
		{"smoke command times out", true, []string{"CODESIGN_VERIFY=0", "CODESIGN_SMOKE_TIMEOUT=1", "CODESIGN_SMOKE_CMD=sleep 60 & sleep 60"}, false, "smoke test timed out after 1s", false, ""},
		{"bad smoke timeout", false, []string{"CODESIGN_SMOKE_TIMEOUT=soon"}, false, "must be a number", false, ""},
		// The command passes but leaves a child that ignores TERM.
		{"leftover child that ignores TERM is killed", true, []string{"CODESIGN_VERIFY=0",
			`CODESIGN_SMOKE_CMD=echo $$ >"$PIDFILE"; (trap "" TERM; exec sleep 600) >/dev/null 2>&1 &`}, true, "smoke test passed", true, ""},
		// Timeout: TERM ends the smoke shell at once, so wait returns early,
		// but its child ignores TERM. Only the parent's KILL step ends it.
		{"timeout: child that ignores TERM is killed", true, []string{"CODESIGN_VERIFY=0", "CODESIGN_SMOKE_TIMEOUT=1",
			`CODESIGN_SMOKE_CMD=echo $$ >"$PIDFILE"; (trap "" TERM; sleep 600) & wait`}, false, "smoke test timed out after 1s", true, ""},
		// The command itself ignores TERM and runs past the limit.
		{"TERM-ignoring command times out and is killed", true, []string{"CODESIGN_VERIFY=0", "CODESIGN_SMOKE_TIMEOUT=1",
			`CODESIGN_SMOKE_CMD=trap "" TERM; echo $$ >"$PIDFILE"; sleep 600`}, false, "smoke test timed out after 1s", true, ""},
		{"denied request", false, []string{"CODESIGN_ACCESS_KEY=dev-branch"}, false, "HTTP 403", false, ""},
		{"zero timeout", false, []string{"CODESIGN_TIMEOUT_MIN=0"}, false, "timed out", false, ""},
		{"bad timeout", false, []string{"CODESIGN_TIMEOUT_MIN=abc"}, false, "must be a number", false, ""},
		{"bad path", false, []string{"CODESIGN_PATH=/nope/file.txt"}, false, ".app directory or a .zip", false, ""},
		{"behind a 6 KB body limit", false, []string{"CODESIGN_VERIFY=0"}, true, "uploaded part 2/", false, "body-limit"},
		{"part retried after 502", false, []string{"CODESIGN_VERIFY=0"}, true, "part 1: HTTP 502, retry 1 of 3", false, "502-once"},
		{"part refused with 400 fails loudly", false, []string{"CODESIGN_VERIFY=0"}, false, "part 0: HTTP 400", false, "400-part"},
		{"bad profile name", false, []string{`CODESIGN_PROFILE=re"lease`}, false, "may hold only", false, ""},
	}
	if !mac {
		c := cases[0]
		c.name, c.env, c.ok, c.output = "smoke needs macOS", []string{"CODESIGN_SMOKE_CMD=true"}, false, "needs macOS"
		cases = append(cases, c)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.macOnly && !mac {
				t.Skip("macOS only")
			}
			e := newEnv(t, 5, true)
			dir := t.TempDir()
			testutil.WriteTree(t, dir, testutil.ElectronLikeApp("com.example.app"))
			out := filepath.Join(dir, "signed")
			ghOut := filepath.Join(dir, "gh-output")
			cmd := exec.Command("sh", script)
			url := e.srv.URL
			if c.proxy != "" {
				p := httptest.NewServer(proxyFor(c.proxy, e.api.Handler()))
				t.Cleanup(p.Close)
				url = p.URL
			}
			cmd.Env = append(os.Environ(),
				"CODESIGN_URL="+url+"/",
				"CODESIGN_PROFILE=release",
				"CODESIGN_PATH="+filepath.Join(dir, "Example.app"),
				"CODESIGN_OUTPUT_DIR="+out,
				"CODESIGN_ACCESS_KEY=client-secret-zq9",
				"GITHUB_OUTPUT="+ghOut,
			)
			pidFile := filepath.Join(dir, "smoke.pid")
			cmd.Env = append(cmd.Env, "PIDFILE="+pidFile)
			cmd.Env = append(cmd.Env, c.env...)
			start := time.Now()
			b, err := cmd.CombinedOutput()
			if time.Since(start) > 30*time.Second {
				t.Fatalf("took %s", time.Since(start))
			}
			if (err == nil) != c.ok || !strings.Contains(string(b), c.output) {
				t.Fatalf("err = %v, want ok=%v with %q:\n%s", err, c.ok, c.output, b)
			}
			if strings.Contains(string(b), "client-secret-zq9") {
				t.Fatalf("credential printed:\n%s", b)
			}
			if c.pidFile {
				b, err := os.ReadFile(pidFile)
				if err != nil {
					t.Fatal(err)
				}
				pgid, err := strconv.Atoi(strings.TrimSpace(string(b)))
				if err != nil {
					t.Fatal(err)
				}
				// The script returns only after its KILL step; allow a moment for reaping.
				deadline := time.Now().Add(2 * time.Second)
				for syscall.Kill(-pgid, 0) == nil {
					if time.Now().After(deadline) {
						syscall.Kill(-pgid, syscall.SIGKILL)
						t.Fatalf("process group %d still has live processes", pgid)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			if c.ok {
				gho, _ := os.ReadFile(ghOut)
				if !strings.Contains(string(gho), "zip="+out+"/Example.zip") || !strings.Contains(string(gho), "job-id=") {
					t.Fatalf("GITHUB_OUTPUT: %s", gho)
				}
			}
		})
	}
}

// proxyFor wraps the API like a misbehaving proxy:
//   - body-limit: refuses request bodies over 6 KB with 413 (like Cloudflare's
//     100 MB limit, scaled to the test part size of 4 KB);
//   - 502-once: the first PUT of part 1 gets 502;
//   - 400-part: every PUT of part 0 gets 400.
func proxyFor(kind string, h http.Handler) http.Handler {
	var mu sync.Mutex
	failed := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isPart := r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/parts/")
		switch kind {
		case "body-limit":
			if r.ContentLength > 6000 {
				http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
				return
			}
		case "502-once":
			mu.Lock()
			first := isPart && strings.HasSuffix(r.URL.Path, "/parts/1") && !failed
			if first {
				failed = true
			}
			mu.Unlock()
			if first {
				io.Copy(io.Discard, r.Body)
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return
			}
		case "400-part":
			if isPart && strings.HasSuffix(r.URL.Path, "/parts/0") {
				io.Copy(io.Discard, r.Body)
				http.Error(w, `{"error":"nope"}`, http.StatusBadRequest)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}
