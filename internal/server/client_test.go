package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
		pidFile bool // the smoke command writes a pid to $PIDFILE that must be gone after
	}{
		{"downloads, verify off", false, []string{"CODESIGN_VERIFY=0"}, true, "Example.dmg", false},
		{"verify catches an unsigned app", true, []string{"CODESIGN_VERIFY=1"}, false, "not signed", false},
		{"smoke command passes", true, []string{"CODESIGN_VERIFY=0", `CODESIGN_SMOKE_CMD=test -x "$APP/Contents/Resources/node/bin/node"`}, true, "smoke test passed", false},
		{"smoke command fails the step", true, []string{"CODESIGN_VERIFY=0", "CODESIGN_SMOKE_CMD=exit 3"}, false, "smoke test failed (exit 3)", false},
		// The sleeps hold stdout; if any survived, the test would wait 60 s.
		{"smoke command times out", true, []string{"CODESIGN_VERIFY=0", "CODESIGN_SMOKE_TIMEOUT=1", "CODESIGN_SMOKE_CMD=sleep 60 & sleep 60"}, false, "smoke test timed out after 1s", false},
		{"bad smoke timeout", false, []string{"CODESIGN_SMOKE_TIMEOUT=soon"}, false, "must be a number", false},
		// The command passes but leaves a child that ignores TERM.
		{"leftover child that ignores TERM is killed", true, []string{"CODESIGN_VERIFY=0",
			`CODESIGN_SMOKE_CMD=(trap "" TERM; exec sleep 60) >/dev/null 2>&1 & echo $! >"$PIDFILE"`}, true, "smoke test passed", true},
		// The command itself ignores TERM and runs past the limit.
		{"TERM-ignoring command times out and is killed", true, []string{"CODESIGN_VERIFY=0", "CODESIGN_SMOKE_TIMEOUT=1",
			`CODESIGN_SMOKE_CMD=trap "" TERM; echo $$ >"$PIDFILE"; sleep 60`}, false, "smoke test timed out after 1s", true},
		{"denied request", false, []string{"CODESIGN_ACCESS_KEY=dev-branch"}, false, "HTTP 403", false},
		{"zero timeout", false, []string{"CODESIGN_TIMEOUT_MIN=0"}, false, "timed out", false},
		{"bad timeout", false, []string{"CODESIGN_TIMEOUT_MIN=abc"}, false, "must be a number", false},
		{"bad path", false, []string{"CODESIGN_PATH=/nope/file.txt"}, false, ".app directory or a .zip", false},
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
			cmd.Env = append(os.Environ(),
				"CODESIGN_URL="+e.srv.URL+"/",
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
				pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
				if err != nil {
					t.Fatal(err)
				}
				// The script returns only after its KILL step; allow a moment for reaping.
				deadline := time.Now().Add(2 * time.Second)
				for syscall.Kill(pid, 0) == nil {
					if time.Now().After(deadline) {
						syscall.Kill(pid, syscall.SIGKILL)
						t.Fatalf("process %d from the smoke group is still running", pid)
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
