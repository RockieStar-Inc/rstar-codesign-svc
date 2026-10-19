// Package runner runs external commands. Tests replace it with a fake.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Default timeouts for external tools.
const (
	CodesignTimeout = 5 * time.Minute
	// NotaryUploadTimeout bounds one `notarytool submit --no-wait` upload.
	// The whole notarization, polling included, is bounded by the job deadline.
	NotaryUploadTimeout = 70 * time.Minute
	HdiutilTimeout      = 10 * time.Minute
	DittoTimeout        = 10 * time.Minute
	ShortTimeout        = 2 * time.Minute
)

// Cmd is one external command.
type Cmd struct {
	Name    string
	Args    []string
	Timeout time.Duration
	Stdin   []byte
	// Secret hides the arguments in errors and logs.
	Secret bool
}

func (c Cmd) String() string {
	if c.Secret {
		return c.Name + " <redacted>"
	}
	return c.Name + " " + strings.Join(c.Args, " ")
}

// Result holds the output of a finished command.
type Result struct {
	Stdout []byte
	Stderr []byte
}

// Runner runs a command and returns its output. A non-zero exit is an error,
// but the output is still returned.
type Runner interface {
	Run(ctx context.Context, c Cmd) (Result, error)
}

// Exec runs real commands with exec.CommandContext.
type Exec struct{}

func (Exec) Run(ctx context.Context, c Cmd) (Result, error) {
	if c.Timeout <= 0 {
		return Result{}, fmt.Errorf("%s: no timeout set", c.Name)
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	var stdout, stderr bytes.Buffer
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return res, fmt.Errorf("%s: timed out after %s", c.Name, c.Timeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if c.Secret {
			msg = ""
		}
		return res, fmt.Errorf("%s: %w: %s", c.String(), err, tail(msg, 2000))
	}
	return res, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
