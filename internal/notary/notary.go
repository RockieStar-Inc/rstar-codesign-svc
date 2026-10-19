// Package notary submits files to Apple notarization, polls for the result,
// and staples tickets.
package notary

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
)

var idRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidID reports whether id is a notary submission id (a UUID).
func ValidID(id string) bool { return idRe.MatchString(id) }

type submission struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type logResult struct {
	Status  string `json:"status"`
	Summary string `json:"statusSummary"`
	Issues  []struct {
		Severity string `json:"severity"`
		Path     string `json:"path"`
		Message  string `json:"message"`
	} `json:"issues"`
}

func credArgs(n config.Notary) []string {
	if n.APIKeyPath != "" {
		return []string{"--key", n.APIKeyPath, "--key-id", n.KeyID, "--issuer", n.IssuerID}
	}
	return []string{"--keychain-profile", n.KeychainProfile, "--keychain", n.Keychain}
}

func notarytool(ctx context.Context, r runner.Runner, n config.Notary, timeout time.Duration, args ...string) (submission, error) {
	args = append(append([]string{"notarytool"}, args...), credArgs(n)...)
	args = append(args, "--output-format", "json")
	res, runErr := r.Run(ctx, runner.Cmd{Name: "xcrun", Args: args, Timeout: timeout})
	var s submission
	if err := json.Unmarshal(res.Stdout, &s); err != nil {
		if runErr != nil {
			return s, fmt.Errorf("notarytool %s: %w", args[1], runErr)
		}
		return s, fmt.Errorf("notarytool %s: output is not JSON", args[1])
	}
	return s, nil
}

// Submit uploads file without waiting and returns the submission id.
func Submit(ctx context.Context, r runner.Runner, n config.Notary, file string) (string, error) {
	s, err := notarytool(ctx, r, n, runner.NotaryUploadTimeout, "submit", file, "--no-wait")
	if err != nil {
		return "", err
	}
	if !ValidID(s.ID) {
		return "", fmt.Errorf("notarytool submit returned a bad id %q", s.ID)
	}
	return s.ID, nil
}

// Wait polls until the submission is done. Accepted returns nil. Invalid or
// Rejected returns an error with a summary of the notary log.
func Wait(ctx context.Context, r runner.Runner, n config.Notary, id string, interval time.Duration) error {
	if !ValidID(id) {
		return fmt.Errorf("bad notary submission id %q", id)
	}
	for {
		s, err := notarytool(ctx, r, n, runner.ShortTimeout, "info", id)
		if err != nil {
			// A failed poll is not a verdict; try again until the deadline.
			if ctx.Err() != nil {
				return err
			}
		} else {
			switch s.Status {
			case "Accepted":
				return nil
			case "In Progress":
			case "Invalid", "Rejected":
				return fmt.Errorf("notarization %s: %s; %s", id, s.Status, fetchLog(ctx, r, n, id))
			default:
				return fmt.Errorf("notarization %s: unexpected status %q", id, s.Status)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("notarization %s: %w", id, ctx.Err())
		case <-time.After(interval):
		}
	}
}

func fetchLog(ctx context.Context, r runner.Runner, n config.Notary, id string) string {
	args := append([]string{"notarytool", "log", id}, credArgs(n)...)
	res, err := r.Run(ctx, runner.Cmd{Name: "xcrun", Args: args, Timeout: runner.ShortTimeout})
	if err != nil {
		return "could not fetch notary log: " + err.Error()
	}
	var lr logResult
	if err := json.Unmarshal(res.Stdout, &lr); err != nil {
		return "notary log is not JSON"
	}
	return summarize(lr)
}

func summarize(lr logResult) string {
	var b strings.Builder
	b.WriteString("notary log: ")
	b.WriteString(lr.Summary)
	const max = 10
	for i, is := range lr.Issues {
		if i == max {
			fmt.Fprintf(&b, "; and %d more", len(lr.Issues)-max)
			break
		}
		fmt.Fprintf(&b, "; [%s] %s: %s", is.Severity, is.Path, is.Message)
	}
	return b.String()
}

// Staple attaches the ticket and validates it.
func Staple(ctx context.Context, r runner.Runner, p string) error {
	if _, err := r.Run(ctx, runner.Cmd{Name: "xcrun", Args: []string{"stapler", "staple", p}, Timeout: runner.ShortTimeout}); err != nil {
		return fmt.Errorf("staple: %w", err)
	}
	if _, err := r.Run(ctx, runner.Cmd{Name: "xcrun", Args: []string{"stapler", "validate", p}, Timeout: runner.ShortTimeout}); err != nil {
		return fmt.Errorf("stapler validate: %w", err)
	}
	return nil
}

// AssessApp runs the Gatekeeper check for an app.
func AssessApp(ctx context.Context, r runner.Runner, app string) error {
	if _, err := r.Run(ctx, runner.Cmd{Name: "spctl", Args: []string{"-a", "-t", "exec", "-vv", app}, Timeout: runner.ShortTimeout}); err != nil {
		return fmt.Errorf("spctl: %w", err)
	}
	return nil
}

// AssessDMG runs the Gatekeeper check for a disk image.
func AssessDMG(ctx context.Context, r runner.Runner, dmg string) error {
	if _, err := r.Run(ctx, runner.Cmd{Name: "spctl", Args: []string{"-a", "-t", "open", "--context", "context:primary-signature", "-vv", dmg}, Timeout: runner.ShortTimeout}); err != nil {
		return fmt.Errorf("spctl: %w", err)
	}
	return nil
}
