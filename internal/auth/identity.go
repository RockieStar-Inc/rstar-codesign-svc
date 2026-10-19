// Package auth verifies CI OIDC tokens and checks the allowlist.
package auth

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
)

// Identity is the CI caller, built from verified token claims.
type Identity struct {
	Issuer       string `json:"issuer"`
	Kind         string `json:"kind"`
	Subject      string `json:"subject"`
	Repo         string `json:"repo"`
	Ref          string `json:"ref"`
	RefProtected bool   `json:"ref_protected"`
	Event        string `json:"event"`
	WorkflowRef  string `json:"workflow_ref,omitempty"`
	SHA          string `json:"sha,omitempty"`
	RunID        string `json:"run_id,omitempty"`
	RunURL       string `json:"run_url,omitempty"`

	// Access key fields, set only for Kind "key".
	KeyID       string   `json:"key_id,omitempty"`
	KeyName     string   `json:"key_name,omitempty"`
	KeyProfiles []string `json:"key_profiles,omitempty"`

	// Token id and expiry, for replay checks.
	JTI    string    `json:"-"`
	Expiry time.Time `json:"-"`
}

// claims holds both GitHub and GitLab claim names.
type claims struct {
	Subject string `json:"sub"`
	JTI     string `json:"jti"`
	SHA     string `json:"sha"`

	// GitHub
	Repository     string    `json:"repository"`
	Ref            string    `json:"ref"`
	RefProtected   boolClaim `json:"ref_protected"`
	EventName      string    `json:"event_name"`
	JobWorkflowRef string    `json:"job_workflow_ref"`
	WorkflowRef    string    `json:"workflow_ref"`
	RunID          string    `json:"run_id"`
	RunAttempt     string    `json:"run_attempt"`

	// GitLab
	ProjectPath    string `json:"project_path"`
	RefPath        string `json:"ref_path"`
	RefType        string `json:"ref_type"`
	PipelineSource string `json:"pipeline_source"`
	PipelineID     string `json:"pipeline_id"`
	JobID          string `json:"job_id"`
}

// boolClaim accepts true or "true".
type boolClaim bool

func (b *boolClaim) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case bool:
		*b = boolClaim(t)
	case string:
		*b = boolClaim(t == "true")
	default:
		*b = false
	}
	return nil
}

func identityFromClaims(is config.Issuer, c claims) (Identity, error) {
	id := Identity{Issuer: is.URL, Kind: is.Kind, Subject: c.Subject, JTI: c.JTI, SHA: c.SHA, RefProtected: bool(c.RefProtected)}
	switch is.Kind {
	case config.KindGitHub:
		if c.Repository == "" || c.Ref == "" {
			return Identity{}, fmt.Errorf("token lacks repository or ref claim")
		}
		id.Repo, id.Ref, id.Event = c.Repository, c.Ref, c.EventName
		id.WorkflowRef = c.JobWorkflowRef
		if id.WorkflowRef == "" {
			id.WorkflowRef = c.WorkflowRef
		}
		id.RunID = c.RunID
		if c.RunID != "" {
			id.RunURL = "https://github.com/" + c.Repository + "/actions/runs/" + c.RunID
		}
	case config.KindGitLab:
		if c.ProjectPath == "" || c.Ref == "" {
			return Identity{}, fmt.Errorf("token lacks project_path or ref claim")
		}
		ref, err := gitLabRef(c.RefPath, c.RefType, c.Ref)
		if err != nil {
			return Identity{}, err
		}
		id.Repo, id.Ref, id.Event = c.ProjectPath, ref, c.PipelineSource
		id.RunID = c.JobID
		if c.PipelineID != "" {
			id.RunURL = strings.TrimSuffix(is.URL, "/") + "/" + c.ProjectPath + "/-/pipelines/" + c.PipelineID
		}
	default:
		return Identity{}, fmt.Errorf("unknown issuer kind %q", is.Kind)
	}
	return id, nil
}

// gitLabRef returns the fully qualified ref. It prefers the ref_path claim.
// Without it, ref_type decides; a ref that already starts with "refs/" is
// refused, because ref_type would not describe it.
func gitLabRef(refPath, refType, ref string) (string, error) {
	if refPath != "" {
		if !strings.HasPrefix(refPath, "refs/heads/") && !strings.HasPrefix(refPath, "refs/tags/") {
			return "", fmt.Errorf("unexpected ref_path %q", refPath)
		}
		return refPath, nil
	}
	if strings.HasPrefix(ref, "refs/") {
		return "", fmt.Errorf("ref %q is already qualified but ref_path is missing", ref)
	}
	switch refType {
	case "branch":
		return "refs/heads/" + ref, nil
	case "tag":
		return "refs/tags/" + ref, nil
	}
	return "", fmt.Errorf("unknown ref_type %q", refType)
}

var defaultEvents = map[string][]string{
	config.KindGitHub: {"push", "workflow_dispatch", "release"},
	config.KindGitLab: {"push", "web"},
	config.KindDev:    {"dev"},
}

// KindKey marks an access-key identity.
const KindKey = "key"

// Allowed reports whether id may use profile. It returns the reason for a deny.
// Deny by default: some rule must match every field. Access keys carry their
// own profile list instead of allow rules.
func Allowed(rules []config.Rule, id Identity, profile string) (bool, string) {
	return allowed(rules, id, &profile)
}

// AllowedAny reports whether some rule admits id for any profile. The server
// checks it before it takes a queue slot; Allowed runs once the profile is known.
func AllowedAny(rules []config.Rule, id Identity) (bool, string) {
	return allowed(rules, id, nil)
}

func allowed(rules []config.Rule, id Identity, profile *string) (bool, string) {
	if id.Kind == KindKey {
		if profile == nil && len(id.KeyProfiles) > 0 || profile != nil && slices.Contains(id.KeyProfiles, *profile) {
			return true, ""
		}
		return false, "profile is not allowed for this access key"
	}
	reason := "no allow rule matches issuer and repo"
	for _, r := range rules {
		if r.Issuer != id.Issuer || r.Repo != id.Repo {
			continue
		}
		if !globAny(r.Refs, id.Ref) {
			reason = "ref " + id.Ref + " is not allowed"
			continue
		}
		if r.ProtectedRefRequired() && !id.RefProtected {
			reason = "ref " + id.Ref + " is not protected"
			continue
		}
		events := r.Events
		if len(events) == 0 {
			events = defaultEvents[id.Kind]
		}
		if id.Event == "" || !slices.Contains(events, id.Event) {
			reason = "event " + id.Event + " is not allowed"
			continue
		}
		if len(r.WorkflowRefs) > 0 && !globAny(r.WorkflowRefs, id.WorkflowRef) {
			reason = "workflow " + id.WorkflowRef + " is not allowed"
			continue
		}
		if profile != nil && !slices.Contains(r.Profiles, *profile) {
			reason = "profile " + *profile + " is not allowed"
			continue
		}
		return true, ""
	}
	return false, reason
}

func globAny(globs []string, s string) bool {
	if s == "" {
		return false
	}
	for _, g := range globs {
		if ok, err := path.Match(g, s); err == nil && ok {
			return true
		}
	}
	return false
}
