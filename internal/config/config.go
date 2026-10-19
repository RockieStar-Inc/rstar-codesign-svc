// Package config loads the service YAML config.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Issuer kinds.
const (
	KindGitHub = "github"
	KindGitLab = "gitlab"
	KindDev    = "dev"
)

// GitHubIssuer is the GitHub Actions OIDC issuer.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

type Config struct {
	Listen           string        `yaml:"listen"`
	WorkDir          string        `yaml:"work_dir"`
	AuditLog         string        `yaml:"audit_log"`
	QueueSize        int           `yaml:"queue_size"`
	ResultTTL        time.Duration `yaml:"result_ttl"`
	JobTimeout       time.Duration `yaml:"job_timeout"`
	UploadTimeout    time.Duration `yaml:"upload_timeout"`
	MaxUploadBytes   int64         `yaml:"max_upload_bytes"`
	MaxExpandedBytes int64         `yaml:"max_expanded_bytes"`
	MaxFiles         int           `yaml:"max_files"`
	MinFreeBytes     int64         `yaml:"min_free_bytes"`
	MaxRetainedJobs  int           `yaml:"max_retained_jobs"`
	Issuers          []Issuer      `yaml:"issuers"`
	Allow            []Rule        `yaml:"allow"`
	Profiles         []Profile     `yaml:"profiles"`
	AccessKeys       AccessKeys    `yaml:"access_keys"`
	DevMode          DevMode       `yaml:"dev_mode"`
}

// AccessKeys is the fallback auth for CI without OIDC. Off by default.
type AccessKeys struct {
	Enabled bool   `yaml:"enabled"`
	File    string `yaml:"file"`
}

type Issuer struct {
	URL      string `yaml:"url"`
	Kind     string `yaml:"kind"` // github or gitlab; inferred from URL when empty
	Audience string `yaml:"audience"`
}

// Rule allows one repo on some refs to use some profiles.
type Rule struct {
	Issuer   string   `yaml:"issuer"`
	Repo     string   `yaml:"repo"`
	Refs     []string `yaml:"refs"`
	Profiles []string `yaml:"profiles"`
	// RequireProtectedRef defaults to true.
	RequireProtectedRef *bool `yaml:"require_protected_ref"`
	// Events defaults to [push, workflow_dispatch, release] on GitHub and
	// [push, web] on GitLab.
	Events []string `yaml:"events"`
	// WorkflowRefs are globs on the GitHub job_workflow_ref claim. Empty means any.
	WorkflowRefs []string `yaml:"workflow_refs"`
}

func (r Rule) ProtectedRefRequired() bool {
	return r.RequireProtectedRef == nil || *r.RequireProtectedRef
}

type Override struct {
	Match        string `yaml:"match"` // path.Match glob on the path relative to the .app
	Entitlements string `yaml:"entitlements"`
}

type Profile struct {
	Name                 string     `yaml:"name"`
	Identity             string     `yaml:"identity"`
	Keychain             string     `yaml:"keychain"`
	TeamID               string     `yaml:"team_id"`
	AllowedBundleIDs     []string   `yaml:"allowed_bundle_ids"`
	Entitlements         string     `yaml:"entitlements"`
	InheritEntitlements  string     `yaml:"inherit_entitlements"`
	EntitlementOverrides []Override `yaml:"entitlement_overrides"`
	HardenedRuntime      *bool      `yaml:"hardened_runtime"`
	Notary               Notary     `yaml:"notary"`
	DMG                  bool       `yaml:"dmg"`
	VolumeName           string     `yaml:"volume_name"`
}

// Notary holds notarytool credentials. Set exactly one option:
// keychain_profile + keychain, or api_key_path + key_id + issuer_id.
type Notary struct {
	KeychainProfile string `yaml:"keychain_profile"`
	Keychain        string `yaml:"keychain"`
	APIKeyPath      string `yaml:"api_key_path"`
	KeyID           string `yaml:"key_id"`
	IssuerID        string `yaml:"issuer_id"`
}

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	keyIDRe = regexp.MustCompile(`^[A-Z0-9]{8,16}$`)
)

func (n Notary) validate() error {
	kc := n.KeychainProfile != "" || n.Keychain != ""
	api := n.APIKeyPath != "" || n.KeyID != "" || n.IssuerID != ""
	switch {
	case kc && api:
		return errors.New("notary: set keychain_profile/keychain or api_key_path/key_id/issuer_id, not both")
	case kc:
		if n.KeychainProfile == "" || n.Keychain == "" {
			return errors.New("notary: keychain_profile and keychain are both required")
		}
	case api:
		if n.APIKeyPath == "" || !keyIDRe.MatchString(n.KeyID) || !uuidRe.MatchString(n.IssuerID) {
			return errors.New("notary: api_key_path, key_id (A-Z0-9) and issuer_id (UUID) are required")
		}
	default:
		return errors.New("notary: no credentials set")
	}
	return nil
}

func (p Profile) Runtime() bool { return p.HardenedRuntime == nil || *p.HardenedRuntime }

// DevMode accepts one static token from an env var. For local tests only.
type DevMode struct {
	Enabled  bool   `yaml:"enabled"`
	TokenEnv string `yaml:"token_env"`
	Repo     string `yaml:"repo"`
	Ref      string `yaml:"ref"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8787"
	}
	if c.QueueSize == 0 {
		c.QueueSize = 5
	}
	if c.ResultTTL == 0 {
		c.ResultTTL = 24 * time.Hour
	}
	if c.JobTimeout == 0 {
		c.JobTimeout = 2 * time.Hour
	}
	if c.UploadTimeout == 0 {
		c.UploadTimeout = 30 * time.Minute
	}
	if c.MaxUploadBytes == 0 {
		c.MaxUploadBytes = 2 << 30
	}
	if c.MaxExpandedBytes == 0 {
		c.MaxExpandedBytes = 4 << 30
	}
	if c.MaxFiles == 0 {
		c.MaxFiles = 200000
	}
	if c.MinFreeBytes == 0 {
		c.MinFreeBytes = 20 << 30
	}
	if c.MaxRetainedJobs == 0 {
		c.MaxRetainedJobs = 20
	}
	if c.DevMode.TokenEnv == "" {
		c.DevMode.TokenEnv = "CODESIGN_DEV_TOKEN"
	}
	for i := range c.Issuers {
		if c.Issuers[i].Kind == "" {
			if c.Issuers[i].URL == GitHubIssuer {
				c.Issuers[i].Kind = KindGitHub
			} else {
				c.Issuers[i].Kind = KindGitLab
			}
		}
	}
}

func (c *Config) Validate() error {
	var errs []error
	if c.WorkDir == "" {
		errs = append(errs, errors.New("work_dir is required"))
	}
	if c.AccessKeys.Enabled && c.AccessKeys.File == "" {
		errs = append(errs, errors.New("access_keys.file is required when access keys are enabled"))
	}
	if c.AuditLog == "" {
		errs = append(errs, errors.New("audit_log is required"))
	}
	for _, is := range c.Issuers {
		if is.URL == "" || is.Audience == "" {
			errs = append(errs, fmt.Errorf("issuer %q: url and audience are required", is.URL))
		}
		if is.Kind != KindGitHub && is.Kind != KindGitLab {
			errs = append(errs, fmt.Errorf("issuer %q: kind must be github or gitlab", is.URL))
		}
	}
	names := map[string]bool{}
	for _, p := range c.Profiles {
		if p.Name == "" || p.Identity == "" || p.Keychain == "" || p.TeamID == "" {
			errs = append(errs, fmt.Errorf("profile %q: name, identity, keychain, team_id are required", p.Name))
		}
		if err := p.Notary.validate(); err != nil {
			errs = append(errs, fmt.Errorf("profile %q: %w", p.Name, err))
		}
		if names[p.Name] {
			errs = append(errs, fmt.Errorf("profile %q: duplicate name", p.Name))
		}
		names[p.Name] = true
	}
	for i, r := range c.Allow {
		if r.Issuer == "" || r.Repo == "" || len(r.Refs) == 0 || len(r.Profiles) == 0 {
			errs = append(errs, fmt.Errorf("allow[%d]: issuer, repo, refs, profiles are required", i))
		}
		for _, p := range r.Profiles {
			if !names[p] {
				errs = append(errs, fmt.Errorf("allow[%d]: unknown profile %q", i, p))
			}
		}
	}
	return errors.Join(errs...)
}

// CheckFiles checks file permissions that matter for secrets. Run it at
// startup: an App Store Connect .p8 key must not be group or world readable.
func (c *Config) CheckFiles() error {
	var errs []error
	for _, p := range c.Profiles {
		if p.Notary.APIKeyPath == "" {
			continue
		}
		fi, err := os.Stat(p.Notary.APIKeyPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("profile %q: %w", p.Name, err))
			continue
		}
		if fi.Mode().Perm()&0o077 != 0 {
			errs = append(errs, fmt.Errorf("profile %q: %s is readable by others (mode %o); chmod 600 it", p.Name, p.Notary.APIKeyPath, fi.Mode().Perm()))
		}
	}
	return errors.Join(errs...)
}

func (c *Config) Profile(name string) (Profile, bool) {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}
