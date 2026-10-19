package auth

import (
	"strings"
	"testing"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
)

const glIssuer = "https://gitlab.example.com"

func rules() []config.Rule {
	no := false
	return []config.Rule{
		{Issuer: config.GitHubIssuer, Repo: "example/app", Refs: []string{"refs/heads/main", "refs/tags/v*"}, Profiles: []string{"release"}},
		{Issuer: config.GitHubIssuer, Repo: "example/pinned", Refs: []string{"refs/tags/v*"}, Profiles: []string{"release"},
			WorkflowRefs: []string{"example/pinned/.github/workflows/release.yml@refs/tags/v*"}},
		{Issuer: config.GitHubIssuer, Repo: "example/pr", Refs: []string{"refs/heads/*"}, Profiles: []string{"release"},
			Events: []string{"pull_request"}, RequireProtectedRef: &no},
		{Issuer: glIssuer, Repo: "group/app", Refs: []string{"refs/heads/main", "refs/tags/v*"}, Profiles: []string{"release"}},
	}
}

func gh(repo, ref, event string) Identity {
	return Identity{Issuer: config.GitHubIssuer, Kind: config.KindGitHub, Repo: repo, Ref: ref, RefProtected: true, Event: event}
}

func TestAllowed(t *testing.T) {
	pinned := gh("example/pinned", "refs/tags/v1.0.0", "push")
	pinned.WorkflowRef = "example/pinned/.github/workflows/release.yml@refs/tags/v1.0.0"
	pinnedOther := pinned
	pinnedOther.WorkflowRef = "example/pinned/.github/workflows/other.yml@refs/tags/v1.0.0"
	unprotected := gh("example/app", "refs/heads/main", "push")
	unprotected.RefProtected = false
	prUnprotected := gh("example/pr", "refs/heads/feature", "pull_request")
	prUnprotected.RefProtected = false
	gl := func(ref, source string) Identity {
		return Identity{Issuer: glIssuer, Kind: config.KindGitLab, Repo: "group/app", Ref: ref, RefProtected: true, Event: source}
	}

	cases := []struct {
		name    string
		id      Identity
		profile string
		want    bool
		reason  string
	}{
		{"main push", gh("example/app", "refs/heads/main", "push"), "release", true, ""},
		{"tag glob", gh("example/app", "refs/tags/v1.2.3", "push"), "release", true, ""},
		{"workflow_dispatch", gh("example/app", "refs/heads/main", "workflow_dispatch"), "release", true, ""},
		{"release event", gh("example/app", "refs/tags/v1", "release"), "release", true, ""},
		{"other branch", gh("example/app", "refs/heads/dev", "push"), "release", false, "ref"},
		{"tag not matching", gh("example/app", "refs/tags/x1", "push"), "release", false, "ref"},
		{"glob does not cross slash", gh("example/app", "refs/tags/v1/evil", "push"), "release", false, "ref"},
		{"other repo", gh("example/other", "refs/heads/main", "push"), "release", false, "no allow rule"},
		{"other profile", gh("example/app", "refs/heads/main", "push"), "debug", false, "profile"},
		{"unprotected ref", unprotected, "release", false, "not protected"},
		{"pull_request", gh("example/app", "refs/heads/main", "pull_request"), "release", false, "event"},
		{"pull_request_target", gh("example/app", "refs/heads/main", "pull_request_target"), "release", false, "event"},
		{"workflow_run", gh("example/app", "refs/heads/main", "workflow_run"), "release", false, "event"},
		{"missing event", gh("example/app", "refs/heads/main", ""), "release", false, "event"},
		{"pull_request listed", prUnprotected, "release", true, ""},
		{"workflow ref match", pinned, "release", true, ""},
		{"workflow ref mismatch", pinnedOther, "release", false, "workflow"},
		{"gitlab branch", gl("refs/heads/main", "push"), "release", true, ""},
		{"gitlab web", gl("refs/tags/v2", "web"), "release", true, ""},
		{"gitlab merge request", gl("refs/heads/main", "merge_request_event"), "release", false, "event"},
		{"gitlab external pr", gl("refs/heads/main", "external_pull_request_event"), "release", false, "event"},
		{"gitlab schedule not default", gl("refs/heads/main", "schedule"), "release", false, "event"},
		{"wrong issuer", Identity{Issuer: "https://evil.example", Kind: config.KindGitHub, Repo: "example/app", Ref: "refs/heads/main", RefProtected: true, Event: "push"}, "release", false, "no allow rule"},
		{"access key profile", Identity{Kind: KindKey, KeyProfiles: []string{"release"}}, "release", true, ""},
		{"access key other profile", Identity{Kind: KindKey, KeyProfiles: []string{"release"}}, "debug", false, "access key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := Allowed(rules(), c.id, c.profile)
			if got != c.want {
				t.Fatalf("Allowed = %v (%s), want %v", got, reason, c.want)
			}
			if !c.want && !strings.Contains(reason, c.reason) {
				t.Fatalf("reason %q does not contain %q", reason, c.reason)
			}
		})
	}
}

func TestAllowedAny(t *testing.T) {
	unprotected := gh("example/app", "refs/heads/main", "push")
	unprotected.RefProtected = false
	cases := []struct {
		name string
		id   Identity
		want bool
	}{
		{"allowed identity", gh("example/app", "refs/tags/v1", "push"), true},
		{"other repo", gh("example/other", "refs/heads/main", "push"), false},
		{"other ref", gh("example/app", "refs/heads/dev", "push"), false},
		{"unprotected", unprotected, false},
		{"pull_request_target", gh("example/app", "refs/heads/main", "pull_request_target"), false},
		{"workflow_run", gh("example/app", "refs/heads/main", "workflow_run"), false},
		{"key with profiles", Identity{Kind: KindKey, KeyProfiles: []string{"release"}}, true},
		{"key without profiles", Identity{Kind: KindKey}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, reason := AllowedAny(rules(), c.id); got != c.want {
				t.Fatalf("AllowedAny = %v (%s)", got, reason)
			}
		})
	}
}

func TestGitLabRef(t *testing.T) {
	cases := []struct {
		name                  string
		refPath, refType, ref string
		want                  string
	}{
		{"ref_path branch", "refs/heads/main", "branch", "main", "refs/heads/main"},
		{"ref_path tag", "refs/tags/v1.0", "tag", "v1.0", "refs/tags/v1.0"},
		{"ref_path wins over ref_type", "refs/tags/v1", "branch", "v1", "refs/tags/v1"},
		{"ref_path other namespace", "refs/merge-requests/1/head", "branch", "x", ""},
		{"branch", "", "branch", "main", "refs/heads/main"},
		{"tag", "", "tag", "v1.0", "refs/tags/v1.0"},
		{"branch with slash", "", "branch", "release/1.x", "refs/heads/release/1.x"},
		{"qualified ref without ref_path is refused", "", "branch", "refs/tags/v1", ""},
		{"qualified heads ref refused too", "", "branch", "refs/heads/main", ""},
		{"unknown ref_type", "", "weird", "main", ""},
		{"missing ref_type", "", "", "main", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := gitLabRef(c.refPath, c.refType, c.ref)
			if c.want == "" {
				if err == nil {
					t.Fatalf("accepted as %q", got)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q %v, want %q", got, err, c.want)
			}
		})
	}
}

func TestIdentityFromClaims(t *testing.T) {
	gl := config.Issuer{URL: glIssuer, Kind: config.KindGitLab}
	ghi := config.Issuer{URL: config.GitHubIssuer, Kind: config.KindGitHub}
	cases := []struct {
		name string
		is   config.Issuer
		c    claims
		want Identity
		bad  bool
	}{
		{"gitlab", gl, claims{ProjectPath: "group/app", Ref: "main", RefType: "branch", RefPath: "refs/heads/main", RefProtected: true, PipelineSource: "push", PipelineID: "42", JobID: "7"},
			Identity{Repo: "group/app", Ref: "refs/heads/main", RefProtected: true, Event: "push", RunID: "7", RunURL: glIssuer + "/group/app/-/pipelines/42"}, false},
		{"gitlab missing project", gl, claims{Ref: "main", RefType: "branch"}, Identity{}, true},
		{"gitlab branch named like a tag ref", gl, claims{ProjectPath: "group/app", Ref: "refs/tags/v1", RefType: "branch"}, Identity{}, true},
		{"github", ghi, claims{Repository: "o/r", Ref: "refs/heads/main", RefProtected: true, EventName: "push", WorkflowRef: "o/r/.github/workflows/a.yml@refs/heads/main", RunID: "5"},
			Identity{Repo: "o/r", Ref: "refs/heads/main", RefProtected: true, Event: "push", WorkflowRef: "o/r/.github/workflows/a.yml@refs/heads/main", RunID: "5", RunURL: "https://github.com/o/r/actions/runs/5"}, false},
		{"github job_workflow_ref preferred", ghi, claims{Repository: "o/r", Ref: "refs/heads/main", JobWorkflowRef: "o/lib/.github/workflows/r.yml@refs/tags/v1", WorkflowRef: "o/r/x"},
			Identity{Repo: "o/r", Ref: "refs/heads/main", WorkflowRef: "o/lib/.github/workflows/r.yml@refs/tags/v1"}, false},
		{"github missing repository", ghi, claims{Ref: "refs/heads/main"}, Identity{}, true},
		{"unknown kind", config.Issuer{Kind: "x"}, claims{}, Identity{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, err := identityFromClaims(c.is, c.c)
			if c.bad {
				if err == nil {
					t.Fatalf("accepted: %+v", id)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			id.Issuer, id.Kind = "", ""
			if id.Repo != c.want.Repo || id.Ref != c.want.Ref || id.RefProtected != c.want.RefProtected || id.Event != c.want.Event ||
				id.WorkflowRef != c.want.WorkflowRef || id.RunID != c.want.RunID || id.RunURL != c.want.RunURL {
				t.Fatalf("got %+v\nwant %+v", id, c.want)
			}
		})
	}
}

func TestBoolClaim(t *testing.T) {
	cases := map[string]bool{`true`: true, `"true"`: true, `false`: false, `"false"`: false, `"yes"`: false, `1`: false, `null`: false}
	for in, want := range cases {
		var b boolClaim
		if err := b.UnmarshalJSON([]byte(in)); err != nil || bool(b) != want {
			t.Errorf("%s: %v %v", in, b, err)
		}
	}
	var b boolClaim
	if err := b.UnmarshalJSON([]byte(`{`)); err == nil {
		t.Error("bad JSON accepted")
	}
}

// TestExampleConfigRules checks that the example allow rules match the refs
// and workflow refs they are meant to match.
func TestExampleConfigRules(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	wf := "example-org/example-app/.github/workflows/release.yml@"
	cases := []struct {
		name       string
		ref, wfRef string
		want       bool
	}{
		{"main", "refs/heads/main", wf + "refs/heads/main", true},
		{"tag", "refs/tags/v1.2.3", wf + "refs/tags/v1.2.3", true},
		{"other workflow", "refs/heads/main", "example-org/example-app/.github/workflows/ci.yml@refs/heads/main", false},
		{"workflow from a branch, ref a tag", "refs/tags/v1", wf + "refs/heads/dev", false},
		{"branch not allowed", "refs/heads/dev", wf + "refs/heads/dev", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := gh("example-org/example-app", c.ref, "push")
			id.WorkflowRef = c.wfRef
			if got, reason := Allowed(cfg.Allow, id, "example-release"); got != c.want {
				t.Fatalf("Allowed = %v (%s)", got, reason)
			}
		})
	}
	gl := Identity{Issuer: "https://gitlab.com", Kind: config.KindGitLab, Repo: "example-group/example-app", Ref: "refs/tags/v2", RefProtected: true, Event: "push"}
	if ok, reason := Allowed(cfg.Allow, gl, "example-release"); !ok {
		t.Fatalf("gitlab tag: %s", reason)
	}
}

func TestReplayCheckDoesNotRecord(t *testing.T) {
	c := NewReplayCache()
	id := gh("example/app", "refs/heads/main", "push")
	id.JTI = "x"
	steps := []struct {
		name string
		use  bool
		want error
	}{
		{"check fresh", false, nil},
		{"check again: still fresh", false, nil},
		{"use", true, nil},
		{"check after use", false, ErrReplay},
		{"use again", true, ErrReplay},
	}
	for _, s := range steps {
		var err error
		if s.use {
			err = c.Use(id)
		} else {
			err = c.Check(id)
		}
		if err != s.want {
			t.Fatalf("%s: err = %v, want %v", s.name, err, s.want)
		}
	}
}

func TestReplayCache(t *testing.T) {
	c := NewReplayCache()
	id := gh("example/app", "refs/heads/main", "push")
	id.JTI = "abc"
	if err := c.Use(id); err != nil {
		t.Fatal(err)
	}
	if err := c.Use(id); err != ErrReplay {
		t.Fatalf("second use: %v", err)
	}
	id.JTI = ""
	if err := c.Use(id); err == nil {
		t.Fatal("missing jti accepted")
	}
	if err := c.Use(Identity{Kind: KindKey}); err != nil {
		t.Fatalf("access key: %v", err)
	}
}
