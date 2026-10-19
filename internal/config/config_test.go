package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExampleConfigParses(t *testing.T) {
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8787" || len(c.Profiles) == 0 || len(c.Allow) == 0 {
		t.Fatalf("%+v", c)
	}
}

const base = `
work_dir: /w
audit_log: /a
profiles:
  - name: release
    identity: "Developer ID Application: Example Corp (TEAMID1234)"
    keychain: /k
    team_id: TEAMID1234
    notary:
%s
`

func TestNotaryValidation(t *testing.T) {
	cases := map[string]string{
		"both":        "      keychain_profile: p\n      keychain: /k\n      api_key_path: /x.p8\n      key_id: ABCDE12345\n      issuer_id: 6053b7fe-68a8-4acb-89be-165aa6465141",
		"none":        "      {}",
		"bad issuer":  "      api_key_path: /x.p8\n      key_id: ABCDE12345\n      issuer_id: nope",
		"no keychain": "      keychain_profile: p",
		"unknown key": "      keychain_profile: p\n      keychain: /k\n      password: x",
	}
	for name, n := range cases {
		if _, err := Parse([]byte(strings.Replace(base, "%s", n, 1))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := "      api_key_path: /x.p8\n      key_id: ABCDE12345\n      issuer_id: 6053b7fe-68a8-4acb-89be-165aa6465141"
	c, err := Parse([]byte(strings.Replace(base, "%s", ok, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if c.QueueSize != 5 || c.UploadTimeout != 30*time.Minute || c.MaxUploadBytes != 2<<30 || c.MaxRetainedJobs != 20 || !c.Profiles[0].Runtime() {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestCheckFilesP8Mode(t *testing.T) {
	p8 := filepath.Join(t.TempDir(), "AuthKey.p8")
	os.WriteFile(p8, []byte("k"), 0o644)
	c := &Config{Profiles: []Profile{{Name: "r", Notary: Notary{APIKeyPath: p8}}}}
	if err := c.CheckFiles(); err == nil {
		t.Fatal("readable .p8 accepted")
	}
	os.Chmod(p8, 0o600)
	if err := c.CheckFiles(); err != nil {
		t.Fatal(err)
	}
}

func TestUploadPartBytes(t *testing.T) {
	ok := "      api_key_path: /x.p8\n      key_id: ABCDE12345\n      issuer_id: 6053b7fe-68a8-4acb-89be-165aa6465141"
	cases := []struct {
		name  string
		extra string
		want  int64 // 0: must be rejected
	}{
		{"default", "", 64 << 20},
		{"95 MiB is the cap", "upload_part_bytes: 99614720\n", 95 << 20},
		{"over the cap", "upload_part_bytes: 99614721\n", 0},
		{"negative", "upload_part_bytes: -1\n", 0},
		{"small", "upload_part_bytes: 1024\n", 1024},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Parse([]byte(c.extra + strings.Replace(base, "%s", ok, 1)))
			if c.want == 0 {
				if err == nil {
					t.Fatal("accepted")
				}
				return
			}
			if err != nil || cfg.UploadPartBytes != c.want {
				t.Fatalf("%v %v", cfg, err)
			}
		})
	}
}
