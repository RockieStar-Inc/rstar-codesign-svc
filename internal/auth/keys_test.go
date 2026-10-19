package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAccessKeys(t *testing.T) {
	s := NewKeyStore(filepath.Join(t.TempDir(), "keys.json"))
	k, raw, err := s.Create("ci", []string{"release"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, KeyPrefix+k.ID+"_") {
		t.Fatalf("key format: %s", raw)
	}
	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(s.Path)
	if strings.Contains(string(b), strings.TrimPrefix(raw, KeyPrefix+k.ID+"_")) {
		t.Fatal("secret stored in clear")
	}

	id, err := s.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if id.Kind != KindKey || id.KeyID != k.ID || id.KeyName != "ci" || id.KeyProfiles[0] != "release" {
		t.Fatalf("identity %+v", id)
	}
	for name, bad := range map[string]string{
		"wrong secret": KeyPrefix + k.ID + "_AAAA",
		"unknown id":   KeyPrefix + "ffffffffffffffff_" + strings.TrimPrefix(raw, KeyPrefix+k.ID+"_"),
		"malformed":    KeyPrefix + "nounderscore",
	} {
		if _, err := s.Verify(bad); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}

	s.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if _, err := s.Verify(raw); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired key: %v", err)
	}
	s.now = time.Now

	if err := s.Revoke(k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(raw); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked key: %v", err)
	}
	if err := s.Revoke("nope"); err == nil {
		t.Fatal("revoke unknown id succeeded")
	}
}
