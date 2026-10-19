package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
)

type testIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ti := &testIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                ti.srv.URL,
			"jwks_uri":                              ti.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	ti.srv = httptest.NewServer(mux)
	t.Cleanup(ti.srv.Close)
	return ti
}

func (ti *testIssuer) token(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"}) + "." + enc(claims)
	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (ti *testIssuer) githubClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": ti.srv.URL, "aud": "codesign-test", "sub": "repo:example/app:ref:refs/heads/main",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "jti": "jti-1",
		"repository": "example/app", "ref": "refs/heads/main", "ref_protected": "true",
		"event_name": "push", "sha": "0123abcd", "run_id": "99",
		"job_workflow_ref": "example/app/.github/workflows/release.yml@refs/heads/main",
	}
}

func TestVerifyGitHubToken(t *testing.T) {
	ti := newTestIssuer(t)
	cfg := &config.Config{Issuers: []config.Issuer{{URL: ti.srv.URL, Kind: config.KindGitHub, Audience: "codesign-test"}}}
	v := NewVerifier(cfg, ti.srv.Client())
	ctx := context.Background()

	id, err := v.Verify(ctx, ti.token(t, ti.key, ti.githubClaims()))
	if err != nil {
		t.Fatal(err)
	}
	if id.Repo != "example/app" || id.Ref != "refs/heads/main" || !id.RefProtected || id.Event != "push" ||
		id.JTI != "jti-1" || id.SHA != "0123abcd" || id.RunURL != "https://github.com/example/app/actions/runs/99" ||
		id.WorkflowRef == "" || id.Expiry.IsZero() {
		t.Fatalf("identity: %+v", id)
	}

	bad := map[string]func(map[string]any){
		"wrong audience": func(c map[string]any) { c["aud"] = "other" },
		"expired":        func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"no repository":  func(c map[string]any) { delete(c, "repository") },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			c := ti.githubClaims()
			mutate(c)
			if _, err := v.Verify(ctx, ti.token(t, ti.key, c)); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("err = %v, want unauthorized", err)
			}
		})
	}
	t.Run("wrong key", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		if _, err := v.Verify(ctx, ti.token(t, other, ti.githubClaims())); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unknown issuer", func(t *testing.T) {
		c := ti.githubClaims()
		c["iss"] = "https://unknown.example"
		if _, err := v.Verify(ctx, ti.token(t, ti.key, c)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if _, err := v.Verify(ctx, "not-a-jwt"); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("access keys disabled", func(t *testing.T) {
		if _, err := v.Verify(ctx, "csk_0011223344556677_secret"); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestVerifyGitLabToken(t *testing.T) {
	ti := newTestIssuer(t)
	cfg := &config.Config{Issuers: []config.Issuer{{URL: ti.srv.URL, Kind: config.KindGitLab, Audience: "codesign-test"}}}
	v := NewVerifier(cfg, ti.srv.Client())
	now := time.Now()
	tok := ti.token(t, ti.key, map[string]any{
		"iss": ti.srv.URL, "aud": "codesign-test", "sub": "project_path:group/app:ref_type:tag:ref:v1.0",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "jti": "j",
		"project_path": "group/app", "ref": "v1.0", "ref_type": "tag", "ref_protected": "true",
		"pipeline_source": "push", "pipeline_id": "7", "job_id": "8",
	})
	id, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if id.Repo != "group/app" || id.Ref != "refs/tags/v1.0" || id.Event != "push" || id.RunID != "8" || !id.RefProtected {
		t.Fatalf("identity: %+v", id)
	}
}
