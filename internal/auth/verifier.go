package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
)

// DevIssuer is the issuer of the dev-mode identity.
const DevIssuer = "dev"

var ErrUnauthorized = errors.New("unauthorized")

// Verifier checks OIDC tokens against the configured issuers.
type Verifier struct {
	issuers  map[string]*issuerState
	client   *http.Client
	devToken string
	devID    Identity
	keys     *KeyStore
}

type issuerState struct {
	cfg      config.Issuer
	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// NewVerifier builds a verifier. Issuer discovery is lazy, so the service
// can start while an issuer is not reachable. client may be nil.
func NewVerifier(cfg *config.Config, client *http.Client) *Verifier {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	v := &Verifier{issuers: map[string]*issuerState{}, client: client}
	for _, is := range cfg.Issuers {
		v.issuers[is.URL] = &issuerState{cfg: is}
	}
	if cfg.AccessKeys.Enabled {
		v.keys = NewKeyStore(cfg.AccessKeys.File)
	}
	if cfg.DevMode.Enabled {
		if tok := os.Getenv(cfg.DevMode.TokenEnv); tok != "" {
			log.Printf("WARNING: DEV MODE IS ON. Static token from $%s is accepted as %s@%s. Never use this in production.",
				cfg.DevMode.TokenEnv, cfg.DevMode.Repo, cfg.DevMode.Ref)
			v.devToken = tok
			v.devID = Identity{Issuer: DevIssuer, Kind: config.KindDev, Subject: "dev", Repo: cfg.DevMode.Repo,
				Ref: cfg.DevMode.Ref, RefProtected: true, Event: "dev"}
		} else {
			log.Printf("WARNING: dev_mode.enabled is set but $%s is empty; dev mode is off", cfg.DevMode.TokenEnv)
		}
	}
	return v
}

// Verify checks a raw bearer token and returns the caller identity.
func (v *Verifier) Verify(ctx context.Context, raw string) (Identity, error) {
	if v.devToken != "" && subtle.ConstantTimeCompare([]byte(raw), []byte(v.devToken)) == 1 {
		return v.devID, nil
	}
	if strings.HasPrefix(raw, KeyPrefix) {
		if v.keys == nil {
			return Identity{}, fmt.Errorf("%w: access keys are disabled", ErrUnauthorized)
		}
		return v.keys.Verify(raw)
	}
	iss, err := unverifiedIssuer(raw)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	st, ok := v.issuers[iss]
	if !ok {
		return Identity{}, fmt.Errorf("%w: issuer %q is not configured", ErrUnauthorized, iss)
	}
	ver, err := st.get(ctx, v.client)
	if err != nil {
		return Identity{}, fmt.Errorf("issuer discovery for %s: %w", iss, err)
	}
	tok, err := ver.Verify(oidc.ClientContext(ctx, v.client), raw)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	var c claims
	if err := tok.Claims(&c); err != nil {
		return Identity{}, fmt.Errorf("%w: claims: %v", ErrUnauthorized, err)
	}
	id, err := identityFromClaims(st.cfg, c)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	id.Expiry = tok.Expiry
	return id, nil
}

func (s *issuerState) get(ctx context.Context, client *http.Client) (*oidc.IDTokenVerifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifier != nil {
		return s.verifier, nil
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, client), 15*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, s.cfg.URL)
	if err != nil {
		return nil, err
	}
	// The key set fetches keys with this context later, so it must not be
	// the request context.
	ks := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), jwksURL(p))
	s.verifier = oidc.NewVerifier(s.cfg.URL, ks, &oidc.Config{ClientID: s.cfg.Audience})
	return s.verifier, nil
}

func jwksURL(p *oidc.Provider) string {
	var m struct {
		JWKSURI string `json:"jwks_uri"`
	}
	_ = p.Claims(&m)
	return m.JWKSURI
}

func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed token")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("malformed token payload")
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(b, &c); err != nil || c.Iss == "" {
		return "", errors.New("token has no iss")
	}
	return c.Iss, nil
}
