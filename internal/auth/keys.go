package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// KeyPrefix starts every access key: csk_<id>_<secret>.
const KeyPrefix = "csk_"

// KeyIssuer is the issuer of access-key identities.
const KeyIssuer = "access-key"

// AccessKey is one stored key. Only the SHA-256 of the secret is kept.
// The secret has 256 random bits, so a plain hash is enough.
type AccessKey struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Profiles   []string  `json:"profiles"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires,omitzero"`
	Revoked    bool      `json:"revoked,omitempty"`
	SecretHash string    `json:"secret_hash"`
}

// KeyStore reads and writes the access key file. It reads the file on each
// call, so keys made or revoked by the CLI apply without a restart.
type KeyStore struct {
	Path string
	now  func() time.Time
}

func NewKeyStore(path string) *KeyStore { return &KeyStore{Path: path, now: time.Now} }

func (s *KeyStore) List() ([]AccessKey, error) {
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []AccessKey
	if err := json.Unmarshal(b, &keys); err != nil {
		return nil, fmt.Errorf("access key file: %w", err)
	}
	return keys, nil
}

// Create makes a key and returns the full key string. It is shown once.
func (s *KeyStore) Create(name string, profiles []string, ttl time.Duration) (AccessKey, string, error) {
	idb := make([]byte, 8)
	sec := make([]byte, 32)
	if _, err := rand.Read(idb); err != nil {
		return AccessKey{}, "", err
	}
	if _, err := rand.Read(sec); err != nil {
		return AccessKey{}, "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(sec)
	k := AccessKey{ID: hex.EncodeToString(idb), Name: name, Profiles: profiles, Created: s.now().UTC(), SecretHash: hashSecret(secret)}
	if ttl > 0 {
		k.Expires = k.Created.Add(ttl)
	}
	err := s.modify(func(keys []AccessKey) ([]AccessKey, error) { return append(keys, k), nil })
	if err != nil {
		return AccessKey{}, "", err
	}
	return k, KeyPrefix + k.ID + "_" + secret, nil
}

func (s *KeyStore) Revoke(id string) error {
	return s.modify(func(keys []AccessKey) ([]AccessKey, error) {
		for i := range keys {
			if keys[i].ID == id {
				keys[i].Revoked = true
				return keys, nil
			}
		}
		return nil, fmt.Errorf("no key with id %s", id)
	})
}

// Verify checks a full key string and returns the caller identity.
func (s *KeyStore) Verify(raw string) (Identity, error) {
	rest, ok := strings.CutPrefix(raw, KeyPrefix)
	id, secret, ok2 := strings.Cut(rest, "_")
	if !ok || !ok2 || id == "" || secret == "" {
		return Identity{}, fmt.Errorf("%w: malformed access key", ErrUnauthorized)
	}
	keys, err := s.List()
	if err != nil {
		return Identity{}, err
	}
	want := hashSecret(secret)
	for _, k := range keys {
		if k.ID != id {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(k.SecretHash)) != 1 {
			break
		}
		if k.Revoked {
			return Identity{}, fmt.Errorf("%w: access key %s is revoked", ErrUnauthorized, id)
		}
		if !k.Expires.IsZero() && s.now().After(k.Expires) {
			return Identity{}, fmt.Errorf("%w: access key %s expired", ErrUnauthorized, id)
		}
		return Identity{Issuer: KeyIssuer, Kind: KindKey, Subject: k.ID, Repo: "key:" + k.Name,
			KeyID: k.ID, KeyName: k.Name, KeyProfiles: k.Profiles}, nil
	}
	return Identity{}, fmt.Errorf("%w: unknown access key", ErrUnauthorized)
}

// modify changes the key file under an exclusive lock and writes it
// atomically with mode 0600.
func (s *KeyStore) modify(f func([]AccessKey) ([]AccessKey, error)) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	keys, err := s.List()
	if err != nil {
		return err
	}
	keys, err = f(keys)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".keys-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.Path)
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
