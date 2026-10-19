package auth

import (
	"errors"
	"sync"
	"time"
)

var ErrReplay = errors.New("token was already used")

// ReplayCache remembers (issuer, jti) pairs until the token expires, so one
// token can create only one job.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

func NewReplayCache() *ReplayCache {
	return &ReplayCache{seen: map[string]time.Time{}, now: time.Now}
}

// Check fails when the token has no jti or was already used. It records
// nothing, so a request refused later (queue full, low disk) can retry.
func (c *ReplayCache) Check(id Identity) error {
	return c.check(id, false)
}

// Use records the token. It fails when the token has no jti or was seen.
// Dev-mode tokens and access keys are not checked.
func (c *ReplayCache) Use(id Identity) error {
	return c.check(id, true)
}

func (c *ReplayCache) check(id Identity, record bool) error {
	if id.Issuer == DevIssuer || id.Kind == KindKey {
		return nil
	}
	if id.JTI == "" {
		return errors.New("token has no jti claim")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	key := id.Issuer + "\x00" + id.JTI
	if _, ok := c.seen[key]; ok {
		return ErrReplay
	}
	if !record {
		return nil
	}
	exp := id.Expiry
	if exp.IsZero() {
		exp = now.Add(time.Hour)
	}
	c.seen[key] = exp
	return nil
}
