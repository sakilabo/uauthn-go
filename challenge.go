package uauthn

import (
	"crypto/rand"
	"sync"
	"time"
)

const challengeTTL = 10 * time.Minute

type challenge struct {
	register bool
	user     string
	expires  time.Time
}

type challenges struct {
	mu sync.Mutex
	m  map[string]challenge
}

func (c *challenges) issue(register bool, user string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	v := b64url.EncodeToString(b)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]challenge)
	}
	for k, ch := range c.m {
		if now.After(ch.expires) {
			delete(c.m, k)
		}
	}
	c.m[v] = challenge{register: register, user: user, expires: now.Add(challengeTTL)}
	return v, nil
}

func (c *challenges) take(v string, register bool) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.m[v]
	if !ok {
		return "", false
	}
	delete(c.m, v)
	if ch.register != register || time.Now().After(ch.expires) {
		return "", false
	}
	return ch.user, true
}
