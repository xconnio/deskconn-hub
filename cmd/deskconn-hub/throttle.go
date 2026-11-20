package main

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// Password logins are limited per account, against guessing one account's password. The Hub
// learns neither where an attempt comes from nor whether it succeeded, so every attempt counts.
// Limits per source, against guesses spread over many accounts, belong in front of the Hub.
const (
	accountLoginAttempts = 20
	accountLoginWindow   = 15 * time.Minute
	// maxTrackedAccounts bounds the memory attempts at many accounts can take (about 10 MB);
	// reaching it starts a new window early.
	maxTrackedAccounts = 100_000
)

var errTooManyLoginAttempts = errors.New("too many login attempts, try again later")

// loginThrottle admits password logins within the limits above. Its zero value is ready to use.
type loginThrottle struct {
	mu      sync.Mutex
	now     func() time.Time
	account windowCounter
}

// admit counts an attempt to log in as authID, or refuses it once its account's limit is reached.
func (l *loginThrottle) admit(authID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	account := strings.ToLower(strings.TrimSpace(authID))
	if !l.account.below(now, accountLoginWindow, maxTrackedAccounts, account, accountLoginAttempts) {
		return errTooManyLoginAttempts
	}
	l.account.add(account)
	return nil
}

// windowCounter counts attempts per key in fixed windows; starting a window forgets the last.
// A window also starts once it holds maxKeys keys, so it never holds more.
type windowCounter struct {
	start  time.Time
	counts map[string]int
}

func (w *windowCounter) below(now time.Time, window time.Duration, maxKeys int, key string, limit int) bool {
	if w.counts == nil || now.Sub(w.start) >= window || len(w.counts) >= maxKeys {
		w.start, w.counts = now, map[string]int{}
	}
	return w.counts[key] < limit
}

func (w *windowCounter) add(key string) { w.counts[key]++ }
