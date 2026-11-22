// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Per-identity bounds on guardian peer broker lookups (managed Windows
// route-only, REVIEW-code-winroute P3-2). The broker is asked once per new
// connection with a valid route credential, before the per-subject limiter
// (which keys on the answer), so without its own bound one enrolled account
// opening many connections could hold every broker slot and get the lookups
// of other accounts refused. Each credential identity gets a token bucket
// and an in-flight cap; a lookup waits up to routePeerLookupWait for both,
// then the request gets 429 (routeCallerPeerLookupLimited). One agent opens
// a handful of connections and keeps them alive, far below these bounds.
const (
	routePeerLookupRate     = 20
	routePeerLookupBurst    = 40
	routePeerLookupInFlight = 4
	routePeerLookupWait     = time.Second
	// routePeerLookupIdle and routePeerLookupPruneAt bound the table: an
	// idle entry is dropped once the table holds more identities.
	routePeerLookupIdle    = 10 * time.Minute
	routePeerLookupPruneAt = 1024
)

var errRoutePeerLookupLimited = errors.New("route-only peer lookups over the account bound")

type routePeerLimit struct {
	slots chan struct{}
	rate  *rate.Limiter
	last  time.Time
}

type routePeerLimiter struct {
	mu      sync.Mutex
	entries map[string]*routePeerLimit
}

var routePeerLookups = &routePeerLimiter{}

// acquire waits for a lookup slot of identity; release frees it.
func (l *routePeerLimiter) acquire(ctx context.Context, identity string) (func(), error) {
	entry := l.entry(identity)
	if ctx == nil {
		ctx = context.Background()
	}
	waitCtx, cancel := context.WithTimeout(ctx, routePeerLookupWait)
	defer cancel()
	if err := entry.rate.Wait(waitCtx); err != nil {
		return nil, errRoutePeerLookupLimited
	}
	select {
	case entry.slots <- struct{}{}:
		return func() { <-entry.slots }, nil
	case <-waitCtx.Done():
		return nil, errRoutePeerLookupLimited
	}
}

func (l *routePeerLimiter) entry(identity string) *routePeerLimit {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.entries == nil {
		l.entries = map[string]*routePeerLimit{}
	}
	entry, ok := l.entries[identity]
	if !ok {
		if len(l.entries) >= routePeerLookupPruneAt {
			for key, e := range l.entries {
				if len(e.slots) == 0 && now.Sub(e.last) > routePeerLookupIdle {
					delete(l.entries, key)
				}
			}
		}
		entry = &routePeerLimit{slots: make(chan struct{}, routePeerLookupInFlight), rate: rate.NewLimiter(routePeerLookupRate, routePeerLookupBurst)}
		l.entries[identity] = entry
	}
	entry.last = now
	return entry
}
