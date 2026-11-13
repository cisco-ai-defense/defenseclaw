// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// maxUIDEntries bounds the cache; past it, entries older than the stale
// window are dropped, then everything.
const maxUIDEntries = 1 << 16

// uidMissTTL is how long "no registration" is reused: a launched actor is
// registered right after it is created, and its chain window starts with
// its first hook, so a miss must not hide it for the full TTL.
const uidMissTTL = time.Second

// ErrActorNotLive reports an actor the Control API says is not running.
var ErrActorNotLive = errors.New("extproc: actor is not live")

// UIDCache caches a UIDResolver per atespace/name. A fresh entry (younger
// than ttl, or uidMissTTL for an unregistered actor) is used as is; when
// the resolver fails, an entry younger than staleMax still serves (§5.5).
// No lifecycle event reaches the callout, so an entry can name an
// incarnation that was deleted, or replaced by a same-name actor created
// again, until it ages out. The engine does not let a decision stand on
// such an entry (see pass in decide.go): the leader answers a chain check
// under a UID that is not the name's live incarnation stale (the engine
// drops the entry with Invalidate), and a decision made on a cached entry
// that no chain answer confirmed is checked with Refresh (GAP-0234,
// GAP-0237).
type UIDCache struct {
	r        UIDResolver
	ttl      time.Duration
	staleMax time.Duration
	now      func() time.Time
	// refreshBudget bounds how long a request waits for a Refresh, and
	// refreshEvery how often a name is refreshed (GAP-0243).
	refreshBudget time.Duration
	refreshEvery  time.Duration

	mu      sync.Mutex
	m       map[string]uidEntry
	refresh map[string]*refreshState
	sf      singleflight.Group
}

// refreshFlightMax bounds one refresh lookup. A request waits refreshBudget
// at most; the lookup goes on, so its answer fills the cache for the next.
const refreshFlightMax = 2 * time.Second

// refreshState is a name's last refresh: when it started, whether it is
// still running, and what it confirmed (GAP-0243).
type refreshState struct {
	started   time.Time
	running   bool
	confirmed time.Time
	entry     uidEntry
}

// RefreshResult is what a Refresh learned.
type RefreshResult int

// Refresh results.
const (
	// RefreshSame: the registration is the cached one.
	RefreshSame RefreshResult = iota
	// RefreshChanged: another UID, profile or attendance, or deleted.
	RefreshChanged
	// RefreshUnconfirmed: no answer within the budget, an outage, or a
	// name refreshed within refreshEvery whose last refresh confirmed
	// nothing.
	RefreshUnconfirmed
)

type uidEntry struct {
	rec  ActorRecord
	live bool
	at   time.Time
}

func (e uidEntry) fresh(now time.Time, ttl time.Duration) bool {
	if e.live && e.rec.UID == "" {
		ttl = min(ttl, uidMissTTL)
	}
	return now.Sub(e.at) < ttl
}

// NewUIDCache wraps r. A nil r resolves nothing: every actor is live with
// no registration (a callout without a leader).
func NewUIDCache(r UIDResolver, ttl, staleMax time.Duration) *UIDCache {
	return &UIDCache{r: r, ttl: ttl, staleMax: staleMax, now: time.Now, m: map[string]uidEntry{},
		refresh: map[string]*refreshState{}, refreshBudget: defaultRefreshBudget, refreshEvery: ttl / 4}
}

// Where Resolve's answer came from.
type resolveSource int

const (
	// fromCache is a cached entry within its TTL.
	fromCache resolveSource = iota
	// fromResolver is the resolver's answer to this call.
	fromResolver
	// fromOutage is a resolver failure: a cached entry within staleMax, or
	// a LookupError.
	fromOutage
)

// Resolve returns a's current incarnation, and where the answer came from.
// ErrActorNotLive: the actor was deleted. Any other error is an outage with
// no usable cached entry.
func (c *UIDCache) Resolve(ctx context.Context, a ActorRef) (ActorRecord, resolveSource, error) {
	if c == nil || c.r == nil {
		return ActorRecord{}, fromResolver, nil
	}
	key := a.Key()
	now := c.now()
	c.mu.Lock()
	e, ok := c.m[key]
	c.mu.Unlock()
	if ok && e.fresh(now, c.ttl) {
		rec, err := e.result()
		return rec, fromCache, err
	}
	ne, err := c.load(ctx, a)
	if err != nil {
		if ok && now.Sub(e.at) < c.staleMax {
			rec, err := e.result()
			return rec, fromOutage, err
		}
		le := &LookupError{Err: err}
		if ok && e.live && e.rec.UID != "" {
			le.Last, le.Known = e.rec, true
		}
		return ActorRecord{}, fromOutage, le
	}
	rec, err := ne.result()
	return rec, fromResolver, err
}

// load asks the resolver for a (one call per name at a time) and caches
// the answer.
func (c *UIDCache) load(ctx context.Context, a ActorRef) (uidEntry, error) {
	key := a.Key()
	v, err, _ := c.sf.Do(key, func() (any, error) {
		rec, live, err := c.r.ResolveActor(ctx, a.Atespace, a.Name)
		if err != nil {
			return nil, err
		}
		ne := uidEntry{rec: rec, live: live, at: c.now()}
		c.store(key, ne)
		return ne, nil
	})
	if err != nil {
		return uidEntry{}, err
	}
	return v.(uidEntry), nil
}

// defaultRefreshBudget is the refresh wait when the engine sets none.
const defaultRefreshBudget = 20 * time.Millisecond

// Refresh resolves a again past its cached entry and reports whether the
// registration changed (GAP-0237). It bounds what a flood of refused
// requests costs the leader and the requests (GAP-0243): one lookup per
// name at a time (its own singleflight, never forgotten while it runs), at
// most one started per refreshEvery, and a request waits refreshBudget for
// it. A name a refresh confirmed within refreshEvery, still cached as it
// was, is the same without a lookup.
func (c *UIDCache) Refresh(ctx context.Context, a ActorRef) RefreshResult {
	if c == nil || c.r == nil {
		return RefreshSame
	}
	key := a.Key()
	now := c.now()
	c.mu.Lock()
	prev, ok := c.m[key]
	st := c.refresh[key]
	if st == nil {
		if len(c.refresh) >= maxUIDEntries {
			for k, old := range c.refresh {
				if !old.running {
					delete(c.refresh, k)
				}
			}
		}
		st = &refreshState{}
		c.refresh[key] = st
	}
	switch {
	case st.running:
		// Join the lookup that is running.
	case !st.confirmed.IsZero() && now.Sub(st.confirmed) < c.refreshEvery && ok && prev.live == st.entry.live && prev.rec == st.entry.rec:
		c.mu.Unlock()
		return RefreshSame
	case !st.started.IsZero() && now.Sub(st.started) < c.refreshEvery:
		c.mu.Unlock()
		return RefreshUnconfirmed
	default:
		st.started, st.running = now, true
	}
	c.mu.Unlock()
	ch := c.sf.DoChan("refresh\x00"+key, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshFlightMax)
		defer cancel()
		rec, live, err := c.r.ResolveActor(fctx, a.Atespace, a.Name)
		c.mu.Lock()
		defer c.mu.Unlock()
		st.running = false
		if err != nil {
			return nil, err
		}
		ne := uidEntry{rec: rec, live: live, at: c.now()}
		st.confirmed, st.entry = ne.at, ne
		c.storeLocked(key, ne)
		return ne, nil
	})
	t := time.NewTimer(c.refreshBudget)
	defer t.Stop()
	select {
	case r := <-ch:
		if r.Err != nil {
			return RefreshUnconfirmed
		}
		ne := r.Val.(uidEntry)
		if !ok || ne.live != prev.live || ne.rec != prev.rec {
			return RefreshChanged
		}
		return RefreshSame
	case <-t.C:
		return RefreshUnconfirmed
	case <-ctx.Done():
		return RefreshUnconfirmed
	}
}

// LookupError is a registration lookup outage with no cached entry young
// enough to serve. Last is the name's last known registered incarnation,
// when Known: an incarnation's profile and attendance never change, so
// they still decide its policy and chain fail mode past the stale window
// (GAP-0188). Its UID is not used: the actor may have been recreated.
type LookupError struct {
	Err   error
	Last  ActorRecord
	Known bool
}

func (e *LookupError) Error() string { return e.Err.Error() }
func (e *LookupError) Unwrap() error { return e.Err }

func (e uidEntry) result() (ActorRecord, error) {
	if !e.live {
		return ActorRecord{}, ErrActorNotLive
	}
	return e.rec, nil
}

func (c *UIDCache) store(key string, e uidEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeLocked(key, e)
}

func (c *UIDCache) storeLocked(key string, e uidEntry) {
	if len(c.m) >= maxUIDEntries {
		for k, old := range c.m {
			if e.at.Sub(old.at) >= c.staleMax {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxUIDEntries {
			clear(c.m)
		}
	}
	c.m[key] = e
}

// Invalidate drops atespace/name: the leader answered its UID stale.
func (c *UIDCache) Invalidate(atespace, name string) {
	if c == nil {
		return
	}
	key := ActorRef{Atespace: atespace, Name: name}.Key()
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
	c.sf.Forget(key)
}
