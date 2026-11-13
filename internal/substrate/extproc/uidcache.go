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
	// refreshBudget bounds how long a request waits for a Refresh
	// (GAP-0243).
	refreshBudget time.Duration

	mu      sync.Mutex
	m       map[string]uidEntry
	refresh map[string]*refreshState
	sf      singleflight.Group
}

// refreshFlightMax bounds one refresh lookup. A request waits refreshBudget
// at most; the lookup goes on, so its answer fills the cache for the next.
const refreshFlightMax = 2 * time.Second

// refusalReuse is how long a refresh's confirmation keeps a policy-stage
// refusal without another lookup, so a flood of refused requests costs the
// leader about one lookup per name per refusalReuse (GAP-0243). Nothing that
// would allow reuses one.
//
// Known, bounded residual (GAP-0237, lead decision 2026-11-13): an actor
// deleted and created again under the same name within refusalReuse of
// such a confirmation may be refused under its predecessor's policy for at
// most refusalReuse (1 s). It is only ever a refusal, never an allow: a
// request that would be allowed is checked by the leader under the live
// incarnation. It is the bound a registration miss already has (uidMissTTL).
const refusalReuse = uidMissTTL

// refreshState is a name's last refresh: whether it is running, and what it
// confirmed when (GAP-0243).
type refreshState struct {
	running bool
	// started is when the running lookup started; confirmed and
	// confirmedStart when the last answered one answered and started.
	started        time.Time
	confirmed      time.Time
	confirmedStart time.Time
	entry          uidEntry
	// failed: the last lookup that ended got no answer from the leader
	// (a transport error or its own timeout).
	failed bool
}

// RefreshResult is what a Refresh learned.
type RefreshResult int

// Refresh results.
const (
	// RefreshSame: the registration is the cached one.
	RefreshSame RefreshResult = iota
	// RefreshChanged: another UID, profile or attendance, or deleted.
	RefreshChanged
	// RefreshUnconfirmed: the leader is reachable (its last lookup for
	// the name answered) but did not answer within this request's budget.
	RefreshUnconfirmed
	// RefreshUnreachable: the lookup got no answer from the leader (a
	// transport error or a timeout), now or on the name's last lookup while
	// this one waits: the leader can't be reached (GAP-0245).
	RefreshUnreachable
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
		refresh: map[string]*refreshState{}, refreshBudget: defaultRefreshBudget}
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
// registration changed (GAP-0237). It bounds what a flood costs the leader
// and the requests (GAP-0243): one lookup per name in flight (its own
// singleflight, never forgotten while it runs), which concurrent refreshes
// join, and a request waits refreshBudget for it.
//
// Anything that would allow, and a cached delete, needs a lookup made
// during this request (one started after since, the request's start): the
// one it starts or joins, or one that started and answered after since. Only
// a policy-stage refusal (refusal) may also stand on an earlier lookup: one
// that confirmed the cached registration within refusalReuse.
func (c *UIDCache) Refresh(ctx context.Context, a ActorRef, refusal bool, since time.Time) RefreshResult {
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
	cachedAsConfirmed := ok && !st.confirmed.IsZero() && prev.live == st.entry.live && prev.rec == st.entry.rec
	switch {
	case cachedAsConfirmed && st.confirmedStart.After(since):
		// A lookup made during this request confirmed the entry.
		c.mu.Unlock()
		return RefreshSame
	case refusal && cachedAsConfirmed && now.Sub(st.confirmed) < refusalReuse:
		c.mu.Unlock()
		return RefreshSame
	case st.running && (refusal || st.started.After(since)):
		// Join the running lookup: one in flight per name.
	case st.running:
		// The running lookup started before this request, and only one
		// runs per name.
		failed := st.failed
		c.mu.Unlock()
		if failed {
			return RefreshUnreachable
		}
		return RefreshUnconfirmed
	default:
		st.running, st.started = true, now
	}
	c.mu.Unlock()
	ch := c.sf.DoChan("refresh\x00"+key, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshFlightMax)
		defer cancel()
		rec, live, err := c.r.ResolveActor(fctx, a.Atespace, a.Name)
		c.mu.Lock()
		defer c.mu.Unlock()
		st.running = false
		st.failed = err != nil
		if err != nil {
			return nil, err
		}
		ne := uidEntry{rec: rec, live: live, at: c.now()}
		st.confirmed, st.confirmedStart, st.entry = ne.at, st.started, ne
		c.storeLocked(key, ne)
		return ne, nil
	})
	t := time.NewTimer(c.refreshBudget)
	defer t.Stop()
	unanswered := func() RefreshResult {
		c.mu.Lock()
		defer c.mu.Unlock()
		if st.failed {
			return RefreshUnreachable
		}
		return RefreshUnconfirmed
	}
	select {
	case r := <-ch:
		if r.Err != nil {
			return RefreshUnreachable
		}
		ne := r.Val.(uidEntry)
		if !ok || ne.live != prev.live || ne.rec != prev.rec {
			return RefreshChanged
		}
		return RefreshSame
	case <-t.C:
		return unanswered()
	case <-ctx.Done():
		return unanswered()
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
