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

	mu sync.Mutex
	m  map[string]uidEntry
	sf singleflight.Group
}

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
	return &UIDCache{r: r, ttl: ttl, staleMax: staleMax, now: time.Now, m: map[string]uidEntry{}}
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

// Refresh resolves a again past its cached entry and reports whether the
// registration changed: another UID, profile or attendance, or deleted
// (GAP-0237). An outage changes nothing.
func (c *UIDCache) Refresh(ctx context.Context, a ActorRef) bool {
	if c == nil || c.r == nil {
		return false
	}
	key := a.Key()
	c.mu.Lock()
	prev, ok := c.m[key]
	c.mu.Unlock()
	c.sf.Forget(key)
	ne, err := c.load(ctx, a)
	if err != nil {
		return false
	}
	return !ok || ne.live != prev.live || ne.rec != prev.rec
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
