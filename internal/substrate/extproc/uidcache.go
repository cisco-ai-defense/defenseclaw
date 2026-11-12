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

// ErrActorNotLive reports an actor the Control API says is not running.
var ErrActorNotLive = errors.New("extproc: actor is not live")

// UIDCache caches a UIDResolver per atespace/name. A fresh entry (younger
// than ttl) is used as is; when the resolver fails, an entry younger than
// staleMax still serves (§5.5). Lifecycle events call Invalidate so a
// recreated actor never inherits its predecessor's UID.
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
	uid  string
	live bool
	at   time.Time
}

// NewUIDCache wraps r. A nil r resolves nothing: every actor is live with
// an empty UID (the interim until A3's client lands).
func NewUIDCache(r UIDResolver, ttl, staleMax time.Duration) *UIDCache {
	return &UIDCache{r: r, ttl: ttl, staleMax: staleMax, now: time.Now, m: map[string]uidEntry{}}
}

// Resolve returns the live UID of a. ErrActorNotLive: the actor is gone or
// stopped. Any other error is an outage with no usable cached entry.
func (c *UIDCache) Resolve(ctx context.Context, a ActorRef) (string, error) {
	if c == nil || c.r == nil {
		return "", nil
	}
	key := a.Key()
	now := c.now()
	c.mu.Lock()
	e, ok := c.m[key]
	c.mu.Unlock()
	if ok && now.Sub(e.at) < c.ttl {
		return e.result()
	}
	v, err, _ := c.sf.Do(key, func() (any, error) {
		uid, live, err := c.r.ResolveUID(ctx, a.Atespace, a.Name)
		if err != nil {
			return nil, err
		}
		ne := uidEntry{uid: uid, live: live && uid != "", at: c.now()}
		c.store(key, ne)
		return ne, nil
	})
	if err != nil {
		if ok && now.Sub(e.at) < c.staleMax {
			return e.result()
		}
		return "", err
	}
	return v.(uidEntry).result()
}

func (e uidEntry) result() (string, error) {
	if !e.live {
		return "", ErrActorNotLive
	}
	return e.uid, nil
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

// Invalidate drops atespace/name: a lifecycle event (delete, recreate,
// fork, suspend) for the actor.
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
