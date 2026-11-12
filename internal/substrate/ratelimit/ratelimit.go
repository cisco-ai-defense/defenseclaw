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

// Package ratelimit is the fair-share limiter of the gateway's actor
// listener (PLAN E11): one actor cannot starve the others of its
// atespace, and one atespace cannot starve the cluster.
//
// Each request is charged to its actor UID and to its atespace. The actor
// bucket holds every actor to per_actor_rps (burst twice that) and a cap on
// concurrent requests, so a flood from one actor is refused at its own
// bucket and never reaches the shared one. The atespace bucket holds the
// atespace to per_atespace_rps; an actor is refused there only while it
// has already taken more than its fair share of the atespace (the
// atespace's rate divided by its active actors), so a quiet actor still
// gets through when the atespace is busy.
package ratelimit

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Defaults (PLAN §7.1 substrate.rate_limits).
const (
	DefaultPerActorRPS    = 20
	DefaultPerAtespaceRPS = 500
	// DefaultPerActorInFlight caps one actor's concurrent requests. Hooks
	// can wait on a judge or an ask, so time alone does not bound them.
	DefaultPerActorInFlight = 16
	// activeWindow is how long an actor counts as active in its atespace.
	activeWindow = 10 * time.Second
	// maxTracked bounds tracked actors; idle ones are dropped past it.
	maxTracked = 65536
)

// Scope names which budget refused a request (metric attribute).
type Scope string

const (
	ScopeActor    Scope = "actor"
	ScopeInFlight Scope = "actor_in_flight"
	ScopeAtespace Scope = "atespace"
)

// ErrLimited is returned with the scope that refused.
type ErrLimited struct{ Scope Scope }

func (e *ErrLimited) Error() string { return "rate limited (" + string(e.Scope) + ")" }

// IsLimited reports a limiter refusal and its scope.
func IsLimited(err error) (Scope, bool) {
	var e *ErrLimited
	if errors.As(err, &e) {
		return e.Scope, true
	}
	return "", false
}

// Config sets the budgets. Zero values take the defaults.
type Config struct {
	PerActorRPS      float64
	PerAtespaceRPS   float64
	PerActorInFlight int
	Now              func() time.Time
}

type actorState struct {
	lim      *rate.Limiter
	inFlight int
	last     time.Time
	// window counts this actor's admitted requests in its atespace's
	// current one-second window.
	window      int64
	windowStart time.Time
}

type atespaceState struct {
	lim    *rate.Limiter
	active map[string]time.Time // actor UID -> last request
}

// Limiter is safe for concurrent use.
type Limiter struct {
	cfg       Config
	mu        sync.Mutex
	actors    map[string]*actorState
	atespaces map[string]*atespaceState
}

// New returns a limiter.
func New(cfg Config) *Limiter {
	if cfg.PerActorRPS <= 0 {
		cfg.PerActorRPS = DefaultPerActorRPS
	}
	if cfg.PerAtespaceRPS <= 0 {
		cfg.PerAtespaceRPS = DefaultPerAtespaceRPS
	}
	if cfg.PerActorInFlight <= 0 {
		cfg.PerActorInFlight = DefaultPerActorInFlight
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Limiter{cfg: cfg, actors: map[string]*actorState{}, atespaces: map[string]*atespaceState{}}
}

// Acquire admits one request of actorUID in atespace, or returns an
// *ErrLimited. A nil error comes with a release func the caller must call
// when the request ends.
func (l *Limiter) Acquire(atespace, actorUID string) (func(), error) {
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.actor(actorUID, now)
	s := l.atespace(atespace)
	a.last = now
	s.active[actorUID] = now
	if a.inFlight >= l.cfg.PerActorInFlight {
		return nil, &ErrLimited{Scope: ScopeInFlight}
	}
	if !a.lim.AllowN(now, 1) {
		return nil, &ErrLimited{Scope: ScopeActor}
	}
	if now.Sub(a.windowStart) >= time.Second {
		a.window, a.windowStart = 0, now
	}
	if !s.lim.AllowN(now, 1) {
		// The atespace is over budget. An actor still within its fair
		// share of the atespace this second gets through; one past its
		// share is refused. The overshoot is bounded by one share per
		// active actor, so at most twice the atespace rate.
		share := l.cfg.PerAtespaceRPS / float64(l.activeCount(s, now))
		if float64(a.window) >= share {
			return nil, &ErrLimited{Scope: ScopeAtespace}
		}
	}
	a.window++
	a.inFlight++
	released := false
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if !released {
			released = true
			a.inFlight--
		}
	}, nil
}

func (l *Limiter) actor(uid string, now time.Time) *actorState {
	if a, ok := l.actors[uid]; ok {
		return a
	}
	if len(l.actors) >= maxTracked {
		l.prune(now)
	}
	a := &actorState{
		lim:         rate.NewLimiter(rate.Limit(l.cfg.PerActorRPS), int(2*l.cfg.PerActorRPS)),
		windowStart: now,
	}
	l.actors[uid] = a
	return a
}

func (l *Limiter) atespace(name string) *atespaceState {
	if s, ok := l.atespaces[name]; ok {
		return s
	}
	s := &atespaceState{
		lim:    rate.NewLimiter(rate.Limit(l.cfg.PerAtespaceRPS), int(l.cfg.PerAtespaceRPS)),
		active: map[string]time.Time{},
	}
	l.atespaces[name] = s
	return s
}

func (l *Limiter) activeCount(s *atespaceState, now time.Time) int {
	n := 0
	for uid, last := range s.active {
		if now.Sub(last) > activeWindow {
			delete(s.active, uid)
			continue
		}
		n++
	}
	if n == 0 {
		return 1
	}
	return n
}

// prune drops idle actors (no request in flight, none for a minute).
func (l *Limiter) prune(now time.Time) {
	for uid, a := range l.actors {
		if a.inFlight == 0 && now.Sub(a.last) > time.Minute {
			delete(l.actors, uid)
		}
	}
}

// Forget drops an actor's state (deleted actor).
func (l *Limiter) Forget(atespace, actorUID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if a, ok := l.actors[actorUID]; ok && a.inFlight == 0 {
		delete(l.actors, actorUID)
	}
	if s, ok := l.atespaces[atespace]; ok {
		delete(s.active, actorUID)
	}
}
