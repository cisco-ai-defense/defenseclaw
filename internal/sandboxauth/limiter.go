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

package sandboxauth

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	// ErrRateLimited is returned when a binding exhausted its token bucket.
	ErrRateLimited = errors.New("sandboxauth: sandbox request rate exceeded")
	// ErrTooManyInFlight is returned when a binding has too many requests
	// open at once.
	ErrTooManyInFlight = errors.New("sandboxauth: too many concurrent sandbox requests")
)

// LimiterConfig holds the per-binding defaults. A binding's RateLimit
// overrides the hook-bucket rate, burst and concurrency.
//
// Hook-class requests and OTLP uploads have separate buckets and separate
// concurrency slots: telemetry gates nothing, so slow or bulky uploads must
// never hold the capacity that PreToolUse and friends need to answer.
type LimiterConfig struct {
	// HookRPS and HookBurst bound hook, notify and inspect calls. A busy
	// agent fires a few hooks per tool call, so the defaults leave room for
	// parallel tool batches while stopping a forging loop.
	HookRPS   float64
	HookBurst int
	// OTLPRPS and OTLPBurst bound telemetry batches in their own bucket so
	// an exporter flush can never starve the hooks that gate tool calls.
	OTLPRPS   float64
	OTLPBurst int
	// MaxInFlight caps concurrent hook, notify and inspect requests per
	// binding.
	MaxInFlight int
	// OTLPMaxInFlight caps concurrent OTLP uploads per binding. Each open
	// upload may pin a whole request body in memory, so this is small.
	OTLPMaxInFlight int
	// OTLPMaxInFlightTotal caps concurrent OTLP uploads across every
	// binding, so the memory sandbox telemetry can pin does not grow with the
	// number of sandboxes.
	OTLPMaxInFlightTotal int
	// IdleTTL drops the state of bindings that have been silent this long.
	IdleTTL time.Duration
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// DefaultLimiterConfig returns the production defaults.
func DefaultLimiterConfig() LimiterConfig {
	return LimiterConfig{
		HookRPS:              25,
		HookBurst:            100,
		OTLPRPS:              10,
		OTLPBurst:            50,
		MaxInFlight:          32,
		OTLPMaxInFlight:      4,
		OTLPMaxInFlightTotal: 16,
		IdleTTL:              10 * time.Minute,
	}
}

// Limiter enforces per-binding request budgets. It is safe for concurrent
// use and holds no goroutines; idle state is swept lazily.
type Limiter struct {
	cfg LimiterConfig

	mu        sync.Mutex
	bindings  map[string]*limiterEntry
	otlpTotal int
	lastSweep time.Time
}

type limiterEntry struct {
	hook  *rate.Limiter
	otlp  *rate.Limiter
	slots *limiterSlots
	maxIn int
	// override is the RateLimit the buckets were built from; a changed
	// binding override rebuilds them.
	override RateLimit
	lastSeen time.Time
}

// limiterSlots is shared by every generation of a binding's entry so a
// release always returns its slot to the counter it was taken from.
type limiterSlots struct {
	hook int
	otlp int
}

// NewLimiter builds a limiter; zero fields in cfg take the defaults.
func NewLimiter(cfg LimiterConfig) *Limiter {
	def := DefaultLimiterConfig()
	if cfg.HookRPS <= 0 {
		cfg.HookRPS = def.HookRPS
	}
	if cfg.HookBurst <= 0 {
		cfg.HookBurst = def.HookBurst
	}
	if cfg.OTLPRPS <= 0 {
		cfg.OTLPRPS = def.OTLPRPS
	}
	if cfg.OTLPBurst <= 0 {
		cfg.OTLPBurst = def.OTLPBurst
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = def.MaxInFlight
	}
	if cfg.OTLPMaxInFlight <= 0 {
		cfg.OTLPMaxInFlight = def.OTLPMaxInFlight
	}
	if cfg.OTLPMaxInFlightTotal <= 0 {
		cfg.OTLPMaxInFlightTotal = def.OTLPMaxInFlightTotal
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = def.IdleTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Limiter{cfg: cfg, bindings: make(map[string]*limiterEntry)}
}

// Acquire admits one request for b on route. On success the caller must
// invoke release exactly once when the request completes; release is
// idempotent.
func (l *Limiter) Acquire(b Binding, route Route) (release func(), err error) {
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	entry := l.entryLocked(b, now)
	entry.lastSeen = now
	otlp := route == RouteOTLP
	bucket := entry.hook
	if otlp {
		if entry.slots.otlp >= l.cfg.OTLPMaxInFlight || l.otlpTotal >= l.cfg.OTLPMaxInFlightTotal {
			return nil, ErrTooManyInFlight
		}
		bucket = entry.otlp
	} else if entry.slots.hook >= entry.maxIn {
		return nil, ErrTooManyInFlight
	}
	if !bucket.AllowN(now, 1) {
		return nil, ErrRateLimited
	}
	slots := entry.slots
	if otlp {
		slots.otlp++
		l.otlpTotal++
	} else {
		slots.hook++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if otlp {
				if slots.otlp > 0 {
					slots.otlp--
				}
				if l.otlpTotal > 0 {
					l.otlpTotal--
				}
			} else if slots.hook > 0 {
				slots.hook--
			}
			if current, ok := l.bindings[b.ID]; ok && current.slots == slots {
				current.lastSeen = l.cfg.Now()
			}
			l.mu.Unlock()
		})
	}, nil
}

// Forget drops a binding's state, e.g. after revoke.
func (l *Limiter) Forget(bindingID string) {
	l.mu.Lock()
	delete(l.bindings, bindingID)
	l.mu.Unlock()
}

func (l *Limiter) entryLocked(b Binding, now time.Time) *limiterEntry {
	entry, ok := l.bindings[b.ID]
	if ok && entry.override == b.RateLimit {
		return entry
	}
	hookRPS, hookBurst, maxIn := l.cfg.HookRPS, l.cfg.HookBurst, l.cfg.MaxInFlight
	if b.RateLimit.RequestsPerSecond > 0 {
		hookRPS = b.RateLimit.RequestsPerSecond
	}
	if b.RateLimit.Burst > 0 {
		hookBurst = b.RateLimit.Burst
	}
	if b.RateLimit.MaxInFlight > 0 {
		maxIn = b.RateLimit.MaxInFlight
	}
	next := &limiterEntry{
		hook:     rate.NewLimiter(rate.Limit(hookRPS), hookBurst),
		otlp:     rate.NewLimiter(rate.Limit(l.cfg.OTLPRPS), l.cfg.OTLPBurst),
		slots:    &limiterSlots{},
		maxIn:    maxIn,
		override: b.RateLimit,
		lastSeen: now,
	}
	if ok {
		// A changed override keeps the requests already admitted so the
		// concurrency cap cannot be reset by an Update.
		next.slots = entry.slots
	}
	l.bindings[b.ID] = next
	return next
}

func (l *Limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	for id, entry := range l.bindings {
		if entry.slots.hook == 0 && entry.slots.otlp == 0 && now.Sub(entry.lastSeen) >= l.cfg.IdleTTL {
			delete(l.bindings, id)
		}
	}
}
