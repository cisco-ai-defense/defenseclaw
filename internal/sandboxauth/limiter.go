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
//
// A managed sandbox hook confirms each allowed tool answer with a second post,
// its delivery receipt (AcquireReceipt). Receipts have a bucket and slots of
// their own, the size of the hook bucket's, so a tool call spends the hook
// rate once: with one shared bucket a run of parallel calls refused the
// receipt of an answer already given, and the hook denied it closed, at half
// the documented rate (rel-1-0-6 GAP-0490).
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

const (
	// DefaultHookRPS and DefaultHookBurst are the per-binding hook (and
	// receipt) rate: 25 a second with a burst of 100.
	DefaultHookRPS   = 25
	DefaultHookBurst = 100
	// MaxRequestLifetimeSeconds is the longest one admitted request stays
	// open: the gateway receipt window (15 s), which is longer than the
	// longest rendered hook attempt (12 s). The gateway pins both values to
	// this one in a test.
	MaxRequestLifetimeSeconds = 15
	// DefaultMaxInFlight bounds the hook, notify and inspect requests one
	// binding holds open. It is the most the rate limit can admit while the
	// first of them is still open: the whole burst, plus the rate for the
	// longest request lifetime (100 + 25 x 15 = 475). Below that bound a
	// request is refused for its rate only, never for how long the requests
	// before it take (rel-1-0-6 GAP-0490: 32, then 128, refused a valid
	// call that the rate admitted). Each pending request holds only its
	// bounded body, and the account in-flight caps stay in force.
	DefaultMaxInFlight = DefaultHookBurst + DefaultHookRPS*MaxRequestLifetimeSeconds
)

// DefaultLimiterConfig returns the production defaults.
func DefaultLimiterConfig() LimiterConfig {
	return LimiterConfig{
		HookRPS:              DefaultHookRPS,
		HookBurst:            DefaultHookBurst,
		OTLPRPS:              10,
		OTLPBurst:            50,
		MaxInFlight:          DefaultMaxInFlight,
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
	hook    *rate.Limiter
	otlp    *rate.Limiter
	receipt *rate.Limiter
	slots   *limiterSlots
	maxIn   int
	// override is the RateLimit the buckets were built from; a changed
	// binding override rebuilds them.
	override RateLimit
	lastSeen time.Time
}

// limiterSlots is shared by every generation of a binding's entry so a
// release always returns its slot to the counter it was taken from.
type limiterSlots struct {
	hook    int
	otlp    int
	receipt int
	pending int
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
	if route == RouteOTLP {
		return l.acquire(b, limiterOTLP)
	}
	return l.acquire(b, limiterHook)
}

// AcquireReceipt admits one delivery receipt acknowledgement for b, from
// the receipt bucket and slots (see LimiterConfig). A forged acknowledgement
// spends only that bucket and still meets the binding's concurrency cap; the
// gateway checks the receipt itself.
func (l *Limiter) AcquireReceipt(b Binding) (release func(), err error) {
	return l.acquire(b, limiterReceipt)
}

// AcquirePendingHook holds a bounded slot while an unmarked hook body is
// read. Its hook or receipt rate budget is charged after classification.
func (l *Limiter) AcquirePendingHook(b Binding) (release func(), err error) {
	return l.acquire(b, limiterPendingHook)
}

// ChargeHookBody spends only the classified rate token. The pending request
// already owns the in-flight slot until its handler finishes.
func (l *Limiter) ChargeHookBody(b Binding, receipt bool) error {
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	entry := l.entryLocked(b, now)
	entry.lastSeen = now
	bucket := entry.hook
	if receipt {
		bucket = entry.receipt
	}
	if !bucket.AllowN(now, 1) {
		return ErrRateLimited
	}
	return nil
}

// limiterClass is the bucket and the slots one request takes.
type limiterClass int

const (
	limiterHook limiterClass = iota
	limiterOTLP
	limiterReceipt
	limiterPendingHook
)

func (l *Limiter) acquire(b Binding, class limiterClass) (release func(), err error) {
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	entry := l.entryLocked(b, now)
	entry.lastSeen = now
	slots := entry.slots
	bucket, held := entry.hook, &slots.hook
	switch class {
	case limiterOTLP:
		if slots.otlp >= l.cfg.OTLPMaxInFlight || l.otlpTotal >= l.cfg.OTLPMaxInFlightTotal {
			return nil, ErrTooManyInFlight
		}
		bucket, held = entry.otlp, &slots.otlp
	case limiterReceipt:
		bucket, held = entry.receipt, &slots.receipt
	case limiterPendingHook:
		held = &slots.pending
	}
	if class != limiterOTLP && *held >= entry.maxIn {
		return nil, ErrTooManyInFlight
	}
	if class != limiterPendingHook && !bucket.AllowN(now, 1) {
		return nil, ErrRateLimited
	}
	*held++
	if class == limiterOTLP {
		l.otlpTotal++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if *held > 0 {
				*held--
			}
			if class == limiterOTLP && l.otlpTotal > 0 {
				l.otlpTotal--
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
		receipt:  rate.NewLimiter(rate.Limit(hookRPS), hookBurst),
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
		if entry.slots.hook == 0 && entry.slots.otlp == 0 && entry.slots.receipt == 0 && entry.slots.pending == 0 && now.Sub(entry.lastSeen) >= l.cfg.IdleTTL {
			delete(l.bindings, id)
		}
	}
}
