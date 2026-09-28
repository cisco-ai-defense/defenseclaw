// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Per-caller limits on a standalone gateway.
//
// Every standalone caller reaches the shared gateway through the hook socket,
// or through the TCP API with its own per-user credential, and both look
// like loopback, which the per-IP limiter exempts. Without a per-caller
// bound one account could take the gateway's capacity and push other
// accounts' hooks past their deadline, and those hooks then deny. Each
// verified caller identity (uid or SID) therefore gets its own token bucket
// and in-flight cap. A caller over either gets an immediate 429 with a
// stable reason; other callers are not affected.
const (
	// hookCallerRate and hookCallerBurst are one caller's sustained and
	// burst request budget. An agent sends a few requests per tool call, so
	// this leaves room for many parallel sessions of one user.
	hookCallerRate  = 60
	hookCallerBurst = 120
	// hookCallerInFlight bounds one caller's concurrent requests.
	hookCallerInFlight = 32
	// hookCallerIdle is how long an idle caller's budget is kept.
	hookCallerIdle = 5 * time.Minute
	// hookCallerLogInterval paces the refusal log line per caller.
	hookCallerLogInterval = 10 * time.Second

	managedHookReasonRateLimited = "enterprise_managed_rate_limited"
)

type hookCallerLimiter struct {
	mu        sync.Mutex
	callers   map[string]*hookCallerBudget
	lastSweep time.Time
	// Test overrides; zero values select the defaults above.
	now                   func() time.Time
	rate, burst, inFlight int
}

type hookCallerBudget struct {
	limiter  *rate.Limiter
	inFlight int
	lastSeen time.Time
	lastLog  time.Time
}

func (l *hookCallerLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *hookCallerLimiter) limits() (rps, burst, inFlight int) {
	rps, burst, inFlight = hookCallerRate, hookCallerBurst, hookCallerInFlight
	if l.rate > 0 {
		rps = l.rate
	}
	if l.burst > 0 {
		burst = l.burst
	}
	if l.inFlight > 0 {
		inFlight = l.inFlight
	}
	return rps, burst, inFlight
}

// acquire admits one request of caller. When it returns true, release must
// be called once the request is done. When it returns false, logNow reports
// whether this refusal should be logged (at most once per interval).
func (l *hookCallerLimiter) acquire(caller string) (release func(), ok, logNow bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	if l.callers == nil {
		l.callers = make(map[string]*hookCallerBudget)
	}
	if now.Sub(l.lastSweep) > time.Minute {
		l.lastSweep = now
		for key, budget := range l.callers {
			if budget.inFlight == 0 && now.Sub(budget.lastSeen) > hookCallerIdle {
				delete(l.callers, key)
			}
		}
	}
	rps, burst, inFlight := l.limits()
	budget := l.callers[caller]
	if budget == nil {
		budget = &hookCallerBudget{limiter: rate.NewLimiter(rate.Limit(rps), burst)}
		l.callers[caller] = budget
	}
	budget.lastSeen = now
	if budget.inFlight >= inFlight || !budget.limiter.AllowN(now, 1) {
		logNow = now.Sub(budget.lastLog) >= hookCallerLogInterval
		if logNow {
			budget.lastLog = now
		}
		return nil, false, logNow
	}
	budget.inFlight++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			budget.inFlight--
			budget.lastSeen = l.clock()
			l.mu.Unlock()
		})
	}, true, false
}

// hookCallerTelemetryBudget suffixes the budget key of a caller's OTLP
// export. A burst of telemetry batches from the user's agents must not use
// up the budget that user's hooks need: a refused hook request denies the
// tool call, while an exporter retries.
const hookCallerTelemetryBudget = "|otlp"

// hookCallerBudgetKey is the limiter key for one request of identity: OTLP
// ingest paths get their own budget, every other route shares the caller's.
func hookCallerBudgetKey(identity, path string) string {
	if isUnscopedOTLPEndpointPath(path) {
		return identity + hookCallerTelemetryBudget
	}
	if _, _, ok := parseOTLPPathToken(path); ok {
		return identity + hookCallerTelemetryBudget
	}
	return identity
}

// admitHookCaller applies the per-caller limits to one request for path. It
// returns the release function to defer, or nil after answering 429.
func (a *APIServer) admitHookCaller(w http.ResponseWriter, identity, route, path string) func() {
	release, ok, logNow := a.hookCallerLimits.acquire(hookCallerBudgetKey(identity, path))
	if ok {
		return release
	}
	if logNow {
		fmt.Fprintf(os.Stderr,
			"[sidecar-api] hook caller rate limited identity=%s route=%s reason=%s\n",
			identity, route, managedHookReasonRateLimited)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "rate_limited",
		"reason":  managedHookReasonRateLimited,
		"message": "DefenseClaw is limiting this account's hook requests; retry shortly",
	})
	return nil
}

// keyedMutex serializes work per key; different keys never wait on each
// other.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedMutexEntry
}

type keyedMutexEntry struct {
	mu   sync.Mutex
	refs int
}

func (k *keyedMutex) lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = make(map[string]*keyedMutexEntry)
	}
	entry := k.locks[key]
	if entry == nil {
		entry = &keyedMutexEntry{}
		k.locks[key] = entry
	}
	entry.refs++
	k.mu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		k.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
