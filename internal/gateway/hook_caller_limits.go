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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
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
//
// The caller cap alone does not bound the host: many accounts can still
// hold more work than the gateway can finish within hook deadlines
// (600 simultaneous hooks took about 25 s on 8 processors, every client had
// given up by then, and the gateway still evaluated and audited each one).
// The gateway therefore also bounds the requests it holds at once across all
// callers, in proportion to its processors. A request over the bound gets the
// same immediate 429, with its own reason, instead of a timeout, and the
// requests inside the bound finish in time.
//
// Within its in-flight cap a caller also runs at most half as many requests
// at a time as the gateway has processors (at least one); the rest wait for
// one of the caller's own run slots. A flood inside its rate budget can still
// need more CPU than a small host gives the gateway, and the CPU is shared
// among all running requests, so another caller's hook shared it with up to
// 32 of the flood's and could take many times longer. With the cap, the
// other callers keep at least half of the processors. A request
// gives its slot up while it waits on a remote scanner (yieldHookRunSlot),
// which uses no gateway CPU, so a caller's parallel tool calls do not queue
// behind Cisco AI Defense or LLM judge round trips.
const (
	// hookCallerRate and hookCallerBurst are one caller's sustained and
	// burst request budget. An agent sends a few requests per tool call, so
	// this leaves room for many parallel sessions of one user.
	hookCallerRate  = 60
	hookCallerBurst = 120
	// hookCallerInFlight bounds one caller's concurrent requests, running
	// or waiting.
	hookCallerInFlight = 32
	// hookGlobalInFlightPerProc and hookGlobalInFlightMin bound the requests
	// the gateway holds at once for all callers together: 16 per processor,
	// at least 32. A processor serves about 3 hooks a second, so a full
	// gateway answers its last admitted request in about 5 s, inside the
	// shortest hook deadline (10 s).
	hookGlobalInFlightPerProc = 16
	hookGlobalInFlightMin     = 32
	// hookCallerIdle is how long an idle caller's budget is kept.
	hookCallerIdle = 5 * time.Minute
	// hookCallerLogInterval paces the refusal log line per caller.
	hookCallerLogInterval = 10 * time.Second

	managedHookReasonRateLimited = "enterprise_managed_rate_limited"
	managedHookReasonOverloaded  = "enterprise_managed_overloaded"
)

type hookCallerLimiter struct {
	mu        sync.Mutex
	callers   map[string]*hookCallerBudget
	lastSweep time.Time
	// total is the number of admitted requests that have not finished, for
	// all callers; lastOverloadLog paces the log line of a full gateway.
	total           int
	lastOverloadLog time.Time
	// Test overrides; zero values select the defaults above.
	now                                            func() time.Time
	rate, burst, inFlight, running, globalInFlight int
}

type hookCallerBudget struct {
	limiter  *rate.Limiter
	inFlight int
	// running holds one token per request of this caller that is running.
	running  chan struct{}
	lastSeen time.Time
	lastLog  time.Time
}

func (l *hookCallerLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// globalLimit is the most requests held at once for all callers.
func (l *hookCallerLimiter) globalLimit() int {
	if l.globalInFlight > 0 {
		return l.globalInFlight
	}
	return max(hookGlobalInFlightMin, hookGlobalInFlightPerProc*runtime.GOMAXPROCS(0))
}

func (l *hookCallerLimiter) limits() (rps, burst, inFlight, running int) {
	rps, burst, inFlight = hookCallerRate, hookCallerBurst, hookCallerInFlight
	running = max(1, runtime.GOMAXPROCS(0)/2)
	if l.rate > 0 {
		rps = l.rate
	}
	if l.burst > 0 {
		burst = l.burst
	}
	if l.inFlight > 0 {
		inFlight = l.inFlight
	}
	if l.running > 0 {
		running = l.running
	}
	return rps, burst, inFlight, running
}

// acquire admits one request of caller. When it returns an empty refusal, the
// request may run once it holds a token of run, and release must be called
// once the request is done. Otherwise refusal is the reason to answer 429
// with, and logNow reports whether this refusal should be logged (at most
// once per interval).
func (l *hookCallerLimiter) acquire(caller string) (release func(), run chan struct{}, refusal string, logNow bool) {
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
	// Telemetry batches are not hooks: a refused hook denies the tool call
	// while an exporter retries, so they stay out of the gateway-wide bound
	// (they keep their own per-caller budget).
	counted := !strings.HasSuffix(caller, hookCallerTelemetryBudget)
	if counted && l.total >= l.globalLimit() {
		logNow = now.Sub(l.lastOverloadLog) >= hookCallerLogInterval
		if logNow {
			l.lastOverloadLog = now
		}
		return nil, nil, managedHookReasonOverloaded, logNow
	}
	rps, burst, inFlight, running := l.limits()
	if counted {
		// Keep capacity for at least three other callers even when one
		// caller fills every request it may hold while queued.
		inFlight = min(inFlight, max(1, l.globalLimit()/4))
	}
	budget := l.callers[caller]
	if budget == nil {
		budget = &hookCallerBudget{limiter: rate.NewLimiter(rate.Limit(rps), burst), running: make(chan struct{}, running)}
		l.callers[caller] = budget
	}
	budget.lastSeen = now
	if budget.inFlight >= inFlight || !budget.limiter.AllowN(now, 1) {
		logNow = now.Sub(budget.lastLog) >= hookCallerLogInterval
		if logNow {
			budget.lastLog = now
		}
		return nil, nil, managedHookReasonRateLimited, logNow
	}
	budget.inFlight++
	if counted {
		l.total++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			budget.inFlight--
			if counted {
				l.total--
			}
			budget.lastSeen = l.clock()
			l.mu.Unlock()
		})
	}, budget.running, "", false
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

// admitHookCaller applies the per-caller limits to one request for path and
// waits for one of the caller's run slots. It returns the request to serve,
// which carries the slot, and the release function to defer; the release
// function is nil after answering 429 or when the client went away while it
// waited.
func (a *APIServer) admitHookCaller(w http.ResponseWriter, r *http.Request, identity, route string) (*http.Request, func()) {
	release, run, refusal, logNow := a.hookCallerLimits.acquire(hookCallerBudgetKey(identity, r.URL.Path))
	if refusal == "" {
		if r.Context().Err() != nil {
			// The client left before it had a slot: nothing to serve.
			release()
			return r, nil
		}
		select {
		case run <- struct{}{}:
			slot := &hookRunSlot{run: run, held: true}
			return r.WithContext(context.WithValue(r.Context(), hookRunSlotContextKey{}, slot)), func() {
				slot.end()
				release()
			}
		case <-r.Context().Done():
			release()
			return r, nil
		}
	}
	if logNow {
		fmt.Fprintf(os.Stderr,
			"[sidecar-api] hook caller refused identity=%s route=%s reason=%s\n",
			identity, route, refusal)
	}
	message := "DefenseClaw is limiting the hook requests of this account; retry shortly"
	if refusal == managedHookReasonOverloaded {
		message = "DefenseClaw is handling as many hook requests as it can; retry shortly"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "rate_limited",
		"reason":  refusal,
		"message": message,
	})
	return r, nil
}

// hookRunSlot is the caller's run slot one admitted request holds.
type hookRunSlot struct {
	run  chan struct{}
	mu   sync.Mutex
	held bool // the request holds one token of run
	done bool // the request has ended
}

type hookRunSlotContextKey struct{}

// yieldHookRunSlot gives up the run slot of the request on ctx while it waits
// on a remote scanner (Cisco AI Defense, the LLM judge). The wait uses no
// gateway CPU, and with one slot a caller's second judged tool call would
// otherwise wait out the first call's round trip before its own and could
// pass the hook's deadline. resume takes a slot back before the request goes
// on, and gives up when the request has ended.
func yieldHookRunSlot(ctx context.Context) (resume func()) {
	slot, _ := ctx.Value(hookRunSlotContextKey{}).(*hookRunSlot)
	if slot == nil {
		return func() {}
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if !slot.held {
		return func() {}
	}
	<-slot.run
	slot.held = false
	return func() {
		select {
		case slot.run <- struct{}{}:
		case <-ctx.Done():
			return
		}
		slot.mu.Lock()
		defer slot.mu.Unlock()
		if slot.done {
			// The request ended while this wait took the slot back.
			<-slot.run
			return
		}
		slot.held = true
	}
}

// end gives back the slot when the request is done.
func (s *hookRunSlot) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	if s.held {
		s.held = false
		<-s.run
	}
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
