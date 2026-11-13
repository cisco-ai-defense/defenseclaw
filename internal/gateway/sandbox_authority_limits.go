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
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// Per-class budgets of the managed sandbox routes on the hook socket.
//
// Each class has its own limiter key per peer uid (hookCallerBudgetKey), so
// a flood of relayed hooks from one sandbox never refuses the same user's
// host hooks or a new sandbox's create, and a burst of daemon events never
// takes the budget a relayed hook needs. The host key (<uid>, 120/s burst
// 240, 64 in flight) and the OTLP key (<uid>|otlp) are unchanged; the
// gateway-wide in-flight cap stays shared by every key.
//
// Sizing: a daemon's per-binding limiter (sandboxauth.DefaultLimiterConfig,
// 25/s burst 100) is the first limit one sandbox meets. The account budget
// is what the managed gateway answers inside the hook's 3.5 s window: every
// relayed call (a proposal and its delivery receipt) makes about two dozen
// audit writes under one SQLite write lock, and four sandboxes at 10 calls a
// second answer in about a second on the shared build box (p95 under 1 s),
// while 96 calls a second did not answer in time in half the runs
// (rel-1-0-6 GAP-0490). The budget was therefore 40 calls a second with a
// burst of 100; since one call no longer waits for a dozen commits one
// after the other (#1384) it is 100 calls a second with a burst of 200
// (rel-1-0-6 GAP-0770), and a call past it
// is refused at once with a 429 and a message that names the budget, instead
// of waiting past the hook's window for an answer that comes too late. The
// delivery receipt that confirms an allowed answer is a second post on the
// hook route: sandbox-receipt, the same rate and burst, counts those
// (hookCallerAdmissionKey), so a receipt never spends the evaluation rate.
// There is no four-binding limit: one account can use its budget across
// more bindings, each with its own in-flight limit
// (sandboxauth.DefaultMaxInFlight). The shared hook and receipt admission
// therefore holds the most calls the account bucket can admit during each
// managed request's actual lifetime, including its initial burst. Raising
// the budget toward 100/s needs less work under the audit write lock
// (the 1.0.10 performance rows). The 60 s policy/current poll is one call a
// minute per live registration.
const (
	sandboxBudgetHook    = "sandbox-hook"
	sandboxBudgetReceipt = "sandbox-receipt"
	sandboxBudgetPending = "sandbox-pending"
	sandboxBudgetPolicy  = "sandbox-policy"
	sandboxBudgetEvents  = "sandbox-events"
	// The account budget is 100 calls a second with a burst of 200
	// (rel-1-0-6 GAP-0770): one hook call no longer waits for the commits of
	// a dozen writes one after the other (#1384), so the managed gateway
	// answers four sandboxes at 25 calls a second inside the hook window.
	sandboxUserHookRate  = 100
	sandboxUserHookBurst = 200
)

var sandboxUserHookInFlight, sandboxUserReceiptInFlight = managedSandboxInFlightLimits()

// sandboxInFlightWindow sizes the per-uid in-flight bounds: the hook answer
// window (3.5 s) and a little slack. A relayed call held past it no longer
// gets an answer its sandbox hook can use, so the bound holds what the
// account bucket admits over one answer window, plus its burst: 560 at
// 100/s burst 200 (S8 DESIGN section 9, major 5). Sizing it by the 12 s
// attempt and 15 s receipt lifetimes, as the 40/s budget did, would let a
// stalled store pin 1400 and 1700 requests per account (S8 lead review
// P2-1).
const sandboxInFlightWindow = 3600 * time.Millisecond

// managedSandboxInFlightLimits sizes the hook and the receipt in-flight
// bounds (separate HTTP requests with separate account rate buckets) by the
// answer window.
func managedSandboxInFlightLimits() (hook, receipt int) {
	capacity := sandboxUserHookBurst + int((time.Duration(sandboxUserHookRate)*sandboxInFlightWindow+time.Second-1)/time.Second)
	return capacity, capacity
}

// sandboxBudgetLimit is one class's rate, burst and in-flight bound per
// uid.
type sandboxBudgetLimit struct {
	Rate, Burst, InFlight int
}

// sandboxBudgetLimits is the per-class table; tests replace entries.
var sandboxBudgetLimits = map[string]sandboxBudgetLimit{
	sandboxBudgetHook:    {Rate: sandboxUserHookRate, Burst: sandboxUserHookBurst, InFlight: sandboxUserHookInFlight},
	sandboxBudgetReceipt: {Rate: sandboxUserHookRate, Burst: sandboxUserHookBurst, InFlight: sandboxUserReceiptInFlight},
	sandboxBudgetPolicy:  {Rate: 10, Burst: 20, InFlight: 8},
	// The daemon posts its lifecycle and egress records every 2 s, one batch
	// per sandbox (daemonRelayTelemetry), and stops a pass at its first
	// 429, besides its other records. What a batch costs is bounded by the
	// records budget (sandboxRecordBudget), not by this rate.
	sandboxBudgetEvents: {Rate: 2, Burst: 8, InFlight: 2},
}

// The sandbox telemetry records one account's daemon may post: the request
// budget above counts batches, and a batch holds up to
// sandboxrelay.MaxTelemetryBatchRecords records, so this budget counts the
// records themselves. 64 a second is one full batch per 2 s flush; the burst
// is two batches, for a backlog after the gateway was out of reach.
const (
	sandboxTelemetryRecordRate  = 64
	sandboxTelemetryRecordBurst = 2 * sandboxrelay.MaxTelemetryBatchRecords
	// sandboxRecordBudgetSweepAt is the number of accounts tracked at which
	// the buckets idle longer than sandboxRecordBudgetIdle (full again) go.
	sandboxRecordBudgetSweepAt = 1024
	sandboxRecordBudgetIdle    = time.Minute
)

// The records of the daemon's other events (foreign sandboxes, rules and
// containers, settings drift, refused access, refused runs) have a sibling
// budget, counted by the record each event makes (sandboxEventRows: a
// foreign_rule event is one record per rule), since one request may carry
// MaxEventBatchRecords events of up to sandboxEventRulesMax rules each. The
// daemon keeps at most MaxUnregisteredEventRecords of these events, so its
// largest batch is the burst, and a batch past it is refused outright.
const (
	sandboxEventRecordRate  = 64
	sandboxEventRecordBurst = sandboxrelay.MaxUnregisteredEventRecords * sandboxEventRulesMax
)

// sandboxRecordBudget is a per-account records budget: perSecond records a
// second with a burst of burst, the sandbox telemetry records budget
// (sandboxTelemetryRecordRate, sandboxTelemetryRecordBurst) when they are
// zero. The zero value is ready.
type sandboxRecordBudget struct {
	perSecond, burst int

	mu    sync.Mutex
	byUID map[int]*sandboxRecordBucket
}

// limits is b's rate and burst.
func (b *sandboxRecordBudget) limits() (int, int) {
	if b.perSecond > 0 && b.burst > 0 {
		return b.perSecond, b.burst
	}
	return sandboxTelemetryRecordRate, sandboxTelemetryRecordBurst
}

type sandboxRecordBucket struct {
	limiter *rate.Limiter
	seen    time.Time
}

// take spends n records of uid's budget at now. When fewer are left it
// spends none and returns how long until n are.
func (b *sandboxRecordBudget) take(uid, n int, now time.Time) (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.byUID == nil {
		b.byUID = map[int]*sandboxRecordBucket{}
	}
	if len(b.byUID) >= sandboxRecordBudgetSweepAt {
		for id, bucket := range b.byUID {
			if now.Sub(bucket.seen) > sandboxRecordBudgetIdle {
				delete(b.byUID, id)
			}
		}
	}
	perSecond, burst := b.limits()
	bucket, ok := b.byUID[uid]
	if !ok {
		bucket = &sandboxRecordBucket{limiter: rate.NewLimiter(rate.Limit(perSecond), burst)}
		b.byUID[uid] = bucket
	}
	bucket.seen = now
	if bucket.limiter.AllowN(now, n) {
		return 0, true
	}
	short := float64(n) - bucket.limiter.TokensAt(now)
	return time.Duration(math.Ceil(short / float64(perSecond) * float64(time.Second))), false
}

// sandboxBudgetClass is the budget class of a sandbox route path, "" for
// every other path (and for the sandbox OTLP routes, which share the
// caller's OTLP budget).
func sandboxBudgetClass(path string) string {
	if !strings.HasPrefix(path, sandboxrelay.PathPrefix) {
		return ""
	}
	switch {
	case strings.HasPrefix(path, sandboxrelay.PathHookPrefix),
		strings.HasPrefix(path, sandboxrelay.PathNotifyPrefix),
		strings.HasPrefix(path, sandboxrelay.PathInspectPrefix):
		return sandboxBudgetHook
	case strings.HasPrefix(path, sandboxrelay.PathOTLPPrefix):
		return ""
	case path == sandboxrelay.PathEvents:
		return sandboxBudgetEvents
	}
	// settings, policy/*, registrations/*, decisions, and any other path
	// under the prefix (which the mux answers 404).
	return sandboxBudgetPolicy
}

// sandboxRouteBodyLimit is the request body bound of a sandbox route, 0
// for a path that keeps the hook socket's default (apiRequestBodyMaxBytes).
func sandboxRouteBodyLimit(path string) int64 {
	switch {
	case isSandboxOTLPPath(path):
		return sandboxrelay.MaxOTLPBodyBytes
	case path == sandboxrelay.PathEvents:
		return sandboxrelay.MaxEventBatchBytes
	case path == sandboxrelay.PathPolicyResolve:
		return sandboxrelay.MaxResolveBytes
	}
	return 0
}

// isSandboxOTLPPath reports a relayed OTLP export path.
func isSandboxOTLPPath(path string) bool {
	return strings.HasPrefix(path, sandboxrelay.PathOTLPPrefix)
}

// sandboxBudgetForKey returns the class limits of a limiter key built by
// hookCallerBudgetKey, and false for a host or OTLP key.
func sandboxBudgetForKey(key string) (sandboxBudgetLimit, bool) {
	at := strings.LastIndexByte(key, '|')
	if at < 0 {
		return sandboxBudgetLimit{}, false
	}
	if key[at+1:] == sandboxBudgetPending {
		return sandboxBudgetLimits[sandboxBudgetHook], true
	}
	limit, ok := sandboxBudgetLimits[key[at+1:]]
	return limit, ok
}

// sandboxHookBudgetMessage is the text of the 429 an account's relayed hook
// or receipt gets when the account budget is empty: it names the budget, so
// the user knows the call was refused for its rate, not lost to an outage.
func sandboxHookBudgetMessage() string {
	return fmt.Sprintf("DefenseClaw allows the sandboxes of one user %d tool calls a second together (a burst of %d); this call is over that budget and did not run, so retry in a few seconds",
		sandboxUserHookRate, sandboxUserHookBurst)
}

// isSandboxHookClassKey reports whether a limiter key is one of the account's
// relayed hook or receipt classes.
func isSandboxHookClassKey(key string) bool {
	at := strings.LastIndexByte(key, '|')
	if at < 0 {
		return false
	}
	switch key[at+1:] {
	case sandboxBudgetHook, sandboxBudgetPending, sandboxBudgetReceipt:
		return true
	}
	return false
}

// Stable reasons of a sandbox request refused 429 by its own binding's
// limiter (sandboxauth), as distinct from the account budget
// (managedHookReasonRateLimited) and the gateway-wide bound
// (managedHookReasonOverloaded).
const (
	sandboxReasonBindingRate     = "sandbox_rate_limited"
	sandboxReasonBindingInFlight = "sandbox_too_many_requests"
)

// sandboxHookRefusal names the cause of a 429 on a sandbox request: the
// stable reason and a message that says which limit refused it, so a hook
// shows the real cause and not the account budget for every refusal. err is
// what the binding's limiter returned (a *sandboxauth.LimitError carrying the
// limit in force for that binding and bucket), or the refusal string the
// account class budget (hookCallerLimiter.chargeClass) or admission produced.
// A binding refusal that does not carry its limit says which kind of limit
// refused and states no number.
func sandboxHookRefusal(err error) (reason, message string) {
	var limit *sandboxauth.LimitError
	switch {
	case errors.As(err, &limit):
		return sandboxLimitRefusal(limit)
	case errors.Is(err, sandboxauth.ErrRateLimited):
		return sandboxReasonBindingRate, "DefenseClaw is limiting how fast this one sandbox may send requests; this request did not run, so retry in a few seconds"
	case errors.Is(err, sandboxauth.ErrTooManyInFlight):
		return sandboxReasonBindingInFlight, "this sandbox already has as many requests waiting for DefenseClaw's answer as it may; this request did not run, so retry in a few seconds"
	case err != nil && err.Error() == managedHookReasonOverloaded:
		return managedHookReasonOverloaded, managedHookOverloadedMessage
	case err != nil && err.Error() == managedHookReasonRateLimited:
		return managedHookReasonRateLimited, sandboxHookBudgetMessage()
	}
	return managedHookReasonRateLimited, managedHookRateLimitedMessage
}

// sandboxLimitRefusal words a binding limiter refusal with the numbers the
// limiter applied to that binding and bucket.
func sandboxLimitRefusal(e *sandboxauth.LimitError) (reason, message string) {
	const retry = "; this request did not run, so retry in a few seconds"
	if errors.Is(e, sandboxauth.ErrRateLimited) {
		what := "tool calls"
		switch e.Limit {
		case sandboxauth.LimitReceipt:
			what = "tool-call confirmations"
		case sandboxauth.LimitTelemetry:
			what = "telemetry uploads"
		}
		return sandboxReasonBindingRate, fmt.Sprintf("DefenseClaw is limiting how fast this one sandbox may send %s (%s a second, a burst of %d)%s",
			what, strconv.FormatFloat(e.RPS, 'g', -1, 64), e.Burst, retry)
	}
	switch e.Limit {
	case sandboxauth.LimitTelemetry:
		return sandboxReasonBindingInFlight, fmt.Sprintf("this sandbox already has as many telemetry uploads waiting as it may (%d)%s", e.MaxInFlight, retry)
	case sandboxauth.LimitTelemetryTotal:
		return sandboxReasonBindingInFlight, fmt.Sprintf("DefenseClaw is already receiving as many telemetry uploads from all sandboxes together as it may (%d)%s", e.MaxInFlight, retry)
	}
	return sandboxReasonBindingInFlight, fmt.Sprintf("this sandbox already has as many requests waiting for DefenseClaw's answer as it may (%d)%s", e.MaxInFlight, retry)
}
