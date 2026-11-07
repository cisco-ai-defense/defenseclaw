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
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// Per-class budgets of the managed sandbox routes on the hook socket.
//
// Each class has its own limiter key per peer uid (hookCallerBudgetKey), so
// a flood of relayed hooks from one sandbox never refuses the same user's
// host hooks or a new sandbox's create, and a burst of daemon events never
// takes the budget a relayed hook needs. The host key (<uid>, 60/s burst
// 120, 32 in flight) and the OTLP key (<uid>|otlp) are unchanged; the
// gateway-wide in-flight cap stays shared by every key.
//
// Sizing: a daemon's per-binding limiter (sandboxauth.DefaultLimiterConfig,
// 25/s burst 100) is the first limit one sandbox meets. The account budget
// is what the managed gateway answers inside the hook's 3.5 s window: every
// relayed call (a proposal and its delivery receipt) makes about two dozen
// audit writes under one SQLite write lock, and four sandboxes at 10 calls a
// second answer in about a second on the shared build box (p95 under 1 s),
// while 96 calls a second did not answer in time in half the runs
// (rel-1-0-6 GAP-0490). The budget is therefore 40 calls a second with a
// burst of 100 (the burst one sandbox may itself send), and a call past it
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
	sandboxUserHookRate  = 40
	sandboxUserHookBurst = 100
)

var sandboxUserHookInFlight, sandboxUserReceiptInFlight = managedSandboxInFlightLimits()

// managedSandboxInFlightLimits uses one rendered ingress attempt's maximum
// lifetime for hooks and the gateway's receipt window for acknowledgements.
// These are separate HTTP requests with separate account rate buckets.
func managedSandboxInFlightLimits() (hook, receipt int) {
	first, retry := connector.SandboxHookAttemptBudgets()
	return sandboxWindowCapacity(max(first, retry)), sandboxWindowCapacity(sandboxHookReceiptWindow)
}

func sandboxWindowCapacity(window time.Duration) int {
	return sandboxUserHookBurst + int((time.Duration(sandboxUserHookRate)*window+time.Second-1)/time.Second)
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
// what the binding's limiter returned, or the refusal string the account
// class budget (hookCallerLimiter.chargeClass) or admission produced.
func sandboxHookRefusal(err error) (reason, message string) {
	switch {
	case errors.Is(err, sandboxauth.ErrRateLimited):
		return sandboxReasonBindingRate, fmt.Sprintf("DefenseClaw is limiting how fast this one sandbox may send requests (tool calls: %d a second, a burst of %d); this request did not run, so retry in a few seconds",
			sandboxauth.DefaultHookRPS, sandboxauth.DefaultHookBurst)
	case errors.Is(err, sandboxauth.ErrTooManyInFlight):
		return sandboxReasonBindingInFlight, fmt.Sprintf("this sandbox already has as many requests waiting for DefenseClaw's answer as it may (%d); this request did not run, so retry in a few seconds",
			sandboxauth.DefaultMaxInFlight)
	case err != nil && err.Error() == managedHookReasonOverloaded:
		return managedHookReasonOverloaded, managedHookOverloadedMessage
	case err != nil && err.Error() == managedHookReasonRateLimited:
		return managedHookReasonRateLimited, sandboxHookBudgetMessage()
	}
	return managedHookReasonRateLimited, managedHookRateLimitedMessage
}
