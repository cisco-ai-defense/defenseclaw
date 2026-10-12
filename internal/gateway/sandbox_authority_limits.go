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
	"math"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

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
// 25/s burst 100) is the first limit one sandbox meets; sandbox-hook at
// 100/s carries four sandboxes at that rate and burst 200 lets two burst
// at once. The 60 s policy/current poll is one call a minute per live
// registration.
const (
	sandboxBudgetHook   = "sandbox-hook"
	sandboxBudgetPolicy = "sandbox-policy"
	sandboxBudgetEvents = "sandbox-events"
)

// sandboxBudgetLimit is one class's rate, burst and in-flight bound per
// uid.
type sandboxBudgetLimit struct {
	Rate, Burst, InFlight int
}

// sandboxBudgetLimits is the per-class table; tests replace entries.
var sandboxBudgetLimits = map[string]sandboxBudgetLimit{
	sandboxBudgetHook:   {Rate: 100, Burst: 200, InFlight: 32},
	sandboxBudgetPolicy: {Rate: 10, Burst: 20, InFlight: 8},
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

// sandboxRecordBudget is the per-account sandbox telemetry records budget
// (sandboxTelemetryRecordRate, sandboxTelemetryRecordBurst). The zero value
// is ready.
type sandboxRecordBudget struct {
	mu    sync.Mutex
	byUID map[int]*sandboxRecordBucket
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
	bucket, ok := b.byUID[uid]
	if !ok {
		bucket = &sandboxRecordBucket{limiter: rate.NewLimiter(sandboxTelemetryRecordRate, sandboxTelemetryRecordBurst)}
		b.byUID[uid] = bucket
	}
	bucket.seen = now
	if bucket.limiter.AllowN(now, n) {
		return 0, true
	}
	short := float64(n) - bucket.limiter.TokensAt(now)
	return time.Duration(math.Ceil(short / sandboxTelemetryRecordRate * float64(time.Second))), false
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
	limit, ok := sandboxBudgetLimits[key[at+1:]]
	return limit, ok
}
