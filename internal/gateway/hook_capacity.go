// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The hook capacity counter is the overload signal of the hook path (S8
// DESIGN 18, owner decision 2026-11-14 on bar H1): how many hook calls ended
// at their answer budget each minute, next to how many were answered in
// time. Past the documented max rate of a host, a managed hook denies the
// call (fail closed) and a per-user hook lets it run late (fail open); both
// are counted here, so status, doctor and telemetry can say the host is over
// its capacity instead of leaving it to look like policy.
//
// Sources: the per-user hook-failures.jsonl report (every late call a hook
// logged, by its own time stamp) and, on a managed gateway, the calls the
// gateway saw end without an answer (a client that left before admission or
// before the answer, and a 429 shed). It is memory only: no audit write, so
// nothing is added to the writer the hooks wait for. A restart starts it
// again.

// hookCapacityWindow is how many one-minute buckets the counter keeps.
const hookCapacityWindow = 60

// hookCapacitySizingDoc is the docs page with the measured max rate per
// instance type and OS (the H1 sizing table).
const hookCapacitySizingDoc = "/docs/reference/hook-sizing"

// Hook capacity outcomes, also the outcome attribute of the telemetry
// counter.
const (
	hookCapacityAnswered     = "answered"
	hookCapacityDeadlineDeny = "deadline_deny"
	hookCapacityLateAllow    = "late_allow"
	hookCapacityShed         = "shed"
)

type hookCapacityBucket struct {
	minute                                     int64
	answered, deadlineDenies, lateAllows, shed uint64
}

// HookCapacityCounts is one minute, or a sum of minutes, of the counter.
type HookCapacityCounts struct {
	Answered       uint64 `json:"answered"`
	DeadlineDenies uint64 `json:"deadline_denies"`
	LateAllows     uint64 `json:"late_allows"`
	Shed           uint64 `json:"shed"`
}

// HookCapacitySnapshot is the /status "hook_capacity" object.
type HookCapacitySnapshot struct {
	WindowMinutes int                `json:"window_minutes"`
	Since         time.Time          `json:"since"`
	LastMinute    HookCapacityCounts `json:"last_minute"`
	Last5Minutes  HookCapacityCounts `json:"last_5_minutes"`
	Window        HookCapacityCounts `json:"window"`
	// PeakMinute is the minute of the window with the most deadline
	// outcomes (denies + late allows); zero when there was none.
	PeakMinute      HookCapacityCounts `json:"peak_minute"`
	PeakMinuteStart *time.Time         `json:"peak_minute_start,omitempty"`
	// AnsweredPerMinutePeak is the most calls answered in time in one
	// minute of the window: the rate the host carried.
	AnsweredPerMinutePeak uint64 `json:"answered_per_minute_peak"`
	// Overloaded: the window holds a deadline deny or a late allow.
	Overloaded bool   `json:"overloaded"`
	SizingDoc  string `json:"sizing_doc"`
}

type hookCapacityCounter struct {
	mu      sync.Mutex
	now     func() time.Time
	since   time.Time
	buckets [hookCapacityWindow]hookCapacityBucket
}

func newHookCapacityCounter(now func() time.Time) *hookCapacityCounter {
	if now == nil {
		now = time.Now
	}
	return &hookCapacityCounter{now: now, since: now().UTC()}
}

// hookCapacity is the process counter: the per-user report (a Sidecar
// function) and the API server both feed it.
var hookCapacity = newHookCapacityCounter(nil)

// note adds n calls of outcome at time at. A time outside the window (a
// late report of an old line, a clock step) is not counted.
func (c *hookCapacityCounter) note(outcome string, at time.Time, n uint64) {
	if c == nil || n == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix() / 60
	minute := at.Unix() / 60
	if at.IsZero() {
		minute = now
	}
	if minute > now || minute <= now-hookCapacityWindow {
		return
	}
	b := &c.buckets[minute%hookCapacityWindow]
	if b.minute != minute {
		*b = hookCapacityBucket{minute: minute}
	}
	switch outcome {
	case hookCapacityAnswered:
		b.answered += n
	case hookCapacityDeadlineDeny:
		b.deadlineDenies += n
	case hookCapacityLateAllow:
		b.lateAllows += n
	case hookCapacityShed:
		b.shed += n
	}
}

func (b hookCapacityBucket) counts() HookCapacityCounts {
	return HookCapacityCounts{Answered: b.answered, DeadlineDenies: b.deadlineDenies, LateAllows: b.lateAllows, Shed: b.shed}
}

func (s *HookCapacityCounts) add(o HookCapacityCounts) {
	s.Answered += o.Answered
	s.DeadlineDenies += o.DeadlineDenies
	s.LateAllows += o.LateAllows
	s.Shed += o.Shed
}

// snapshot sums the window as of now.
func (c *hookCapacityCounter) snapshot() HookCapacitySnapshot {
	snap := HookCapacitySnapshot{WindowMinutes: hookCapacityWindow, SizingDoc: hookCapacitySizingDoc}
	if c == nil {
		return snap
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix() / 60
	snap.Since = c.since
	if start := time.Unix((now-hookCapacityWindow+1)*60, 0).UTC(); start.After(snap.Since) {
		snap.Since = start
	}
	var peak uint64
	for _, b := range c.buckets {
		if b.minute > now || b.minute <= now-hookCapacityWindow {
			continue
		}
		counts := b.counts()
		snap.Window.add(counts)
		if b.minute == now {
			snap.LastMinute.add(counts)
		}
		if b.minute > now-5 {
			snap.Last5Minutes.add(counts)
		}
		if late := counts.DeadlineDenies + counts.LateAllows; late > peak {
			peak = late
			snap.PeakMinute = counts
			at := time.Unix(b.minute*60, 0).UTC()
			snap.PeakMinuteStart = &at
		}
		if counts.Answered > snap.AnsweredPerMinutePeak {
			snap.AnsweredPerMinutePeak = counts.Answered
		}
	}
	snap.Overloaded = snap.Window.DeadlineDenies+snap.Window.LateAllows > 0
	return snap
}

// noteHookCallCapacity counts one finalized live hook call (DESIGN 18). On a
// per-user gateway a call that ended at its answer budget is counted from
// the line the hook logged (noteHookFailureCapacity), so here only the calls
// answered in time count. On a managed gateway the hook logs to the account
// folder the gateway does not read, so the recorded outcome of the call is
// the source: the deadline deny the receipt or the fail mode proves, or the
// late allow of an open outage mode.
func (a *APIServer) noteHookCallCapacity(resp agentHookResponse, clientLeft bool) {
	deadline := resp.Reason == hookexec.ManagedGatewayNoAnswerReason || resp.Reason == hookexec.PerUserGatewayNoAnswerReason
	if a == nil || (!clientLeft && !deadline) {
		hookCapacity.note(hookCapacityAnswered, time.Time{}, 1)
		return
	}
	if perUserHookInstall(a.scannerCfg) {
		return
	}
	if resp.Action == "block" {
		hookCapacity.note(hookCapacityDeadlineDeny, time.Time{}, 1)
		return
	}
	hookCapacity.note(hookCapacityLateAllow, time.Time{}, 1)
}

// noteHookCallerGoneCapacity counts a managed call the gateway never
// decided: refused by the admission limits (shed, once per call), or whose
// client left before admission (its outcome follows the outage fail mode).
func (a *APIServer) noteHookCallerGoneCapacity(connector string, shed bool) {
	if shed {
		hookCapacity.note(hookCapacityShed, time.Time{}, 1)
		return
	}
	if cfg := a.runtimeConfigSnapshot(); cfg != nil && cfg.EffectiveHookOutageFailModeForConnector(connector) == "open" {
		hookCapacity.note(hookCapacityLateAllow, time.Time{}, 1)
		return
	}
	hookCapacity.note(hookCapacityDeadlineDeny, time.Time{}, 1)
}
