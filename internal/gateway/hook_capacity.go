// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
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
const hookCapacitySizingDoc = "/docs/support-matrix#hook-sizing"

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
	// PeakMinute is the minute of the window with the most calls that got
	// no answer in time (deadline denies + late allows + shed); zero when
	// there was none.
	PeakMinute      HookCapacityCounts `json:"peak_minute"`
	PeakMinuteStart *time.Time         `json:"peak_minute_start,omitempty"`
	// AnsweredPerMinutePeak is the most calls answered in time in one
	// minute of the window: the rate the host carried.
	AnsweredPerMinutePeak uint64 `json:"answered_per_minute_peak"`
	// Overloaded: the window holds a deadline deny, a late allow or a call
	// the admission limits refused (shed: its hook blocks it when the budget
	// ends unless a resend is admitted).
	Overloaded bool   `json:"overloaded"`
	SizingDoc  string `json:"sizing_doc"`
}

type hookCapacityCounter struct {
	mu      sync.Mutex
	now     func() time.Time
	since   time.Time
	buckets [hookCapacityWindow]hookCapacityBucket
	// sink exports each deadline outcome as the telemetry counter
	// defenseclaw.hook.deadline_outcomes; nil until the API server binds its
	// observability runtime. Called outside mu.
	sink func(outcome string, n uint64)
}

// setSink binds the telemetry export of the deadline outcomes.
func (c *hookCapacityCounter) setSink(sink func(outcome string, n uint64)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.sink = sink
	c.mu.Unlock()
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
	if sink := c.noteLocked(outcome, at, n); sink != nil && outcome != hookCapacityAnswered {
		sink(outcome, n)
	}
}

// noteLocked counts under mu and returns the sink of a counted outcome.
func (c *hookCapacityCounter) noteLocked(outcome string, at time.Time, n uint64) func(string, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix() / 60
	minute := at.Unix() / 60
	if at.IsZero() {
		minute = now
	}
	if minute > now || minute <= now-hookCapacityWindow {
		return nil
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
	return c.sink
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
		if late := counts.DeadlineDenies + counts.LateAllows + counts.Shed; late > peak {
			peak = late
			snap.PeakMinute = counts
			at := time.Unix(b.minute*60, 0).UTC()
			snap.PeakMinuteStart = &at
		}
		if counts.Answered > snap.AnsweredPerMinutePeak {
			snap.AnsweredPerMinutePeak = counts.Answered
		}
	}
	snap.Overloaded = snap.Window.DeadlineDenies+snap.Window.LateAllows+snap.Window.Shed > 0
	return snap
}

// hookCapacityReceiptContextKey carries what the delivery receipt of a
// managed call said to its finalization (hookCapacityReceipt). Set only for
// a call whose answer was offered on the receipt channel.
type hookCapacityReceiptContextKey struct{}

// hookCapacityReceipt is the receipt line of an offered answer: late or
// open is the hook telling the gateway its answer budget ended first; an
// empty line is no receipt (a lost connection or an older hook), which
// proves no deadline.
type hookCapacityReceipt struct{ line string }

// hookCapacityExcludedContextKey marks a finalization the counter skips: the
// journal-failure 503 (pendingFailureHookDecision) is a store or disk
// problem, not load, and must not tell the administrator to run fewer
// agents.
type hookCapacityExcludedContextKey struct{}

// noteHookCallCapacity counts one finalized live hook call (DESIGN 18). On a
// per-user gateway a call that ended at its answer budget is counted from
// the line the hook logged (noteHookFailureCapacity), so here only the calls
// answered in time count. On a managed gateway the hook logs to the account
// folder the gateway does not read, so a deadline is counted only from
// evidence of one: a late or open delivery receipt (the hook says which it
// did), or a client that left before the answer (its outcome follows the
// no-answer fail mode, as for a caller gone before admission). A row that is
// unconfirmed for another reason (no receipt, an older hook) proves no
// deadline and is not counted either way. A panic here never reaches the
// answer.
func (a *APIServer) noteHookCallCapacity(ctx context.Context, connectorName string, resp agentHookResponse, clientLeft bool) {
	defer recoverHookCapacityNote()
	if excluded, _ := ctx.Value(hookCapacityExcludedContextKey{}).(bool); excluded {
		return
	}
	receipt, offered := ctx.Value(hookCapacityReceiptContextKey{}).(hookCapacityReceipt)
	lateReceipt := receipt.line == hookexec.HookDeliveryReceiptLate || receipt.line == hookexec.HookDeliveryReceiptOpen
	noEvidence := resp.Action == hookActionUnconfirmed || resp.Reason == hookexec.ManagedGatewayNoAnswerReason ||
		resp.Reason == hookexec.PerUserGatewayNoAnswerReason || (offered && receipt.line == "")
	if a == nil || perUserHookInstall(a.scannerCfg) {
		if !clientLeft && !lateReceipt && !noEvidence {
			hookCapacity.note(hookCapacityAnswered, time.Time{}, 1)
		}
		return
	}
	switch {
	case receipt.line == hookexec.HookDeliveryReceiptLate:
		hookCapacity.note(hookCapacityDeadlineDeny, time.Time{}, 1)
	case receipt.line == hookexec.HookDeliveryReceiptOpen:
		hookCapacity.note(hookCapacityLateAllow, time.Time{}, 1)
	case clientLeft:
		noteHookOutageCapacity(a.decisionConfig(ctx), connectorName)
	case !noEvidence:
		hookCapacity.note(hookCapacityAnswered, time.Time{}, 1)
	}
}

// noteHookOutageCapacity counts a managed call that ended without an answer
// by the no-answer fail mode of its connector: closed (the default) is a
// deadline deny, open a late allow.
func noteHookOutageCapacity(cfg *config.Config, connector string) {
	if cfg != nil && cfg.EffectiveHookOutageFailModeForConnector(connector) == "open" {
		hookCapacity.note(hookCapacityLateAllow, time.Time{}, 1)
		return
	}
	hookCapacity.note(hookCapacityDeadlineDeny, time.Time{}, 1)
}

// noteHookCallerGoneCapacity counts a managed call the gateway never
// decided: refused by the admission limits (shed, counted by the caller once
// per call), or whose client left before admission (its outcome follows the
// outage fail mode).
func (a *APIServer) noteHookCallerGoneCapacity(connector string, shed bool) {
	defer recoverHookCapacityNote()
	if shed {
		hookCapacity.note(hookCapacityShed, time.Time{}, 1)
		return
	}
	noteHookOutageCapacity(a.runtimeConfigSnapshot(), connector)
}

// noteSandboxReceiptExpiredCapacity counts once a sandbox proposal whose
// receipt never came within sandboxHookReceiptWindow: recovery closes it,
// and the hook took its no-answer fallback.
func (a *APIServer) noteSandboxReceiptExpiredCapacity(connector string) {
	defer recoverHookCapacityNote()
	if a == nil {
		return
	}
	noteHookOutageCapacity(a.runtimeConfigSnapshot(), connector)
}

// recoverHookCapacityNote keeps a panic of the counter or its telemetry sink
// off the hook answer: the call is answered as decided, and the panic is
// logged.
func recoverHookCapacityNote() {
	if recovered := recover(); recovered != nil {
		fmt.Fprintf(os.Stderr, "[gateway] hook capacity note panic (answer unchanged): %v\n", recovered)
	}
}

// hookDeadlineOutcomeV8Producer is the producer of the deadline outcome
// counter.
const hookDeadlineOutcomeV8Producer = "gateway.hook_capacity"

// recordHookDeadlineOutcomeMetric exports n deadline outcomes as the
// telemetry counter defenseclaw.hook.deadline_outcomes. Best effort: an
// unbound runtime or a failed export never changes a hook answer.
func (a *APIServer) recordHookDeadlineOutcomeMetric(outcome string, n uint64) {
	defer recoverHookCapacityNote()
	if a == nil || n == 0 {
		return
	}
	switch outcome {
	case hookCapacityDeadlineDeny, hookCapacityLateAllow, hookCapacityShed:
	default:
		return
	}
	metricRuntime, _ := a.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	if metricRuntime == nil {
		return
	}
	ctx := context.Background()
	item := newGatewayGeneratedMetricItem(
		ctx,
		time.Now().UTC(),
		observability.SourceGateway,
		"",
		hookDeadlineOutcomeV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawHookDeadlineOutcomes),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawHookDeadlineOutcomes(observability.MetricDefenseClawHookDeadlineOutcomesInput{
				Envelope:                envelope,
				Value:                   int64(min(n, uint64(1<<62))),
				DefenseClawMetricReason: outcome,
			})
		},
	)
	_, _ = metricRuntime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}
