// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The live shadow run of the effect-model rule lane (S7, GAP-0256).
//
// guardrail.cascade.lanes.effects=shadow computes the effect lane beside today's rules
// on every outermost trusted-action dispatch of a hook call and writes what it
// would have done, and never changes the answer:
//
//   - verdict-neutral: nothing it returns reaches a finding, a verdict or a
//     response. A panic, a time-out and an over-budget input are recorded and
//     ignored;
//   - off the hook's path: the run starts on its own goroutine, so the hook
//     does not wait for it, and a bounded number of runs are in flight; a call
//     that finds every slot busy is counted (effectShadowDropped), never queued;
//   - bounded work: the command must pass shellparse.TooDeep, the same parser
//     input bound the readers of the hook use (a chain, nesting or brace budget
//     past it skips the run, reason parse_budget_exceeded), the walker has its
//     own work budget, and a per-call wall-clock cap (effectShadowTimeCap)
//     stops the walk and discards its answer (reason shadow_timeout);
//   - one code path: effectShadowRun is what the live hook runs and what the
//     benchmark harness (EvaluateDeterministicAction, so s7-gate's effects
//     column) runs, so a number the gate reports is what the hook computes.

// Reason codes a shadow run records when it has no verdict (or a partial one).
const (
	effectShadowReasonBudget  = "parse_budget_exceeded"
	effectShadowReasonTimeout = "shadow_timeout"
	effectShadowReasonPanic   = "shadow_panic"
)

const (
	// effectShadowMaxConcurrent bounds the shadow runs in flight in a process.
	effectShadowMaxConcurrent = 4
	// effectShadowMaxCommandBytes bounds the command text the shadow run reads.
	// The parse before the walk cannot be interrupted and costs about a
	// microsecond and 400 bytes of garbage per input byte (measured on the
	// build box, 2026-11-13), so the size is the bound on its time and
	// allocation. 64 KiB is above the largest real call (13,559 nodes in 3.1
	// million owner-trace calls); a command past it is skipped, like one past
	// the parser bound.
	effectShadowMaxCommandBytes = 64 << 10
	// effectShadowCleanSample is the 1-in-N sample of clean, fully computed
	// runs that gets an audit row, so the cost of a clean call stays visible
	// without a row for every hook call. A run with a tier above clean, or with
	// a reason code, always gets a row.
	effectShadowCleanSample = 100
)

// effectShadowTimeCap is the wall-clock cap of one shadow run. It is a
// variable only so tests can widen it; production never changes it.
var effectShadowTimeCap = 50 * time.Millisecond

// effectShadowFaultHook is a test-only seam: when non-nil it runs inside the
// guarded part of effectShadowRun, so a test can make the run panic or stall.
var effectShadowFaultHook func()

// effectShadowLiveOff stops the hook from starting the async run. Only the
// s7bench harness sets it: the harness measures the same core through
// EvaluateDeterministicAction (effectShadowRun) and reads the answer per case,
// so a second run per hook call would only double the CPU and the audit rows.
var effectShadowLiveOff bool

var (
	effectShadowSlots   = make(chan struct{}, effectShadowMaxConcurrent)
	effectShadowDropped atomic.Int64
	effectShadowSeen    atomic.Int64
)

// effectShadowBudgetReason applies the input bounds to the call. It is the one
// place the lane asks "is this input within what the shadow run may read": the
// size bound above, and shellparse.TooDeep, the parser input bound the readers
// of the hook use (nesting, chain operators, brace expansion). Only shell text
// reaches a recursive parser; argv and JSON-argument calls are bounded by the
// extractor itself.
func effectShadowBudgetReason(call effects.Call) string {
	if call.Command == "" {
		return ""
	}
	if len(call.Command) > effectShadowMaxCommandBytes || shellparse.TooDeep(call.Command) {
		return effectShadowReasonBudget
	}
	return ""
}

// effectShadowRun is the shared core: the effect lane for one request, graded
// once for each tier asked. It never mutates the request and never panics. A
// skipped, timed-out or panicked run returns clean allow results carrying the
// reason code and the cost, so the caller records it and goes on.
func effectShadowRun(request trustedActionRequest, mode effectRulesMode, tiers ...effectTierMode) (results []EffectShadowResult) {
	start := time.Now()
	results = make([]EffectShadowResult, len(tiers))
	for i := range results {
		results[i] = EffectShadowResult{Mode: string(mode), Tier: string(effectTierClean), Action: guardrailActionAllow}
	}
	finish := func(reason string, effectCount int) []EffectShadowResult {
		cost := time.Since(start).Microseconds()
		for i := range results {
			results[i].Reason, results[i].CostUS, results[i].Effects = reason, cost, effectCount
		}
		return results
	}
	defer func() {
		if recover() != nil {
			for i := range results {
				results[i] = EffectShadowResult{Mode: string(mode), Tier: string(effectTierClean), Action: guardrailActionAllow}
			}
			results = finish(effectShadowReasonPanic, 0)
		}
	}()
	call, opts, ok := effectCall(request.Connector, request.Input)
	if !ok {
		return results
	}
	if reason := effectShadowBudgetReason(call); reason != "" {
		return finish(reason, 0)
	}
	deadline := start.Add(effectShadowTimeCap)
	opts.Deadline = deadline
	if effectShadowFaultHook != nil {
		effectShadowFaultHook()
	}
	result := effects.Extract(call, opts)
	if time.Now().After(deadline) {
		return finish(effectShadowReasonTimeout, len(result.Effects))
	}
	facts := effectrules.Project(result, effectrules.Env{
		Home:    request.Input.ActiveHome,
		Flavor:  opts.Flavor,
		Resolve: effectResolverOverride,
	})
	strictOrManaged := request.StrictPolicy || request.ManagedInstall
	for i, tier := range tiers {
		c := classifyEffects(result, facts, opts.Flavor, tier)
		res := &results[i]
		res.Sets, res.Program, res.Kind = c.sets, c.program, c.kind
		switch {
		case c.restricted:
			res.Tier = string(effectTierRestricted)
		case c.touches:
			res.Tier = string(effectTierUnknown)
		}
		res.Action = effectAction(c.touches, c.restrictedRuling, strictOrManaged)
		if res.Tier != string(effectTierClean) {
			res.RuleIDs = []string{"effect.protected_target_" + res.Tier}
		}
	}
	if time.Now().After(deadline) {
		return finish(effectShadowReasonTimeout, len(result.Effects))
	}
	return finish("", len(result.Effects))
}

// scheduleEffectShadow starts one shadow run for the hook on its own goroutine
// and hands the answer to record. It returns at once. When every slot is in
// use the run is dropped and counted, never queued behind the hook.
func scheduleEffectShadow(request trustedActionRequest, mode effectRulesMode, tier effectTierMode, record func(EffectShadowResult)) {
	if record == nil || effectShadowLiveOff {
		return
	}
	select {
	case effectShadowSlots <- struct{}{}:
	default:
		effectShadowDropped.Add(1)
		return
	}
	go func() {
		defer func() {
			<-effectShadowSlots
			_ = recover() // a recorder failure is as neutral as a run failure
		}()
		record(effectShadowRun(request, mode, tier)[0])
	}()
}

// effectShadowRecordWorthy reports whether a finished run gets an audit row:
// every run that has a tier above clean or a reason code, and a 1-in-N sample
// of the clean ones.
func effectShadowRecordWorthy(res EffectShadowResult) bool {
	if res.Tier != string(effectTierClean) || res.Reason != "" {
		return true
	}
	return effectShadowSeen.Add(1)%effectShadowCleanSample == 0
}

// effectShadowAuditDetails renders the audit row details: value-free (the
// protected-set names, the program and the kind, never a path or a command).
func effectShadowAuditDetails(res EffectShadowResult, dropped int64) string {
	var b strings.Builder
	b.WriteString("lane=effects-shadow mode=" + res.Mode + " tier=" + res.Tier + " would=" + res.Action)
	if len(res.Sets) > 0 {
		b.WriteString(" sets=" + strings.Join(res.Sets, ","))
	}
	if res.Program != "" {
		b.WriteString(" program=" + res.Program)
	}
	if res.Kind != "" {
		b.WriteString(" kind=" + res.Kind)
	}
	if len(res.RuleIDs) > 0 {
		b.WriteString(" rules=" + strings.Join(res.RuleIDs, ","))
	}
	if res.Reason != "" {
		b.WriteString(" reason=" + res.Reason)
	}
	b.WriteString(" cost_us=" + strconv.FormatInt(res.CostUS, 10))
	b.WriteString(" effects=" + strconv.Itoa(res.Effects))
	if dropped > 0 {
		b.WriteString(" dropped=" + strconv.FormatInt(dropped, 10))
	}
	return b.String()
}

// recordEffectShadow writes the audit row of one finished shadow run, as a
// guardrail-inspection row (a guardrail evaluation; the shared audit and
// telemetry registries get no new action) whose details start with
// lane=effects-shadow. The row is INFO, never an alert: a shadow verdict is a
// measurement. A nil server or logger records nothing.
func (a *APIServer) recordEffectShadow(ctx context.Context, connectorName string, res EffectShadowResult) {
	if a == nil || a.logger == nil || !effectShadowRecordWorthy(res) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_ = a.logger.LogActionCtx(context.WithoutCancel(ctx), string(audit.ActionGuardrailInspection), connectorName,
		effectShadowAuditDetails(res, effectShadowDropped.Swap(0)))
}
