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
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The live shadow run of the effect-model rule lane (S7, GAP-0256).
//
// guardrail.cascade.lanes.effects=shadow computes the effect lane beside today's rules
// on every outermost trusted-action dispatch of a hook call and writes what it
// would have done, and never changes the answer:
//
//   - verdict-neutral: nothing it returns reaches a finding, a verdict or a
//     response. A panic and an over-budget input are recorded and ignored;
//   - off the hook's path: the run starts on its own goroutine, so the hook
//     does not wait for it, and a bounded number of runs are in flight; a call
//     that finds every slot busy is counted (effectShadowDropped), never queued;
//   - bounded work, counted and never timed: the command must pass
//     shellparse.TooDeep, the same parser input bound the readers of the hook
//     use (a chain, nesting or brace budget past it skips the run, reason
//     parse_budget_exceeded; the readers take their own over-limit path on
//     that bound), and the extractor counts its own work (the walker budget,
//     the effect count, the nesting depth). A run that hits one of those
//     keeps what it read and classified, and the call is TRUNCATED
//     (bounded.Effects, reason work_budget_exceeded), never clean. No clock
//     decides an answer, so a call gets the same verdict on a loaded host as
//     on an idle one (DET111 rule: bounds are counted work, never wall clock;
//     FIX-T19, review P2-1);
//   - one code path: effectShadowRun is what the live hook runs and what the
//     benchmark harness (EvaluateDeterministicAction, so s7-gate's effects
//     column) runs, so a number the gate reports is what the hook computes.

// Reason codes a shadow run records when it has no verdict (or a partial one).
const (
	effectShadowReasonBudget = "parse_budget_exceeded"
	// effectShadowReasonWork: the extractor stopped at one of its counted caps
	// (effects.ReasonLimit). The answer of what it read is kept and the call
	// is truncated (EffectShadowResult.truncated).
	effectShadowReasonWork  = "work_budget_exceeded"
	effectShadowReasonPanic = "shadow_panic"
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

// effectShadowFaultHook is a test-only seam: when non-nil it runs inside the
// guarded part of effectShadowRun, so a test can make the run panic or stall
// (a stall changes only the cost the run reports, never its answer).
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
// skipped or panicked run returns clean allow results carrying the reason code
// and the cost, so the caller records it and goes on (the lane is raise only:
// the 1.0.10 readers decide such a call, and they take their own over-limit
// path on the shared input bound). A run cut at a counted cap of the
// extractor keeps its classification and carries the cut (truncated). The
// clock is read only for the cost it reports.
func effectShadowRun(request trustedActionRequest, mode effectRulesMode, tiers ...effectTierMode) (results []EffectShadowResult) {
	start := time.Now()
	results = make([]EffectShadowResult, len(tiers))
	for i := range results {
		results[i] = EffectShadowResult{Mode: string(mode), Tier: string(effectTierClean), Action: guardrailActionAllow}
	}
	finish := func(reason string, effectCount int, cut bounded.CapSet) []EffectShadowResult {
		cost := time.Since(start).Microseconds()
		for i := range results {
			results[i].Reason, results[i].CostUS, results[i].Effects, results[i].truncated = reason, cost, effectCount, cut
		}
		return results
	}
	defer func() {
		if recover() != nil {
			for i := range results {
				results[i] = EffectShadowResult{Mode: string(mode), Tier: string(effectTierClean), Action: guardrailActionAllow}
			}
			results = finish(effectShadowReasonPanic, 0, bounded.CapSet{})
		}
	}()
	call, opts, ok := effectCall(request.Connector, request.Input, effectWindowsCall(request))
	if !ok {
		return results
	}
	if reason := effectShadowBudgetReason(call); reason != "" {
		return finish(reason, 0, bounded.CapSet{})
	}
	opts = effectAccountOptions(call, opts, request.effectLogin)
	if effectShadowFaultHook != nil {
		effectShadowFaultHook()
	}
	result := effects.Extract(call, opts)
	accountHomes := make([]string, 0, len(opts.Accounts))
	for _, home := range opts.Accounts {
		if home != "" {
			accountHomes = append(accountHomes, home)
		}
	}
	facts := effectrules.Project(result, effectrules.Env{
		Home:         request.Input.ActiveHome,
		Flavor:       opts.Flavor,
		AccountHomes: accountHomes,
		Resolve:      effectResolverOverride,
	})
	// The unknown tier alerts in the default pack, per-user and managed alike
	// (owner ruling 2026-11-21, GAP-1611/1698); the strict packs block.
	strict := request.StrictPolicy
	text := effectReachText(call)
	reachEnv := newEffectReachEnv(request.Input.ActiveHome, text)
	for i, tier := range tiers {
		c := classifyEffects(result, facts, opts.Flavor, tier, reachEnv)
		effectReachUnplaced(&c, result, facts, text, request.Input.ActiveHome, opts.Flavor)
		res := &results[i]
		res.Sets, res.Program, res.Kind, res.Reach, res.RoleHeld, res.LinkHeld, res.Known = c.sets, c.program, c.kind, c.reach, c.roleHeld, c.linkHeld, c.known
		res.KnownMutation, res.LinkTo = c.knownMutation, c.linkTo && !c.linkAt
		res.ReadProofs = c.readProofs
		switch {
		case c.restricted:
			res.Tier = string(effectTierRestricted)
		case c.touches:
			res.Tier = string(effectTierUnknown)
		}
		res.Action = effectAction(c.touches, c.restrictedRuling, strict)
		if res.Tier != string(effectTierClean) {
			res.RuleIDs = []string{"effect.protected_target_" + res.Tier}
		}
	}
	for i := range results {
		countEffectReach(results[i])
	}
	if effectExtractCut(result) {
		return finish(effectShadowReasonWork, len(result.Effects), bounded.Of(bounded.Effects))
	}
	return finish("", len(result.Effects), bounded.CapSet{})
}

// effectExtractCut reports whether the extractor stopped at one of its
// counted caps (effects.ReasonLimit: the walker work budget, the effect
// count, the nesting depth of a script or an MCP argument tree). What it read
// before the cap is classified and kept; the part past it is read by nothing
// in this lane, so the call is TRUNCATED, never clean.
func effectExtractCut(result effects.Result) bool {
	for _, u := range result.Unknowns {
		if u.Code == effects.ReasonLimit {
			return true
		}
	}
	return false
}

// effectReachText is the call text the reach rule's name scan reads: the
// shell command, else the argv words.
func effectReachText(call effects.Call) string {
	if call.Command != "" {
		return call.Command
	}
	return strings.Join(call.Argv, " ")
}

// effectReachCounts counts, per reach reason, the effect-lane verdicts above
// clean that carried it, and effectReachRoleHeld the R-ROLE unknowns counted
// but not raised. The benchmark harness and the shadow report read them
// (EffectReachCounts) to hold each reason's benign rate at 1.0.10.
var (
	effectReachCounts   = map[string]*atomic.Int64{}
	effectReachRoleHeld atomic.Int64
	effectReachLinkHeld atomic.Int64
)

func init() {
	for _, r := range effectrules.ReachReasons {
		effectReachCounts[r] = new(atomic.Int64)
	}
}

func countEffectReach(res EffectShadowResult) {
	if res.Tier != string(effectTierClean) {
		for _, r := range res.Reach {
			if n := effectReachCounts[r]; n != nil {
				n.Add(1)
			}
		}
	}
	if res.RoleHeld {
		effectReachRoleHeld.Add(1)
	}
	if res.LinkHeld {
		effectReachLinkHeld.Add(1)
	}
}

// EffectReachCounts returns the per-reason counts since the process started,
// plus "R-ROLE-held" and "LINK-held" (a member reached only through a
// followed link, counted, not raised).
func EffectReachCounts() map[string]int64 {
	out := make(map[string]int64, len(effectReachCounts)+2)
	for r, n := range effectReachCounts {
		out[r] = n.Load()
	}
	out[effectrules.ReachRole+"-held"] = effectReachRoleHeld.Load()
	out["LINK-held"] = effectReachLinkHeld.Load()
	return out
}

// scheduleEffectShadow starts one shadow run for the hook on its own goroutine
// and hands the answer to record. It returns at once. When every slot is in
// use the run is dropped and counted, never queued behind the hook.
func scheduleEffectShadow(request trustedActionRequest, mode effectRulesMode, tier effectTierMode, record func(EffectShadowResult)) {
	if record == nil || effectShadowLiveOff {
		return
	}
	goEffectShadow(func() { record(effectShadowRun(request, mode, tier)[0]) })
}

// goEffectShadow runs fn on its own goroutine in one of the bounded shadow
// slots. It returns at once; when every slot is in use fn is dropped and
// counted (effectShadowDropped), never queued behind the hook.
func goEffectShadow(fn func()) {
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
		fn()
	}()
}

// recordEffectShadowAsync hands a finished run of the ON lane to record off
// the hook's path, in the same bounded slots: the hook never waits for the
// audit write.
func recordEffectShadowAsync(res EffectShadowResult, record func(EffectShadowResult)) {
	if record == nil || effectShadowLiveOff {
		return
	}
	goEffectShadow(func() { record(res) })
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
	if len(res.Reach) > 0 {
		b.WriteString(" reach=" + strings.Join(res.Reach, ","))
	}
	if res.RoleHeld {
		b.WriteString(" role_held=1")
	}
	if res.LinkHeld {
		b.WriteString(" link_held=1")
	}
	if res.Known {
		b.WriteString(" known=1")
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
