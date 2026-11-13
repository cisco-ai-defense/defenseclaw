// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// shadowLiveRequest is a hook-shaped request for one shell command.
func shadowLiveRequest(command string) trustedActionRequest {
	return trustedActionRequest{
		Input: actionfacts.Input{
			Command: command, ActiveHome: "/home/u", CWD: "/home/u/work",
			DialectHint: actionfacts.DialectPOSIX,
		},
		Connector:          "claudecode",
		EnforcementCapable: true,
	}
}

// useEffectsRulesMode publishes a generation with guardrail.effects_rules set
// and a lexical link resolver, and restores both when the test ends.
func useEffectsRulesMode(t *testing.T, mode string) {
	t.Helper()
	previous := liveGeneration.Load()
	cfg := &config.Config{}
	cfg.Guardrail.EffectsRules = mode
	cfg.Guardrail.EffectsRulesTier = string(tierRestricted)
	liveGeneration.Store(&Generation{Config: cfg})
	prevResolver := effectResolverOverride
	effectResolverOverride = func(path string) (string, bool) { return path, true }
	t.Cleanup(func() {
		liveGeneration.Store(previous)
		effectResolverOverride = prevResolver
		effectShadowFaultHook = nil
	})
}

// dispatchShadowLive dispatches one command through the trusted-action
// dispatcher and returns its findings and the shadow records it produced.
func dispatchShadowLive(t *testing.T, command string, want int) ([]RuleFinding, []EffectShadowResult) {
	t.Helper()
	var mu sync.Mutex
	var got []EffectShadowResult
	done := make(chan struct{}, 8)
	request := shadowLiveRequest(command)
	request.recordEffectShadow = func(res EffectShadowResult) {
		mu.Lock()
		got = append(got, res)
		mu.Unlock()
		done <- struct{}{}
	}
	findings := dispatchTrustedAction(context.Background(), request)
	for i := 0; i < want; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("shadow record %d of %d did not arrive", i+1, want)
		}
	}
	// Let a record that should not exist show up before the count is read.
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	return findings, append([]EffectShadowResult(nil), got...)
}

const shadowLiveWrite = `echo k >> /home/u/.ssh/authorized_keys`

// The hook computes the effect lane in shadow mode and records the would-be
// verdict (tier, action, rule id, cost), and the findings are the findings of
// the same call with the lane off: shadow is verdict-neutral.
func TestEffectShadowLiveRecordsAndIsVerdictNeutral(t *testing.T) {
	useEffectsRulesMode(t, "off")
	offFindings, offRecs := dispatchShadowLive(t, shadowLiveWrite, 0)
	if len(offRecs) != 0 {
		t.Fatalf("effects_rules=off recorded %d shadow runs, want 0", len(offRecs))
	}

	useEffectsRulesMode(t, "shadow")
	findings, recs := dispatchShadowLive(t, shadowLiveWrite, 1)
	if len(recs) != 1 {
		t.Fatalf("shadow recorded %d runs, want 1", len(recs))
	}
	res := recs[0]
	if res.Mode != "shadow" || res.Tier != string(effectTierRestricted) || res.Action != guardrailActionBlock {
		t.Fatalf("would-be verdict = mode %q tier %q action %q, want shadow restricted block", res.Mode, res.Tier, res.Action)
	}
	if len(res.RuleIDs) != 1 || res.RuleIDs[0] != "effect.protected_target_restricted" || res.Reason != "" || res.Effects == 0 {
		t.Fatalf("record = %+v, want one restricted rule id, no reason, effects counted", res)
	}
	if !reflect.DeepEqual(ruleIDsOf(findings), ruleIDsOf(offFindings)) {
		t.Fatalf("shadow changed the findings: off %v, shadow %v", ruleIDsOf(offFindings), ruleIDsOf(findings))
	}
	for _, id := range ruleIDsOf(findings) {
		if strings.HasPrefix(id, "effect.") {
			t.Fatalf("shadow leaked an effect finding into the verdict: %s", id)
		}
	}
}

func ruleIDsOf(findings []RuleFinding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

// A panic inside the run is recorded and ignored: the findings are unchanged
// and the hook is not affected.
func TestEffectShadowLivePanicIsRecordedAndIgnored(t *testing.T) {
	useEffectsRulesMode(t, "off")
	baseline, _ := dispatchShadowLive(t, shadowLiveWrite, 0)

	useEffectsRulesMode(t, "shadow")
	effectShadowFaultHook = func() { panic("injected shadow fault") }
	findings, recs := dispatchShadowLive(t, shadowLiveWrite, 1)
	if len(recs) != 1 || recs[0].Reason != effectShadowReasonPanic || recs[0].Action != guardrailActionAllow || recs[0].Tier != string(effectTierClean) {
		t.Fatalf("panic record = %+v, want shadow_panic, clean, allow", recs)
	}
	if !reflect.DeepEqual(ruleIDsOf(findings), ruleIDsOf(baseline)) {
		t.Fatalf("a shadow panic changed the findings: %v vs %v", ruleIDsOf(findings), ruleIDsOf(baseline))
	}
}

// A run past the wall-clock cap is recorded as shadow_timeout and its answer
// is discarded.
func TestEffectShadowLiveTimeoutIsRecordedAndDiscarded(t *testing.T) {
	useEffectsRulesMode(t, "shadow")
	prev := effectShadowTimeCap
	effectShadowTimeCap = 5 * time.Millisecond
	t.Cleanup(func() { effectShadowTimeCap = prev })
	effectShadowFaultHook = func() { time.Sleep(30 * time.Millisecond) }
	_, recs := dispatchShadowLive(t, shadowLiveWrite, 1)
	if len(recs) != 1 || recs[0].Reason != effectShadowReasonTimeout || recs[0].Action != guardrailActionAllow || len(recs[0].RuleIDs) != 0 {
		t.Fatalf("timeout record = %+v, want shadow_timeout, allow, no rule ids", recs)
	}
}

// Input past the parser bound skips the run: the extractor never starts and the
// record carries parse_budget_exceeded.
func TestEffectShadowLiveParseBudgetSkipsTheRun(t *testing.T) {
	useEffectsRulesMode(t, "shadow")
	started := false
	effectShadowFaultHook = func() { started = true }
	deep := strings.Repeat("(", 600) + "x" + strings.Repeat(")", 600)
	_, recs := dispatchShadowLive(t, deep, 1)
	if started {
		t.Fatal("the extractor ran on input past the parser bound")
	}
	if len(recs) != 1 || recs[0].Reason != effectShadowReasonBudget || recs[0].Action != guardrailActionAllow {
		t.Fatalf("budget record = %+v, want parse_budget_exceeded, allow", recs)
	}
}

// With every slot busy a run is dropped and counted, never queued, and the
// dispatch returns at once.
func TestEffectShadowLiveBusySlotsDropAndCount(t *testing.T) {
	for i := 0; i < effectShadowMaxConcurrent; i++ {
		effectShadowSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < effectShadowMaxConcurrent; i++ {
			<-effectShadowSlots
		}
	})
	before := effectShadowDropped.Load()
	called := false
	scheduleEffectShadow(shadowLiveRequest(shadowLiveWrite), effectRulesShadow, tierRestricted,
		func(EffectShadowResult) { called = true })
	if effectShadowDropped.Load() != before+1 || called {
		t.Fatalf("dropped %d (want %d), recorded %v (want false)", effectShadowDropped.Load(), before+1, called)
	}
}

// The audit row details are value-free: the program, kind and set names, never a
// path or a command.
func TestEffectShadowAuditDetailsAreValueFree(t *testing.T) {
	useEffectsRulesMode(t, "shadow")
	res := effectShadowRun(shadowLiveRequest(shadowLiveWrite), effectRulesShadow, tierRestricted)[0]
	details := effectShadowAuditDetails(res, 3)
	for _, want := range []string{"lane=effects-shadow mode=shadow", "tier=restricted", "would=block", "rules=effect.protected_target_restricted", "cost_us=", "dropped=3"} {
		if !strings.Contains(details, want) {
			t.Fatalf("details %q lack %q", details, want)
		}
	}
	for _, leak := range []string{"/home/u", ".ssh/", "echo"} {
		if strings.Contains(details, leak) {
			t.Fatalf("details %q carry %q", details, leak)
		}
	}
}

// Inputs shaped like the GAP-0254 pipeline and the GAP-0255 || list, plus the
// other ways a call can ask for unbounded work, cannot exceed the shadow time
// or allocation cap: each is skipped by the input bound or finishes inside both
// caps. The "near" shapes sit just under the size bound, so they reach the
// parser and the walker and measure the worst case the lane admits.
func TestEffectShadowLivePathologicalInputsStayInsideTheCaps(t *testing.T) {
	useEffectsRulesMode(t, "shadow")
	const allocCap = 64 << 20
	timeCap := 4 * effectShadowTimeCap // the parse before the walk is not interruptible
	near := effectShadowMaxCommandBytes - 64
	fill := func(unit string) string { return strings.Repeat(unit, near/len(unit)) }
	protectedWrite := " echo k >> /home/u/.ssh/authorized_keys"
	type shape struct {
		command string
		skipped bool // the input bound must skip it
	}
	shapes := map[string]shape{
		"gap0254-pipeline-67kb":     {strings.Repeat("a | ", 17<<10), true},
		"gap0255-or-list-500kb":     {strings.Repeat("a || ", 100<<10), true},
		"and-list-500kb":            {strings.Repeat("a && ", 100<<10), true},
		"nesting-600":               {strings.Repeat("(", 600) + "x" + strings.Repeat(")", 600), true},
		"brace-explosion":           {strings.Repeat("{a,b}", 40), true},
		"flat-words-1mib":           {strings.Repeat("a ", 512<<10), true},
		"many-redirects-800kb":      {strings.Repeat("echo k >> /home/u/.ssh/authorized_keys; ", 20<<10), true},
		"near-cap-pipeline":         {fill("a | ") + protectedWrite, false},
		"near-cap-or-list":          {fill("a || ") + protectedWrite, false},
		"near-cap-and-list":         {fill("a && ") + protectedWrite, false},
		"near-cap-flat-words":       {fill("a ") + protectedWrite, false},
		"near-cap-redirects":        {fill("echo k >> /home/u/.ssh/authorized_keys; "), false},
		"near-cap-nested-groups":    {strings.Repeat("(", 500) + fill("a;") + strings.Repeat(")", 500), false},
		"near-cap-semicolon-chain":  {fill("a; ") + protectedWrite, false},
		"near-cap-command-subst":    {fill("$(a) ") + protectedWrite, false},
		"near-cap-assignments":      {fill("A=b ") + protectedWrite, false},
		"near-cap-quoted-words":     {fill("'a b' ") + protectedWrite, false},
		"near-cap-heredoc-and-pipe": {"cat <<E | tee /home/u/.ssh/authorized_keys\n" + fill("x\n") + "E", false},
	}
	for name, sh := range shapes {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			res := effectShadowRun(shadowLiveRequest(sh.command), effectRulesShadow, tierRestricted)[0]
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			alloc := after.TotalAlloc - before.TotalAlloc
			if sh.skipped && res.Reason != effectShadowReasonBudget {
				t.Errorf("%s reason %q, want the input bound to skip it (%s)", name, res.Reason, effectShadowReasonBudget)
			}
			if elapsed > timeCap {
				t.Errorf("%s took %v, over the shadow time bound %v (reason %q)", name, elapsed, timeCap, res.Reason)
			}
			if alloc > allocCap {
				t.Errorf("%s allocated %d MiB, over the shadow allocation cap %d MiB (reason %q)", name, alloc>>20, allocCap>>20, res.Reason)
			}
			t.Logf("%s: %v, %d KiB alloc, reason %q tier %s", name, elapsed, alloc>>10, res.Reason, res.Tier)
		})
	}
}
