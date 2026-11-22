// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The effect lane is bounded by counted work, never by wall clock (DET111
// rule; FIX-T19, review P2-1 on T19 1a1ce4ad62). These tests use only names
// T19 has, so they run red there and green at the fix.

// effectsLaneSlowStep is past the 50 ms wall-clock cap the lane had at T19
// (effectShadowTimeCap): a loaded host, a GC pause or a Defender scan.
const effectsLaneSlowStep = 60 * time.Millisecond

// TestEffectsLaneVerdictIgnoresTheClock (DET111 FIX-T19, review P2-1): a run
// slowed past the old wall-clock cap keeps its verdict. The lane is bounded by
// counted work; no clock turns a finished classification into a clean allow.
// At T19 (1a1ce4ad62) the slow run returned clean with reason shadow_timeout
// and its Known keys write raised nothing in the ON lane.
func TestEffectsLaneVerdictIgnoresTheClock(t *testing.T) {
	useEffectsRulesMode(t, "on")
	request := shadowLiveRequest(shadowLiveWrite)
	idleRes := computeEffectShadow(request, effectRulesOn, tierRestricted)
	idle := effectShadowFindings(idleRes, effectRulesOn)
	if idleRes.Tier != string(effectTierRestricted) || len(idle) == 0 {
		t.Fatalf("idle run = tier %s findings %v, want a restricted raise for the Known keys write", idleRes.Tier, ruleIDsOf(idle))
	}
	effectShadowFaultHook = func() { time.Sleep(effectsLaneSlowStep) }
	slowRes := computeEffectShadow(request, effectRulesOn, tierRestricted)
	slow := effectShadowFindings(slowRes, effectRulesOn)
	if slowRes.Tier != idleRes.Tier || slowRes.Action != idleRes.Action || slowRes.Reason != "" {
		t.Fatalf("slow run = tier %s action %s reason %q, want the idle answer (tier %s action %s, no reason)",
			slowRes.Tier, slowRes.Action, slowRes.Reason, idleRes.Tier, idleRes.Action)
	}
	if !reflect.DeepEqual(ruleIDsOf(slow), ruleIDsOf(idle)) {
		t.Fatalf("slow run findings %v, idle run %v: the verdict depends on the clock", ruleIDsOf(slow), ruleIDsOf(idle))
	}
}

// effectsLaneWorkCutCommand is within the shared input bound (no TooDeep, under
// the size bound) but has more simple commands than the walker's counted
// work budget (effects walkWorkBudget, 20000), so the walk stops before the
// end of the call.
func effectsLaneWorkCutCommand() string { return strings.Repeat("a;", 20001) + "echo ok" }

// TestEffectsLaneWorkBudgetIsTruncatedNotClean (DET111 FIX-T19, review P2-1
// b): a walk stopped at a counted cap of the extractor keeps what it read,
// and the call is TRUNCATED through the one truncated path
// (withBoundedTruncation), never a clean effect answer. At T19 the cut walk
// added nothing to the call.
func TestEffectsLaneWorkBudgetIsTruncatedNotClean(t *testing.T) {
	command := effectsLaneWorkCutCommand()
	if shellparse.TooDeep(command) || len(command) > effectShadowMaxCommandBytes {
		t.Fatal("the command must be within the shared input bound, so the walker reads it")
	}
	useEffectsRulesMode(t, "off")
	off := dispatchTrustedAction(context.Background(), shadowLiveRequest(command))
	useEffectsRulesMode(t, "on")
	on := dispatchTrustedAction(context.Background(), shadowLiveRequest(command))
	if !boundedCapsOf(on).Has(bounded.Effects) {
		t.Fatalf("lane on: findings %v carry no truncation at the effect cap (caps %q)", ruleIDsOf(on), boundedCapsOf(on).Reason())
	}
	limits := 0
	for _, f := range on {
		if canonicalTrustedRuleID(f.RuleID) == evaluationLimitRuleID {
			limits++
		}
	}
	if limits != 1 {
		t.Fatalf("lane on: %d evaluation-limit findings in %v, want one", limits, ruleIDsOf(on))
	}
	for _, f := range off {
		if !slices.ContainsFunc(on, func(g RuleFinding) bool { return g.RuleID == f.RuleID }) {
			t.Fatalf("lane on dropped the lane-off finding %s (off %v, on %v)", f.RuleID, ruleIDsOf(off), ruleIDsOf(on))
		}
	}
}
