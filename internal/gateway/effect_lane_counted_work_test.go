// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

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
	t.Cleanup(setEffectShadowFaultHookIdle(t, func() { time.Sleep(effectsLaneSlowStep) }))
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

// effectsLaneCutOperands is a call of 300 file operands: within the shared
// input bound and the 1.0.10 operand bound (1024), past the extractor's
// counted effect cap (256), so the lane's walk records a cap cut.
func effectsLaneCutOperands(program, tail string) string {
	files := make([]string, 300)
	for i := range files {
		files[i] = "src/f" + strconv.Itoa(i) + ".go"
	}
	return program + " " + strings.Join(files, " ") + tail
}

// TestEffectsLaneCountedCutKeepsItsAnswer (DET111 FIX-T19, review P2-1 b, c):
// a walk stopped at a counted cap of the extractor keeps what it classified
// and says so in its record (extract_cap_exceeded), never a clean full
// answer; the call keeps every 1.0.10 finding (the floor read it under its own
// caps) and gets no new verdict from the cut, so a benign long file list
// raises nothing new. At T19 the cut record carried no reason: it read as a
// clean, fully computed run.
func TestEffectsLaneCountedCutKeepsItsAnswer(t *testing.T) {
	for _, tc := range []struct {
		name, command, tier string
	}{
		{"benign cat", effectsLaneCutOperands("cat", ""), "clean"},
		{"benign git add", effectsLaneCutOperands("git add", ""), "clean"},
		{"keys write", effectsLaneCutOperands("cat", " > /home/u/.ssh/authorized_keys"), "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if shellparse.TooDeep(tc.command) || len(tc.command) > effectShadowMaxCommandBytes {
				t.Fatal("the command must be within the shared input bound, so the walker reads it")
			}
			useEffectsRulesMode(t, "on")
			res := computeEffectShadow(shadowLiveRequest(tc.command), effectRulesOn, tierRestricted)
			if res.Reason != "extract_cap_exceeded" || res.Tier != tc.tier {
				t.Fatalf("cut run = reason %q tier %s, want extract_cap_exceeded with the classified tier %s", res.Reason, res.Tier, tc.tier)
			}
			on := dispatchTrustedAction(context.Background(), shadowLiveRequest(tc.command))
			useEffectsRulesMode(t, "off")
			off := dispatchTrustedAction(context.Background(), shadowLiveRequest(tc.command))
			for _, f := range off {
				if !slices.ContainsFunc(on, func(g RuleFinding) bool { return g.RuleID == f.RuleID && g.Severity == f.Severity }) {
					t.Fatalf("lane on dropped or changed the lane-off finding %s (off %v, on %v)", f.RuleID, ruleIDsOf(off), ruleIDsOf(on))
				}
			}
			if tc.tier == "clean" && !reflect.DeepEqual(ruleIDsOf(on), ruleIDsOf(off)) {
				t.Fatalf("benign cut call: lane on %v, lane off %v: the cut added a verdict", ruleIDsOf(on), ruleIDsOf(off))
			}
		})
	}
}
