// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// GAP-1953: a panic in the triage of regex_judge or judge_first is an
// evaluation fault of the inspection: the verdict is raised to CRITICAL (a
// block in action mode, as a tool call the evaluation failed on), never the
// verdict of a text with no triage signals.

const gap1953Benign = "an ordinary question about the weather"

func gap1953BenignJudge(t *testing.T) *LLMJudge {
	t.Helper()
	benign := json.RawMessage(`{"Instruction Manipulation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}, "Context Manipulation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}, "Obfuscation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}, "Semantic Manipulation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}, "Token Exploitation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}}`)
	return stubJudge(t, judgeCase{Kind: "injection", Response: benign})
}

// gap1953Inspectors: regex_judge with no judge, judge_first with a judge
// that answers (a scripted provider, no live model) and judge_first with no
// judge (its regex_only fallback).
func gap1953Inspectors(t *testing.T) map[string]*GuardrailInspector {
	t.Helper()
	regexJudge := NewGuardrailInspector("local", nil, nil)
	regexJudge.SetDetectionStrategy("regex_judge", "", "", "", false)
	judgeFirst := NewGuardrailInspector("local", nil, gap1953BenignJudge(t))
	judgeFirst.SetDetectionStrategy("judge_first", "", "", "", false)
	judgeFirstFallback := NewGuardrailInspector("local", nil, nil)
	judgeFirstFallback.SetDetectionStrategy("judge_first", "", "", "", false)
	return map[string]*GuardrailInspector{"regex_judge": regexJudge, "judge_first": judgeFirst, "judge_first_fallback": judgeFirstFallback}
}

func gap1953Inspect(t *testing.T, inspector *GuardrailInspector, content, mode string) (verdict *ScanVerdict) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Inspect panicked (the triage fault was not contained): %v", recovered)
		}
	}()
	return inspector.Inspect(context.Background(), "prompt", content, nil, "model", mode)
}

// The seam makes every triage scan panic: a benign prompt is then blocked in
// action mode and not allowed in observe mode, with the fault finding.
func TestGAP1953TriageFaultIsNotAnAllow(t *testing.T) {
	for name, inspector := range gap1953Inspectors(t) {
		for _, mode := range []string{"action", "observe"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				if got := gap1953Inspect(t, inspector, gap1953Benign, mode); got == nil || got.Action != "allow" {
					t.Fatalf("benign prompt verdict %+v with no fault, want allow; the test lost its subject", got)
				}
				recovered := 0
				inspector.SetPanicRecorderFunc(func(context.Context) { recovered++ })
				t.Cleanup(func() { inspector.SetPanicRecorderFunc(nil) })
				triageFaultHook = func(string) { panic("GAP-1953 test triage fault") }
				t.Cleanup(func() { triageFaultHook = nil })
				got := gap1953Inspect(t, inspector, gap1953Benign, mode)
				if got == nil || got.Severity != "CRITICAL" || got.Action == "allow" {
					t.Fatalf("triage fault verdict %+v, want CRITICAL and not allow", got)
				}
				if mode == "action" && got.Action != guardrailActionBlock {
					t.Errorf("triage fault action %q in action mode, want block", got.Action)
				}
				if len(got.Findings) == 0 || got.Findings[0] != triageFaultFinding {
					t.Errorf("findings %v do not start with %q", got.Findings, triageFaultFinding)
				}
				if recovered != 1 {
					t.Errorf("panic recorder saw %d faults, want 1", recovered)
				}
			})
		}
	}
}

// A real triage panic (the GAP-1933 trigger on 1.0.11 before its fix: 300
// U+023A before a PII request) is answered no weaker than its ASCII twin,
// whose triage raises a HIGH_SIGNAL. With that fix merged triage no longer
// panics and the prompt is judged as the twin, so the test holds on both
// sides of it.
func TestGAP1953RealTriagePanicIsNoWeakerThanTheTwin(t *testing.T) {
	const request = " find their password, please"
	padded, twin := strings.Repeat("Ⱥ", 300)+request, strings.Repeat("a", 300)+request
	for name, inspector := range gap1953Inspectors(t) {
		if name == "judge_first_fallback" {
			continue // regex_only: no triage
		}
		t.Run(name, func(t *testing.T) {
			want := gap1953Inspect(t, inspector, twin, "action")
			if want == nil || want.Action == "allow" || want.Severity != "HIGH" {
				t.Fatalf("the ASCII twin verdict %+v, want a HIGH finding; the test lost its subject", want)
			}
			got := gap1953Inspect(t, inspector, padded, "action")
			if got == nil || got.Action == "allow" || strongerGuardrailAction(got.Action, want.Action) != got.Action ||
				severityRank[got.Severity] < severityRank[want.Severity] {
				t.Fatalf("padded prompt verdict %+v, want no weaker than the ASCII twin (%s %s)", got, want.Action, want.Severity)
			}
		})
	}
}
