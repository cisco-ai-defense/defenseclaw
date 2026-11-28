// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// GAP-1933: the triage evidence window was located in
// strings.ToLower(original) and cut from original. U+023A (2 bytes) lowers
// to 3 bytes, so 300 of them before a PII request put the window past the
// end of original and triagePatterns panicked: regex_judge has no recovery
// (the inspection itself panicked) and judge_first recovered the triage
// goroutine into no signals at all (triage failed open). Each prompt is now
// judged as its ASCII twin, the same text with an ASCII letter per U+023A.
func gap1933Prompts() (padded, twin string) {
	const request = " find their password, please"
	return strings.Repeat("\u023a", 300) + request, strings.Repeat("a", 300) + request
}

func gap1933Call[T any](t *testing.T, what string, call func() T) (out T) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", what, recovered)
		}
	}()
	return call()
}

func gap1933SignalKeys(signals []TriageSignal) []string {
	keys := make([]string, 0, len(signals))
	for _, signal := range signals {
		keys = append(keys, signal.Level+"/"+signal.FindingID+"/"+signal.Pattern)
	}
	slices.Sort(keys)
	return keys
}

func TestGAP1933TriageGrowingLetterKeepsTheSignals(t *testing.T) {
	padded, twin := gap1933Prompts()
	got := gap1933Call(t, "triagePatterns", func() []TriageSignal { return triagePatterns("prompt", padded) })
	want := triagePatterns("prompt", twin)
	if len(want) == 0 {
		t.Fatal("the ASCII twin raised no triage signal; the test lost its subject")
	}
	if g, w := gap1933SignalKeys(got), gap1933SignalKeys(want); !slices.Equal(g, w) {
		t.Fatalf("signals %v, want %v as for the ASCII twin", g, w)
	}
	for _, signal := range got {
		if !utf8.ValidString(signal.Evidence) || !strings.Contains(signal.Evidence, "find their password") {
			t.Errorf("%s evidence %q does not hold the match as valid UTF-8", signal.FindingID, signal.Evidence)
		}
	}
	re := regexp.MustCompile(`find their password`)
	evidence := gap1933Call(t, "extractEvidenceRegex", func() string {
		return extractEvidenceRegex(padded, normalizeForTriage(padded), re)
	})
	if !strings.Contains(evidence, "find their password") || strings.HasPrefix(evidence, "[normalized]") {
		t.Errorf("extractEvidenceRegex = %q, want the window of the original", evidence)
	}
}

// A shrinking letter (U+212A Kelvin and U+0130 lower to ASCII k and i) no
// longer cuts the window short of the match either.
func TestGAP1933TriageShrinkingLetterKeepsTheMatchInTheWindow(t *testing.T) {
	prompt := strings.Repeat("\u212a\u0130", 60) + " find their password"
	evidence := extractEvidence(prompt, normalizeForTriage(prompt), "find their password")
	if !utf8.ValidString(evidence) || !strings.HasSuffix(evidence, "find their password") {
		t.Errorf("extractEvidence = %q, want a valid window ending at the match", evidence)
	}
}

func TestGAP1933RegexJudgeGrowingLetterIsJudgedAsItsASCIITwin(t *testing.T) {
	padded, twin := gap1933Prompts()
	inspector := NewGuardrailInspector("local", nil, nil)
	ctx := context.Background()
	want := inspector.inspectRegexJudge(ctx, "prompt", twin, nil, "test", "action")
	if want == nil || want.Severity == "NONE" {
		t.Fatalf("the ASCII twin verdict %+v carries no triage finding; the test lost its subject", want)
	}
	got := gap1933Call(t, "inspectRegexJudge", func() *ScanVerdict {
		return inspector.inspectRegexJudge(ctx, "prompt", padded, nil, "test", "action")
	})
	if got == nil || got.Action != want.Action || got.Severity != want.Severity || !slices.Equal(got.Findings, want.Findings) {
		t.Fatalf("regex_judge verdict %+v, want %+v as for the ASCII twin", got, want)
	}
}

// judge_first with a judge that answers (a scripted provider: no live model)
// merges the HIGH_SIGNAL triage net into the judge's verdict. The triage
// goroutine's recovery hid the signals; it must not fire at all now.
func TestGAP1933JudgeFirstGrowingLetterKeepsTheTriageNet(t *testing.T) {
	padded, twin := gap1933Prompts()
	benign := json.RawMessage(`{"Instruction Manipulation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}, "Context Manipulation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}, "Obfuscation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}, "Semantic Manipulation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}, "Token Exploitation": {"reasoning": "n/a", "label": false, "signal_strength": "weak_signal"}}`)
	inspector := NewGuardrailInspector("local", nil, stubJudge(t, judgeCase{Kind: "injection", Response: benign}))
	inspector.SetDetectionStrategy("judge_first", "", "", "", false)
	recovered := 0
	inspector.SetPanicRecorderFunc(func(context.Context) { recovered++ })
	ctx := context.Background()
	want := inspector.Inspect(ctx, "prompt", twin, nil, "model", "action")
	if want == nil || want.Severity == "NONE" {
		t.Fatalf("the ASCII twin verdict %+v carries no triage finding; the test lost its subject", want)
	}
	got := gap1933Call(t, "judge_first Inspect", func() *ScanVerdict {
		return inspector.Inspect(ctx, "prompt", padded, nil, "model", "action")
	})
	if recovered != 0 {
		t.Errorf("judge_first recovered %d panics (the triage goroutine dropped its signals)", recovered)
	}
	if got == nil || got.Action != want.Action || got.Severity != want.Severity {
		t.Fatalf("judge_first verdict %+v, want %+v as for the ASCII twin", got, want)
	}
}
