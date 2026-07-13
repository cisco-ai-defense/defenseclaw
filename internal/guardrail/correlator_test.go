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

package guardrail

import (
	"testing"
)

func TestLoadCorrelationPatterns_Defaults(t *testing.T) {
	set, err := DefaultCorrelationPatterns()
	if err != nil {
		t.Fatalf("LoadCorrelationPatterns: %v", err)
	}
	want := map[string]bool{
		"LETHAL-TRIFECTA":                 true,
		"TRIFECTA-WITH-FINGERPRINT-MATCH": true,
		"ESCALATION-CHAIN":                true,
		"DESTRUCTIVE-FLOW":                true,
	}
	if len(set.Patterns) != len(want) {
		t.Errorf("got %d patterns, want %d", len(set.Patterns), len(want))
	}
	for _, p := range set.Patterns {
		if !want[p.ID] {
			t.Errorf("unexpected pattern id %q", p.ID)
		}
		if p.SeverityOnMatch != "CRITICAL" {
			t.Errorf("pattern %q severity_on_match = %q, want CRITICAL", p.ID, p.SeverityOnMatch)
		}
		if p.WindowEvents <= 0 {
			t.Errorf("pattern %q window_events = %d, should default to positive", p.ID, p.WindowEvents)
		}
	}
}

func TestLethalTrifecta_FiresOnAllThreeAxes(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()
	pattern := mustFindPattern(t, set, "LETHAL-TRIFECTA")

	// Newest-first window (as ListRecentFindingsInSession returns); the
	// temporal order is ingress (oldest) -> sensitive -> egress (newest),
	// which is the exfil direction LETHAL-TRIFECTA now requires.
	window := []CorrelationFinding{
		{ID: "f-003", DataAxis: []DataAxis{AxisEgressExternal}, Severity: "HIGH"},
		{ID: "f-002", DataAxis: []DataAxis{AxisSensitiveAccess}, Severity: "HIGH"},
		{ID: "f-001", DataAxis: []DataAxis{AxisIngressUntrusted}, Severity: "HIGH"},
	}

	contributing := pattern.Match(window)
	if len(contributing) != 3 {
		t.Fatalf("expected 3 contributing findings, got %d", len(contributing))
	}
	// Contributing is returned in temporal (oldest-first) order.
	if contributing[0].ID != "f-001" || contributing[1].ID != "f-002" || contributing[2].ID != "f-003" {
		t.Errorf("expected temporal order f-001,f-002,f-003; got %+v", contributing)
	}
}

func TestLethalTrifecta_DoesNotFireWithoutAllAxes(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()
	pattern := mustFindPattern(t, set, "LETHAL-TRIFECTA")

	// Missing egress_external
	window := []CorrelationFinding{
		{ID: "f-002", DataAxis: []DataAxis{AxisSensitiveAccess}, Severity: "HIGH"},
		{ID: "f-001", DataAxis: []DataAxis{AxisIngressUntrusted}, Severity: "HIGH"},
	}

	if got := pattern.Match(window); got != nil {
		t.Errorf("expected no match, got %+v", got)
	}
}

func TestMatchOrderedAllOf(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()
	pattern := mustFindPattern(t, set, "LETHAL-TRIFECTA")
	if !pattern.Ordered {
		t.Fatalf("LETHAL-TRIFECTA expected to be ordered")
	}

	// In temporal order: ingress (oldest) -> sensitive -> egress (newest).
	// Window is newest-first, so egress is at index 0.
	inOrder := []CorrelationFinding{
		{ID: "f-003", DataAxis: []DataAxis{AxisEgressExternal}, Severity: "HIGH"},
		{ID: "f-002", DataAxis: []DataAxis{AxisSensitiveAccess}, Severity: "HIGH"},
		{ID: "f-001", DataAxis: []DataAxis{AxisIngressUntrusted}, Severity: "HIGH"},
	}
	contributing := pattern.Match(inOrder)
	if len(contributing) != 3 {
		t.Fatalf("in-order window: expected 3 contributing, got %d: %+v", len(contributing), contributing)
	}
	if contributing[0].ID != "f-001" || contributing[1].ID != "f-002" || contributing[2].ID != "f-003" {
		t.Errorf("in-order window: expected temporal order f-001,f-002,f-003; got %+v", contributing)
	}

	// Same three axes, reversed temporal order: egress (oldest) ->
	// sensitive -> ingress (newest). The exfil direction is violated,
	// so an ordered pattern must NOT fire even though all axes present.
	reversed := []CorrelationFinding{
		{ID: "f-003", DataAxis: []DataAxis{AxisIngressUntrusted}, Severity: "HIGH"},
		{ID: "f-002", DataAxis: []DataAxis{AxisSensitiveAccess}, Severity: "HIGH"},
		{ID: "f-001", DataAxis: []DataAxis{AxisEgressExternal}, Severity: "HIGH"},
	}
	if got := pattern.Match(reversed); got != nil {
		t.Errorf("reversed-order window: expected no match for ordered pattern, got %+v", got)
	}

	// Sanity: the same reversed window WOULD match if the pattern were
	// unordered, confirming the order constraint is what rejects it.
	unordered := *pattern
	unordered.Ordered = false
	if got := unordered.Match(reversed); len(got) != 3 {
		t.Errorf("reversed-order window: unordered variant should match all 3, got %+v", got)
	}
}

func TestEscalationChain_FiresInOrder(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()
	pattern := mustFindPattern(t, set, "ESCALATION-CHAIN")

	// Window is newest-first; temporal order is oldest-first.
	// MEDIUM at turn 1 -> HIGH at turn 2 -> HIGH at turn 3.
	window := []CorrelationFinding{
		{ID: "t3", Severity: "HIGH"},
		{ID: "t2", Severity: "HIGH"},
		{ID: "t1", Severity: "MEDIUM"},
	}

	contributing := pattern.Match(window)
	if len(contributing) != 3 {
		t.Fatalf("expected 3 contributing, got %d: %+v", len(contributing), contributing)
	}
	if contributing[0].ID != "t1" || contributing[1].ID != "t2" || contributing[2].ID != "t3" {
		t.Errorf("sequence order wrong; got %+v", contributing)
	}
}

func TestEscalationChain_DoesNotFireOnAllHighs(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()
	pattern := mustFindPattern(t, set, "ESCALATION-CHAIN")

	// No MEDIUM to start the chain.
	window := []CorrelationFinding{
		{ID: "t3", Severity: "HIGH"},
		{ID: "t2", Severity: "HIGH"},
		{ID: "t1", Severity: "HIGH"},
	}

	if got := pattern.Match(window); got != nil {
		t.Errorf("expected no match, got %+v", got)
	}
}

func TestDestructiveFlow_FiresOnExecShellAfterSensitive(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()
	pattern := mustFindPattern(t, set, "DESTRUCTIVE-FLOW")

	window := []CorrelationFinding{
		{
			ID:                  "f-003",
			RuleID:              "SHELL-DESTRUCTIVE-RM-RF",
			Severity:            "CRITICAL",
			ToolCapabilityClass: CapExecShell,
		},
		{
			ID:       "f-002",
			RuleID:   "PATH-SSH-KEY",
			Severity: "HIGH",
			DataAxis: []DataAxis{AxisSensitiveAccess},
		},
	}

	contributing := pattern.Match(window)
	if len(contributing) != 2 {
		t.Fatalf("expected 2 contributing, got %d: %+v", len(contributing), contributing)
	}
}

func TestDestructiveFlow_DoesNotFireWithoutSensitiveAccess(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()
	pattern := mustFindPattern(t, set, "DESTRUCTIVE-FLOW")

	window := []CorrelationFinding{
		{
			ID:                  "f-001",
			RuleID:              "SHELL-DESTRUCTIVE-RM-RF",
			Severity:            "CRITICAL",
			ToolCapabilityClass: CapExecShell,
		},
	}

	if got := pattern.Match(window); got != nil {
		t.Errorf("expected no match (destructive alone is not a flow), got %+v", got)
	}
}

func TestFingerprintChain_RequiresSameFingerprint(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()
	pattern := mustFindPattern(t, set, "TRIFECTA-WITH-FINGERPRINT-MATCH")

	// Same fingerprint across sensitive_access + egress_external.
	match := []CorrelationFinding{
		{ID: "f-002", DataAxis: []DataAxis{AxisEgressExternal}, ContentFingerprint: "abc12345", Severity: "HIGH"},
		{ID: "f-001", DataAxis: []DataAxis{AxisSensitiveAccess}, ContentFingerprint: "abc12345", Severity: "HIGH"},
	}
	if got := pattern.Match(match); len(got) != 2 {
		t.Errorf("matching fingerprints: expected 2 contributing, got %+v", got)
	}

	// Different fingerprints — must NOT match.
	nomatch := []CorrelationFinding{
		{ID: "f-002", DataAxis: []DataAxis{AxisEgressExternal}, ContentFingerprint: "zzz99999", Severity: "HIGH"},
		{ID: "f-001", DataAxis: []DataAxis{AxisSensitiveAccess}, ContentFingerprint: "abc12345", Severity: "HIGH"},
	}
	if got := pattern.Match(nomatch); got != nil {
		t.Errorf("different fingerprints should not match, got %+v", got)
	}
}

func TestEvaluate_ReturnsAllMatchingPatterns(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()

	// Window that triggers LETHAL-TRIFECTA — and nothing else.
	window := []CorrelationFinding{
		{ID: "f-003", DataAxis: []DataAxis{AxisEgressExternal}, Severity: "HIGH"},
		{ID: "f-002", DataAxis: []DataAxis{AxisSensitiveAccess}, Severity: "HIGH"},
		{ID: "f-001", DataAxis: []DataAxis{AxisIngressUntrusted}, Severity: "HIGH"},
	}

	matches := Evaluate(set.Patterns, window)
	seen := map[string]bool{}
	for _, m := range matches {
		seen[m.Pattern.ID] = true
	}
	if !seen["LETHAL-TRIFECTA"] {
		t.Errorf("expected LETHAL-TRIFECTA to fire, matches=%+v", seen)
	}
}

func TestSyntheticFindingRuleID(t *testing.T) {
	m := CorrelationMatch{Pattern: CorrelationPattern{ID: "lethal-trifecta"}}
	if got := m.SyntheticFindingRuleID(); got != "CORR-LETHAL-TRIFECTA" {
		t.Errorf("SyntheticFindingRuleID = %q, want CORR-LETHAL-TRIFECTA", got)
	}
}

func TestWindowSizeIsRespected(t *testing.T) {
	set, _ := DefaultCorrelationPatterns()
	pattern := mustFindPattern(t, set, "ESCALATION-CHAIN")

	// ESCALATION-CHAIN has window_events: 10. Put the MEDIUM outside
	// the window so it should NOT contribute.
	var window []CorrelationFinding
	for i := 0; i < 10; i++ {
		window = append(window, CorrelationFinding{ID: "high", Severity: "HIGH"})
	}
	// Oldest (outside window): the MEDIUM that would complete the chain.
	window = append(window, CorrelationFinding{ID: "medium-out-of-window", Severity: "MEDIUM"})

	if got := pattern.Match(window); got != nil {
		t.Errorf("medium outside window should not complete the chain, got %+v", got)
	}
}

func mustFindPattern(t *testing.T, set *CorrelationPatternSet, id string) *CorrelationPattern {
	t.Helper()
	for i := range set.Patterns {
		if set.Patterns[i].ID == id {
			return &set.Patterns[i]
		}
	}
	t.Fatalf("pattern %q not found", id)
	return nil
}
