// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"
	"testing"
)

func TestFirstAcceptedRuleMatchDoesNotEnumerateBenignTail(t *testing.T) {
	// A post-tool document may contain thousands of numbers. When the first
	// candidate is already acceptable, later matches must not cost work or
	// memory before the hook can answer.
	rule := PatternRule{ID: "ENT-PHONE-E164", Pattern: regexp.MustCompile(`[1-9][0-9]{9}`)}
	content := strings.Repeat("1234567890 ", 5000)
	want := []int{0, 10}
	if got := firstAcceptedRuleMatch(rule, content); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("first match = %v, want %v", got, want)
	}
	if allocations := testing.AllocsPerRun(3, func() { _ = firstAcceptedRuleMatch(rule, content) }); allocations > 64 {
		t.Fatalf("first accepted match allocated %.0f times while scanning later candidates", allocations)
	}
}

func TestFirstAcceptedRuleMatchStillSearchesPastRejectedCandidate(t *testing.T) {
	valid := alertFatiguePAN(t, "47", 16)
	content := "4111111111111111 " + valid
	rule := PatternRule{ID: "ENT-CC-VISA", Pattern: regexp.MustCompile(`[0-9]{16}`)}
	want := []int{17, 33}
	if got := firstAcceptedRuleMatch(rule, content); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("validated match = %v, want %v", got, want)
	}
}
