// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"testing"
)

// An alternation is required to hold a literal of each of the strongest sets
// of the alternative it matches, not of one set only: a patch header holds
// ":" and so passed the fork-bomb rule on its first set, and the whole
// automaton then ran over an 889 KB patch (GAP-1040). A text of the shape a
// rule matches still passes, and a text that holds the first set only does
// not.
func TestRuleLiteralPlanOfAlternationChecksSeveralSetsPerAlternative(t *testing.T) {
	forkBomb := regexp.MustCompile(`(?i)(?:^|\s)(?::\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|perl\s+-e\s+['"]?\s*fork\s+while\s+fork\s*;?\s*['"]?|ruby\s+-e\s+['"]?\s*loop\s*\{\s*fork\s*\}\s*;?\s*['"]?)\s*$`)
	if plan := ruleRequiredLiterals(forkBomb); len(plan) < 2 {
		t.Fatalf("plan %q: want a clause for each of the strongest sets, not one", plan)
	}
	header := "*** Begin Patch\n*** Add File: /home/u/proj/notes.txt\n+" + "lorem ipsum dolor sit amet\n*** End Patch\n"
	if (&ruleScanText{text: header}).mayMatch(forkBomb) {
		t.Fatalf("a patch header with a colon and no other literal of the rule cannot match it")
	}
	for _, text := range []string{":(){ :|:& };:", "perl -e 'fork while fork'", "ruby -e 'loop { fork }'", "x\n" + ":(){ :|:& };:"} {
		if !forkBomb.MatchString(text) {
			t.Fatalf("%q: the rule no longer matches its own sample", text)
		}
		if !(&ruleScanText{text: text}).mayMatch(forkBomb) {
			t.Fatalf("%q matches the rule and was skipped", text)
		}
	}
}

// The benign twin: an alternation whose alternatives have one set each keeps
// its single clause, and a rule with an impossible alternative still skips.
func TestRuleLiteralPlanOfPlainAlternationKeepsOneClause(t *testing.T) {
	plain := regexp.MustCompile(`(?i)\b(?:alpha|bravo|charlie)\b`)
	if plan := ruleRequiredLiterals(plain); len(plan) != 1 || len(plan[0]) != 3 {
		t.Fatalf("plan %q: want one clause of the three words", plan)
	}
	if !(&ruleScanText{text: "say Bravo now"}).mayMatch(plain) || (&ruleScanText{text: "say delta now"}).mayMatch(plain) {
		t.Fatal("a word of the alternation must pass and another word must not")
	}
}
