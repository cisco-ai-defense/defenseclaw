// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// inlineProgramBound is the program bound of the inline perl and ruby reader
// (actionfacts maxInlineInterpreterBytes); TestBoundRuleInlineProgramPastItsBound
// checks it against the analysis.
const inlineProgramBound = 2 << 10

// inlineProgram is an ordinary perl or ruby program of exactly size bytes.
func inlineProgram(program string, size int) string {
	line := "print 1;\n"
	if program == "ruby" {
		line = "puts 1\n"
	}
	body := strings.Repeat(line, size/len(line))
	return body + strings.Repeat("#", size-len(body))
}

// The input bound of the inline program reader is a cap of the bound rule
// (cap bytes): at the bound the program is read, past it the call is
// truncated, and what was read before or after it still decides.
func init() {
	fill := func(size int) string { return "perl -e '" + inlineProgram("perl", size) + "'" }
	registerBoundedLane(boundedLaneCap{lane: "inline program bytes", cap: bounded.Bytes, limit: inlineProgramBound,
		gen: func(size int, shape boundedShape) (boundedLaneCall, bool) {
			if shape.nested || shape.multi {
				return boundedLaneCall{}, false
			}
			return boundedShellLane(fill, fill)(size, shape)
		},
		seen: boundedShellSeenCall})
}

// TestBoundRuleInlineProgramPastItsBound: input_limit alone, on an ordinary
// perl or ruby program past the 2 KiB bound of the inline reader inside a
// word under the 4 KiB byte bound, was a clean allow in all 5 tiers. It is
// the unknown tier of the ONE BOUND RULE now: an alert in the default,
// permissive and managed default tiers, a block in strict and managed strict,
// from the bound alone never more. A proven finding keeps its own verdict:
// the twin rows with the state write before or after the program block in
// every tier, as the write alone does. Under the bound the program is read
// and stays allowed (rel-1-0-10:GAP-0689, lead ruling 2026-11-15).
func TestBoundRuleInlineProgramPastItsBound(t *testing.T) {
	env := boundedLaneEnv(t)
	for _, program := range []string{"perl", "ruby"} {
		for size, limited := range map[int]bool{inlineProgramBound: false, inlineProgramBound + 1: true} {
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: program + " -e '" + inlineProgram(program, size) + "'"})
			if got := slices.Contains(facts.Parse.Issues, actionfacts.IssueInputLimit); got != limited {
				t.Fatalf("%s program of %d bytes: input_limit=%t (%v), want %t: the reader bound moved", program, size, got, facts.Parse, limited)
			}
		}
	}
	type row struct {
		id, command string
		proven      bool // the state write decides: a block in every tier
		truncated   bool
	}
	var rows []row
	for _, program := range []string{"perl", "ruby"} {
		under := program + " -e '" + inlineProgram(program, inlineProgramBound) + "'"
		past := program + " -e '" + inlineProgram(program, 3000) + "'"
		rows = append(rows,
			row{program + "-under-the-bound", under, false, false},
			row{program + "-past-the-bound", past, false, true},
			row{program + "-past-the-bound-proven-before", boundedShellSeen + "; " + past, true, true},
			row{program + "-past-the-bound-proven-after", past + "; " + boundedShellSeen, true, true},
			row{program + "-under-the-bound-proven-before", boundedShellSeen + "; " + under, true, false},
		)
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, r := range rows {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(r.command))
			limited := boundedHasLimit(findings, bounded.Bytes, true)
			if limited != r.truncated {
				t.Errorf("%s/%s: truncated=%t, want %t (action %s, findings %v)", tier.name, r.id, limited, r.truncated, action, findings)
			}
			want := bounded.Allow
			switch {
			case r.proven:
				want = gap0747StateWriteAction(tier.tier)
			case r.truncated:
				want = bounded.Unknown(tier.tier)
			}
			if got := boundedParse(action); got != want {
				t.Errorf("%s/%s: action %s, want %s (findings %v)", tier.name, r.id, action, want, findings)
			}
		}
	}
}
