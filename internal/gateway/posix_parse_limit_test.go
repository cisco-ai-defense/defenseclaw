// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A POSIX call whose analysis stops at a byte bound is TRUNCATED in every tier
// (rel-1-0-10:GAP-0382): an alert in the default and permissive packs (a
// managed install's included), a block in the strict pack, never an allow.
// The row ids are the case ids of the proof: just under and just over the
// word bound (4 KiB), the call bound (64 KiB) and the arguments bound
// (256 KiB), several oversize words, a here-document, a nested sh -c.
func TestPosixInputBytesAreTruncatedInEveryTier(t *testing.T) {
	word := func(n int) string { return strings.Repeat("a", n) }
	type row struct {
		id, command string
		truncated   bool
	}
	rows := []row{
		{"word-under-4096", "echo " + word(4096), false},
		{"word-over-4097", "echo " + word(4097), true},
		{"words-several-over", "echo " + word(5000) + " " + word(6000) + " " + word(7000), true},
		{"word-under-then-over-call-64k", "echo " + word(4000) + "; echo " + word(4000), false},
		{"call-over-64k-many-words", "echo" + strings.Repeat(" "+word(2000), 33), true},
		{"word-over-in-pipeline", "true | echo " + word(4097) + " | cat", true},
		{"heredoc-body-over-4k-is-not-a-word", "cat <<EOF\n" + word(8000) + "\nEOF\n", false},
		{"heredoc-call-over-64k", "cat <<EOF\n" + word(70000) + "\nEOF\n", true},
		{"nested-sh-c-word-over", "sh -c 'echo " + word(4200) + "'", true},
		{"word-over-256k", "echo " + word(262144+5), true},
		{"word-over-before-seen-write", "echo " + word(4097) + "; " + boundedShellSeen, true},
	}
	env := boundedLaneEnv(t)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, r := range rows {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(r.command))
			limited := boundedHasLimit(findings, bounded.Bytes, true)
			if limited != r.truncated {
				t.Errorf("%s/%s: truncated=%t, want %t (action %s, findings %v)", tier.name, r.id, limited, r.truncated, action, findings)
			}
			if r.truncated && boundedParse(action) < floor {
				t.Errorf("%s/%s: action %s is below the unknown tier %s", tier.name, r.id, action, floor)
			}
			if r.id == "word-over-before-seen-write" && boundedParse(action) != bounded.Block {
				t.Errorf("%s/%s: a proven write before the bound must still block, got %s", tier.name, r.id, action)
			}
		}
	}
}

// A count bound is not a byte bound: a statement of more argv words than the
// analysis keeps stays with the operand bound.
func TestShellInputPastByteBoundIgnoresCounts(t *testing.T) {
	if actionfacts.ShellInputPastByteBound("ls"+strings.Repeat(" ox", 600), 0) {
		t.Fatal("600 short words are a count, not a byte bound")
	}
	if !actionfacts.ShellInputPastByteBound("echo "+strings.Repeat("a", 4097), 0) {
		t.Fatal("a word of 4097 bytes is past the word bound")
	}
}
