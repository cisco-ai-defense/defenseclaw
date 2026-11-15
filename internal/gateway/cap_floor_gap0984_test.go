// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap0984JoinedQuotes is one statement of n joined quoted words: a quoted
// opener line, a quoted quote, ... (the drain shape of the GAP-0913 review).
func gap0984JoinedQuotes(n int) string {
	return "tool '" + strings.Repeat("cat <<'\"'\"'E'\"'\"'\n", n) + "E\nit's (x)\necho after"
}

// gap0984ManyWords is one shell statement of n quoted words, each after a
// blank: every word is a new reading of a growing prefix.
func gap0984ManyWords(n int) string {
	return "bash -c 'true'" + strings.Repeat(" 'a'", n)
}

// rel-1-0-10:GAP-0984. The cap floor read the consumer of every quoted word
// by parsing its statement from the start, so a statement of n joined quotes
// cost n parses of a growing prefix: 0.9 s at 9 KiB and 14.5 s at 36 KiB per
// hook call, past the hook answer budget. A word that only grows keeps the
// reading that already ruled a shell -c out: the cost no longer grows with n.
func TestGAP0984CapFloorJoinedQuotesAreOneReading(t *testing.T) {
	charged := map[int]int{}
	for _, n := range []int{500, 4000} {
		command := gap0984JoinedQuotes(n)
		reader := &capFloorConsumerReader{budget: capFloorConsumerBytes}
		capFloorCut(command, reader, 0, len(command))
		if reader.unread {
			t.Fatalf("n=%d: the consumer reads ran out of budget", n)
		}
		charged[n] = capFloorConsumerBytes - reader.budget
	}
	if charged[4000] != charged[500] {
		t.Errorf("consumer bytes parsed grow with the quotes: %v", charged)
	}
}

// rel-1-0-10:GAP-0984. Readings that cannot be kept are charged to
// capFloorConsumerBytes; past it nothing more is parsed and the cut reports
// the cap (TRUNCATED: the unknown tier of the pack, never an allow).
func TestGAP0984CapFloorConsumerBudgetIsACap(t *testing.T) {
	command := gap0984ManyWords(2000)
	reader := &capFloorConsumerReader{budget: capFloorConsumerBytes}
	capFloorCut(command, reader, 0, len(command))
	if !reader.unread || reader.budget < 0 {
		t.Fatalf("unread=%v budget=%d, want the budget spent and reported", reader.unread, reader.budget)
	}
	if _, _, unread := capFloorPieces(command, ""); !unread {
		t.Fatal("capFloorPieces does not report the spent budget")
	}
	env := boundedLaneEnv(t)
	call := command + "\ncat <<'EOF' > notes.txt\n" + gap0486Blocked["B1"] + "\nEOF"
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(call))
		got := boundedParse(action)
		if want := bounded.Unknown(tier.tier); bounded.Stricter(got, want) != got {
			t.Errorf("%s: action=%s, want at least %v; findings=%v", tier.name, action, want, findings)
		}
	}
}
