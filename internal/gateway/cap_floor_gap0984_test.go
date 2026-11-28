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
	env := boundedLaneEnvAnyOS(t)
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

// TestGAP0984CapFloorPlainWordReuse covers the review's ANSI-C scratch
// case and words whose earlier reading can or cannot safely be reused.
func TestGAP0984CapFloorPlainWordReuse(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		wantBody     bool
		wantReads    int
	}{
		{"review-ANSI-C", "bash $'-c'", true, 2},
		{"plain-option", "bash '-c'", true, 2},
		{"plain-data", "tool arg'data'", false, 1},
		{"plain-double", "tool arg'one'\"data\"", false, 1},
		{"plain-joined", "tool arg'data'\"more\"", false, 1},
		{"escaped-join", "tool arg'a'\\''b'", false, 2},
		{"ANSI-C-data", "tool $'data'", false, 2},
		{"locale-data", "tool arg'one'$\"data\"", false, 2},
		{"escaped-data", "tool \\x'data'", false, 2},
		{"expanded-data", "tool $HOME'data'", false, 2},
		{"tilde-data", "tool ~'data'", false, 2},
		{"glob-data", "tool *'data'", false, 2},
		{"brace-data", "tool {x,y}'data'", false, 2},
		{"double-expansion", "tool arg'one'\"$HOME\"", false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := tc.prefix + "'true'"
			reader := &capFloorConsumerReader{budget: capFloorConsumerBytes}
			pieces := capFloorCut(command, reader, 0, len(command))
			found := false
			for _, piece := range pieces {
				if piece.body == "true" {
					found = true
				}
			}
			if found != tc.wantBody {
				t.Errorf("script piece=%v, want %v", found, tc.wantBody)
			}
			// Every case starts its first quoted word at the same offset
			// as its first quote. Nonplain words must also read the prefix
			// at the final quote, even if it previously ruled a shell out.
			first := strings.IndexAny(command, "'\"")
			want := first
			if tc.wantReads == 2 {
				want += len(tc.prefix)
			}
			if got := capFloorConsumerBytes - reader.budget; got != want {
				t.Errorf("charged=%d, want %d", got, want)
			}
			if reader.unread {
				t.Fatal("unexpected budget refusal")
			}
		})
	}
}
