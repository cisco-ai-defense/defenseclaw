// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1767 (P3, security, the GAP-1306 residual): past
// streamSecretMaxHeld bytes held behind an open token or digit run, the
// stream paths send the held pieces before the one with the run's first
// byte, and the run stays held (GAP-1306). When the pieces from the run's
// first byte are over the bound themselves (the run's lane gets no text while
// another lane streams, or one piece is that large), they all went out with
// the run's first bytes and no verdict. Now the bound decides the run
// (TRUNCATED, the unknown tier of the pack): the tiers that block on an
// unknown cut the stream before a byte of the run goes out, the others alert
// and send, and the run's rule still decides it once whole.

// gap1767Filler is one piece of the other lane: a few of them pass
// streamSecretMaxHeld while the card's lane is quiet.
const gap1767Filler = 64 << 10

// gap1767Rows: a card number whose first digits end the only piece of its
// lane (choice 0) before the other lane (choice 1) streams more than
// streamSecretMaxHeld, then the rest of the card.
func gap1767Rows(t *testing.T, tier, pack string, managed bool) []gap1265Row {
	t.Helper()
	card := gap1091Value("card-visa-spaced", gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4))
	cut := card.body + 9 // "4xxx xxxx": a digit run still open
	pieces := []string{"The code is " + card.text[:cut]}
	filler := retestFiller(gap1767Filler)[:gap1767Filler]
	for n := 0; n <= streamSecretMaxHeld; n += len(filler) {
		pieces = append(pieces, gap1265Choice1+filler)
	}
	pieces = append(pieces, card.text[cut:]+" is the value. Done.\n")
	return []gap1265Row{{name: "card-quiet-lane-over-held-bound", tier: tier, pack: pack, managed: managed,
		pieces: pieces, secret: card, wantBlocked: true}}
}

// TestGAP1767RunOverHeldBoundIsTruncated: in every tier, on the /llm, raw
// forward and passthrough (OpenAI chat) routes, a card number whose own
// held pieces pass streamSecretMaxHeld gets the bound's TRUNCATED verdict
// (red before the fix: no verdict, and its first digits went out in every
// tier): a tier that blocks an unknown cuts the stream at the bound with
// none of its bytes out; the others alert once and block the card once
// whole.
func TestGAP1767RunOverHeldBoundIsTruncated(t *testing.T) {
	for _, path := range gap0429PathsNamed(t, "llm", "raw-forward", "passthrough/"+gap0429OpenAIChat.name) {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			blocks := map[string]bool{}
			for _, tier := range streamTailTiers {
				if hookAnswerRaceBuild && !tier.blocks {
					continue
				}
				blocks[tier.name] = tier.blocks
				rows = append(rows, gap1767Rows(t, tier.name, tier.pack, tier.managed)...)
			}
			results, log := gap1265Serve(t, path, rows)
			// The reason is redacted in the log, so the verdict is the
			// alert line of each tier that alerts on an unknown (and the
			// cut, below, of each one that blocks).
			alerts := 0
			for _, row := range rows {
				if !blocks[row.tier] {
					alerts++
				}
			}
			if n := strings.Count(log, "STREAM-TRUNCATED"); n != alerts {
				t.Errorf("%s: %d TRUNCATED alert(s) for a run over the held bound, want %d (one per alerting tier): %s", path.name, n, alerts, gap1265LogLine(log, "TRUNCATED"))
			}
			for i, row := range rows {
				res := results[i]
				name := path.name + "/" + row.tier + "/" + row.name
				n := row.secret.end - row.secret.body
				if !blocks[row.tier] && !res.blocked {
					t.Errorf("%s: the card is not blocked once whole", name)
				}
				if blocks[row.tier] && (res.before > 0 || res.final > 0) {
					t.Errorf("%s: the tier blocks an unknown, but %d (before the verdict) / %d (at the end) of %d value bytes reached the client", name, res.before, res.final, n)
				}
				if blocks[row.tier] && strings.Contains(res.got, "is the value. Done.") {
					t.Errorf("%s: the tier blocks an unknown, but the stream was not cut at the bound", name)
				}
			}
		})
	}
}

// gap1767Table is a reply of large pieces that each end in a number, so a
// digit run is open at every piece end and the hold passes
// streamSecretMaxHeld behind runs that the next piece closes (the GAP-1306
// path: the pieces before the run fit the bound). Few large pieces keep the
// raw forward, which checks the whole text at every frame, under the
// request deadline.
func gap1767Table() []string {
	filler := retestFiller(gap1767Filler)[:gap1767Filler]
	var pieces []string
	for i, n := 0, 0; n <= streamSecretMaxHeld+gap1767Filler; i++ {
		p := " " + filler + fmt.Sprintf(" row %d", 10+i)
		pieces = append(pieces, p)
		n += len(p)
	}
	return append(pieces, " Total done.\n")
}

// gap1767CheckTable is the GAP-1767 rule on a benign reply whose hold passes
// streamSecretMaxHeld behind open runs: one TRUNCATED alert per tier that
// alerts on an unknown, with the whole reply sent; each tier that blocks an
// unknown cuts the stream before its end.
func gap1767CheckTable(t *testing.T, label string, rows []gap1265Row, results []gap1265Result, log string, blocks map[string]bool) {
	t.Helper()
	alerts := 0
	for _, row := range rows {
		if !blocks[row.tier] {
			alerts++
		}
	}
	if n := strings.Count(log, "STREAM-TRUNCATED"); n != alerts {
		t.Errorf("%s: %d TRUNCATED alert(s) for a reply held over the bound, want %d (one per alerting tier): %s", label, n, alerts, gap1265LogLine(log, "TRUNCATED"))
	}
	for i, row := range rows {
		res := results[i]
		want := strings.Join(row.pieces, "")
		name := label + "/" + row.tier + "/" + row.name
		switch {
		case !blocks[row.tier] && (res.got != want || res.blocked):
			t.Errorf("%s: the tier alerts on an unknown, but the client got %d of %d bytes, blocked=%v", name, len(res.got), len(want), res.blocked)
		case blocks[row.tier] && res.got == want:
			t.Errorf("%s: the tier blocks an unknown, but the whole reply went out with no cut", name)
		}
	}
}

// TestGAP1767NumericTableOverHeldBoundIsTruncated: on the /llm, raw forward
// and passthrough (OpenAI chat, Anthropic) routes, a reply held over
// streamSecretMaxHeld behind open digit runs gets the bound's TRUNCATED
// verdict once (LEAD ruling 2026-11-26 21:00Z on GAP-1767 and GAP-1265). Red
// at f6e151801a: the pieces before the run went out with no verdict in every
// tier (GAP-1306), so the cap hit reached the call with no bounded.Truncated.
func TestGAP1767NumericTableOverHeldBoundIsTruncated(t *testing.T) {
	table := gap1767Table()
	for _, path := range gap0429PathsNamed(t, "llm", "raw-forward", "passthrough/"+gap0429OpenAIChat.name, "passthrough/anthropic") {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			blocks := map[string]bool{}
			for _, tier := range streamTailTiers {
				if hookAnswerRaceBuild && !tier.blocks {
					continue
				}
				blocks[tier.name] = tier.blocks
				rows = append(rows, gap1265Row{name: "numeric-table-large-pieces", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: table})
			}
			results, log := gap1265Serve(t, path, rows)
			gap1767CheckTable(t, path.name, rows, results, log, blocks)
		})
	}
}
