// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
)

// rel-1-0-10:GAP-1306 (P3, found by review r3 of GAP-0429/1265): past
// streamSecretMaxHeld bytes held behind open token or digit runs, the stream
// paths (the /llm proxy, the passthrough stream, the raw forward) sent the
// whole hold once the check had read it. The last held piece carries the run
// still open, so a card number or a token cut at that moment had its first
// bytes out before the check that reads it whole. Now only the pieces before
// the one with the open run's first byte go out; the run stays held, and the
// next text decides it. The run is at most streamSecretMaxToken bytes, so
// the bound still makes progress, with no verdict (GAP-1265).

// gap1306Half is the text of one held piece: two of them pass
// streamSecretMaxHeld, one does not.
const gap1306Half = 600 << 10

// gap1306Rows are a card number cut right where the hold passes its bound,
// and the same stream with a benign number there, in one tier: a piece that
// ends in an open digit run, then a piece that passes the bound and ends in
// the first digits of the card (or a port number), then the rest.
func gap1306Rows(t *testing.T, tier, pack string, managed bool) []gap1265Row {
	t.Helper()
	filler := retestFiller(gap1306Half)[:gap1306Half]
	card := gap1091Value("card-visa-spaced", gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4))
	cut := card.body + 9 // "4xxx xxxx": a digit run still open
	first := filler + " took 42"
	return []gap1265Row{
		{name: "card-cut-at-held-bound", tier: tier, pack: pack, managed: managed, pieces: []string{
			first, " ms. " + filler + card.text[:cut], card.text[cut:] + " is the value. Done.\n",
		}, secret: card, wantBlocked: true},
		{name: "port-cut-at-held-bound", tier: tier, pack: pack, managed: managed, pieces: []string{
			first, " ms. " + filler + "The service listens on port 80", "80 and then it stopped.\n",
		}},
	}
}

// TestGAP1306HeldBoundKeepsTheOpenRun: in every tier, on the /llm,
// passthrough and raw forward routes, a card number whose first digits end
// the piece that passes streamSecretMaxHeld is held whole until its verdict
// (red before the fix: those digits went out with the whole hold), and the
// benign stream of the same shape reaches the client whole, with no block and
// no TRUNCATED alert.
func TestGAP1306HeldBoundKeepsTheOpenRun(t *testing.T) {
	paths := append(gap1265Paths(t), gap0429PathsNamed(t, "passthrough/"+gap0429OpenAIChat.name)...)
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			for _, tier := range streamTailTiers {
				if hookAnswerRaceBuild && !tier.blocks {
					continue
				}
				rows = append(rows, gap1306Rows(t, tier.name, tier.pack, tier.managed)...)
			}
			results, log := gap1265Serve(t, path, rows)
			for i, row := range rows {
				gap1265Check(t, path.name, row, results[i])
			}
			gap1265NoTruncated(t, path.name, log)
		})
	}
}
