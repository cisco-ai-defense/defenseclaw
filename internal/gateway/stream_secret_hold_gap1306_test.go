// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
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
// the bound still makes progress. The bound itself takes the TRUNCATED
// verdict of the unknown tier once per call (rel-1-0-10:GAP-1767, LEAD
// ruling 2026-11-26 21:00Z): a cap hit never goes out with no verdict.

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
// (red before the fix: those digits went out with the whole hold). The cap
// hit takes the TRUNCATED verdict once per row (GAP-1767): a tier that
// blocks an unknown cuts the stream there with none of the card out; the
// others alert once, block the card once whole, and send the benign stream
// of the same shape whole.
func TestGAP1306HeldBoundKeepsTheOpenRun(t *testing.T) {
	paths := append(gap1265Paths(t), gap0429PathsNamed(t, "passthrough/"+gap0429OpenAIChat.name)...)
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			blocks := map[string]bool{}
			for _, tier := range streamTailTiers {
				if hookAnswerRaceBuild && !tier.blocks {
					continue
				}
				blocks[tier.name] = tier.blocks
				rows = append(rows, gap1306Rows(t, tier.name, tier.pack, tier.managed)...)
			}
			results, log := gap1265Serve(t, path, rows)
			alerts := 0
			for i, row := range rows {
				res := results[i]
				if !blocks[row.tier] {
					alerts++
					gap1265Check(t, path.name, row, res)
					continue
				}
				name := path.name + "/" + row.tier + "/" + row.name
				if row.secret.text != "" && (res.before > 0 || res.final > 0) {
					t.Errorf("%s: the tier blocks an unknown, but %d (before the verdict) / %d (at the end) value bytes reached the client", name, res.before, res.final)
				}
				if res.got == strings.Join(row.pieces, "") {
					t.Errorf("%s: the tier blocks an unknown, but the stream was not cut at the held bound", name)
				}
			}
			if n := strings.Count(log, "STREAM-TRUNCATED"); n != alerts {
				t.Errorf("%s: %d TRUNCATED alert(s) at the held bound, want %d (one per row of an alerting tier): %s", path.name, n, alerts, gap1265LogLine(log, "TRUNCATED"))
			}
		})
	}
}
