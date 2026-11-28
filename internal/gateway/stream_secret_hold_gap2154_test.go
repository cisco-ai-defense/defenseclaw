// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// rel-1-0-10:GAP-2154 (P3, regression vs rel/1.0.10, found by CHK-OPUS on
// GAP-1767): nothing ended a token or digit run open at the end of a lane
// when the lane itself ended (a thinking block that ends "step 3", a choice
// that finishes with "total 42"). Every later piece of the other lanes was
// held behind it: the client saw nothing more until streamSecretMaxHeld
// bytes or the end, where rel/1.0.10 streamed it live, and past the bound
// (GAP-1767) strict and managed-strict cut a benign reply and the other
// tiers alerted. Now the provider's lane-end signal, or the next lane of the
// same choice, ends the run: the check has read it whole, so a card there
// is still blocked before any of it goes out.

const (
	gap2154Alpha = "ALPHA-MARK"
	gap2154Beta  = "BETA-MARK"
	gap2154End   = "The end of the long answer."
)

// gap2154Filler is one piece of the long answer: a few pass
// streamSecretMaxHeld.
const gap2154Filler = 64 << 10

// gap2154Lead is the first lane, ending in an open digit run (or in tail,
// a card number), then the signal that ends it, in the path's shape; the
// later pieces go to the other lane.
func gap2154Lead(t *testing.T, path, tail string) []string {
	t.Helper()
	if path == "passthrough/anthropic" {
		ev := func(typ string, fields map[string]any) string {
			fields["type"] = typ
			return gap1265Raw + "event: " + typ + "\ndata: " + streamTailJSON(fields) + "\n\n"
		}
		return []string{
			ev("content_block_delta", map[string]any{"index": 0, "delta": map[string]any{"type": "thinking_delta", "thinking": "Let me count the rows: " + tail}}),
			ev("content_block_stop", map[string]any{"index": 0}),
			ev("content_block_start", map[string]any{"index": 1, "content_block": map[string]any{"type": "text", "text": ""}}),
		}
	}
	return []string{"Let me count the rows: " + tail, gap1265Finish0}
}

// gap2154Later is a piece of the other lane (the answer block, or choice 1).
func gap2154Later(path, text string) string {
	if path == "passthrough/anthropic" {
		return text
	}
	return gap1265Choice1 + text
}

func gap2154Rows(t *testing.T, path, tier, pack string, managed bool) []gap1265Row {
	t.Helper()
	// Freeze: the later lane's first piece must reach the client before its
	// second piece is read (red: held behind the ended lane's "42").
	freeze := append(gap2154Lead(t, path, "total 42"),
		// Past the initial stream buffer (stream_buffer_bytes), so it goes
		// out on its own once read; well inside streamRunParkMax, so a
		// parked reasoning run holds it (GAP-2162 round 3).
		gap2154Later(path, "First part "+retestFiller(2048)[:2048]+" "+gap2154Alpha+". "),
		gap2154Later(path, "second part "+gap2154Beta+". "+gap2154End+"\n"))
	// Over the held bound: a benign long answer behind the ended lane's
	// "step 3" (red: strict cut it, the other tiers raised TRUNCATED).
	long := gap2154Lead(t, path, "step 3")
	filler := retestFiller(gap2154Filler)[:gap2154Filler]
	for n := 0; n <= streamSecretMaxHeld; n += len(filler) {
		long = append(long, gap2154Later(path, filler))
	}
	long = append(long, gap2154Later(path, gap2154End+"\n"))
	// Protection: a card that ends its lane is blocked once the lane ends,
	// before any of it goes out.
	card := gap1091Value("card-visa-spaced", gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4))
	cardRow := append(gap2154Lead(t, path, card.text[card.body:card.end]), gap2154Later(path, "ok. "+gap2154End+"\n"))
	beta := gap0429Secret{name: "beta-mark", class: "marker", text: gap2154Beta, end: len(gap2154Beta)}
	digits := card.text[card.body:card.end]
	cardOwn := gap0429Secret{name: card.name, class: card.class, text: "rows: " + digits, body: len("rows: "), end: len("rows: ") + len(digits)}
	return []gap1265Row{
		{name: "ended-lane-freeze", tier: tier, pack: pack, managed: managed, pieces: freeze, secret: beta},
		{name: "ended-lane-over-held-bound", tier: tier, pack: pack, managed: managed, pieces: long},
		{name: "card-ends-its-lane", tier: tier, pack: pack, managed: managed, pieces: cardRow, secret: cardOwn, wantBlocked: true},
	}
}

// TestGAP2154EndedLaneEndsItsRun: on the /llm, raw forward and passthrough
// (OpenAI chat: a choice's finish_reason; Anthropic: a thinking block's
// content_block_stop) routes, in every tier, a card that ends its lane is
// blocked with none of it out. OpenAI streams later answer text live. An
// unresolved Anthropic thinking run and its later answer remain queued in
// wire order, preserving the signed thinking bytes (GAP-2170).
func TestGAP2154EndedLaneEndsItsRun(t *testing.T) {
	paths := gap0429PathsNamed(t, "llm", "raw-forward", "passthrough/"+gap0429OpenAIChat.name, "passthrough/anthropic")
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			for _, tier := range streamTailTiers {
				if hookAnswerRaceBuild && !tier.blocks {
					continue
				}
				rows = append(rows, gap2154Rows(t, path.name, tier.name, tier.pack, tier.managed)...)
			}
			results, log := gap1265Serve(t, path, rows)
			for i, row := range rows {
				res := results[i]
				name := path.name + "/" + row.tier + "/" + row.name
				switch row.name {
				case "card-ends-its-lane":
					if !res.blocked {
						t.Errorf("%s: a card that ends its lane is not blocked", name)
					}
					if n := gap0429Released(res.snapRaw, row.secret); n > 0 {
						t.Errorf("%s: %d card bytes reached the client before the verdict", name, n)
					}
					if n := gap0429Released(res.bodyRaw, row.secret); n > 0 {
						t.Errorf("%s: blocked, but %d card bytes reached the client", name, n)
					}
				default:
					if res.blocked || !strings.Contains(res.got, gap2154End) {
						t.Errorf("%s: a benign reply was cut or blocked (blocked=%v, %d bytes, end present=%v)", name, res.blocked, len(res.got), strings.Contains(res.got, gap2154End))
					}
					if row.name == "ended-lane-freeze" {
						if path.name == "passthrough/anthropic" {
							// Thinking can be signed. Its unresolved run and the following
							// answer remain queued in wire order until the verdict.
							if strings.Contains(res.snapRaw, gap2154Alpha) || !strings.Contains(res.bodyRaw, "total 42") {
								t.Errorf("%s: signed thinking was released early or changed", name)
							}
						} else if !strings.Contains(res.snapRaw, gap2154Alpha) {
							t.Errorf("%s: the answer's first piece was still held behind the ended lane when its second piece was read (client had %d bytes)", name, len(res.snapRaw))
						}
					}
				}
			}
			gap1265NoTruncated(t, path.name, log)
		})
	}
}
