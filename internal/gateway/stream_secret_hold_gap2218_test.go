// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// rel-1-0-10:GAP-2218: the GAP-1767 x GAP-2170 fix let the held bound
// release, with no verdict, every open run that was only a parked reasoning
// run. That is right for the run parked by the switch to the answer (it
// stays parked until the message ends while the answer streams, GAP-2170),
// but a reasoning run parked at a thinking block end or a switch to a tool
// call (the streamRunParkMax park) got the GAP-1767 TRUNCATED verdict at the
// train parent, and lost it. Now only the answer park is released.

const gap2218End = "GAP2218-END-MARK"

// gap2218Pieces: one thinking piece of about the held bound that ends in an
// open card digit run, the thinking block's end (the run is parked), a tool
// call whose input passes the bound well inside streamRunParkMax, then an
// answer with an end marker (Anthropic passthrough wire events).
func gap2218Pieces(t *testing.T) ([]string, gap0429Secret) {
	t.Helper()
	ev := func(typ string, fields map[string]any) string {
		fields["type"] = typ
		return gap1265Raw + "event: " + typ + "\ndata: " + streamTailJSON(fields) + "\n\n"
	}
	card := gap1091Value("card-visa-spaced", gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4))
	cut := card.body + 9 // "4xxx xxxx": a digit run still open
	// The thinking piece is just under the bound.
	n := streamSecretMaxHeld - 8<<10
	lead := "Notes: " + retestFiller(n)[:n] + " The code is "
	prefix := card.text[card.body:cut]
	own := gap0429Secret{name: card.name, class: card.class, text: lead + prefix, body: len(lead), end: len(lead) + len(prefix)}
	tool := retestFiller(6 << 10)[:6<<10]
	return []string{
		ev("content_block_delta", map[string]any{"index": 0, "delta": map[string]any{"type": "thinking_delta", "thinking": own.text}}),
		ev("content_block_stop", map[string]any{"index": 0}),
		ev("content_block_start", map[string]any{"index": 1, "content_block": map[string]any{"type": "tool_use", "id": "toolu_gap2218", "name": "notes", "input": map[string]any{}}}),
		ev("content_block_delta", map[string]any{"index": 1, "delta": map[string]any{"type": "input_json_delta", "partial_json": `{"text":"` + tool + `"}`}}),
		ev("content_block_stop", map[string]any{"index": 1}),
		ev("content_block_start", map[string]any{"index": 2, "content_block": map[string]any{"type": "text", "text": ""}}),
		ev("content_block_delta", map[string]any{"index": 2, "delta": map[string]any{"type": "text_delta", "text": "Done. " + gap2218End + "\n"}}),
	}, own
}

// TestGAP2218ToolSwitchParkedRunOverHeldBoundIsTruncated: on the Anthropic
// passthrough, in every tier, a reasoning run parked at its block end and a
// tool switch whose own held pieces pass streamSecretMaxHeld gets the bound's
// TRUNCATED verdict, as at the train parent (red at 4bdfc7c308: released
// with no verdict): the tiers that block an unknown cut the stream with none
// of the run out, the others alert once.
func TestGAP2218ToolSwitchParkedRunOverHeldBoundIsTruncated(t *testing.T) {
	path := gap0429PathsNamed(t, "passthrough/anthropic")[0]
	var rows []gap1265Row
	blocks := map[string]bool{}
	for _, tier := range streamTailTiers {
		if hookAnswerRaceBuild && !tier.blocks {
			continue
		}
		blocks[tier.name] = tier.blocks
		pieces, own := gap2218Pieces(t)
		rows = append(rows, gap1265Row{name: "tool-switch-parked-run-over-held-bound", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: pieces, secret: own})
	}
	results, log := gap1265Serve(t, path, rows)
	alerts := 0
	for _, row := range rows {
		if !blocks[row.tier] {
			alerts++
		}
	}
	if n := strings.Count(log, "STREAM-TRUNCATED"); n != alerts {
		t.Errorf("%d TRUNCATED alert(s) for a tool-switch parked run over the held bound, want %d (one per alerting tier): %s", n, alerts, gap1265LogLine(log, "TRUNCATED"))
	}
	for i, row := range rows {
		res := results[i]
		name := path.name + "/" + row.tier + "/" + row.name
		if blocks[row.tier] && (res.before > 0 || res.final > 0) {
			t.Errorf("%s: the tier blocks an unknown, but %d (before the verdict) / %d (at the end) bytes of the open run reached the client", name, res.before, res.final)
		}
		if blocks[row.tier] && strings.Contains(res.got, gap2218End) {
			t.Errorf("%s: the tier blocks an unknown, but the stream was not cut at the bound", name)
		}
	}
}
