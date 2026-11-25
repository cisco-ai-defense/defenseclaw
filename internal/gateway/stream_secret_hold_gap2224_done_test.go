// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// rel-1-0-10:GAP-2224 (CHK-T23E2224 B1): the GAP-2162 Responses summary-part
// split, with the .done events carrying the part text as OpenAI sends them
// (text.done and part.done repeat the part). Those repeats are snapshot
// bytes: they must not spend the park, or the parked half of a split secret
// goes out before its verdict (red at 4a64bc1aa8 in every tier: 22 of 40
// token bytes, 10 of 19 card bytes; the parent 5e0f22d418 held them).
func gap2224DoneRows(t *testing.T, tier, pack string, managed bool) []gap1265Row {
	t.Helper()
	var rows []gap1265Row
	lead := retestFiller(6000)[:6000] + " "
	for _, s := range gap2162Splits(t) {
		p0 := lead + "I read it. " + s.first
		p1 := s.rest + " is the one."
		ev := func(typ string, part int, extra map[string]any) string {
			f := map[string]any{"item_id": "rs_1", "output_index": 0, "summary_index": part}
			for k, v := range extra {
				f[k] = v
			}
			return gap2162Event(typ, f)
		}
		pieces := []string{
			ev("response.reasoning_summary_text.delta", 0, map[string]any{"delta": p0}),
			ev("response.reasoning_summary_text.done", 0, map[string]any{"text": p0}),
			ev("response.reasoning_summary_part.done", 0, map[string]any{"part": map[string]any{"type": "summary_text", "text": p0}}),
			ev("response.reasoning_summary_part.added", 1, map[string]any{"part": map[string]any{"type": "summary_text", "text": ""}}),
			ev("response.reasoning_summary_text.delta", 1, map[string]any{"delta": p1}),
			ev("response.reasoning_summary_text.done", 1, map[string]any{"text": p1}),
			ev("response.reasoning_summary_part.done", 1, map[string]any{"part": map[string]any{"type": "summary_text", "text": p1}}),
			"Done.\n",
		}
		rows = append(rows, gap1265Row{name: "done-repeats/" + s.name, tier: tier, pack: pack, managed: managed,
			pieces: pieces, at: 4, pause: gap2162Pause, secret: s.secret, wantBlocked: s.wantBlocked})
	}
	return rows
}

// TestGAP2224ResponsesDoneRepeatsKeepTheSplitHeld: on the OpenAI Responses
// passthrough, in every tier, a secret split across two summary parts whose
// .done events repeat the part text stays held until it is whole, and none
// of its value reaches the client before the verdict.
func TestGAP2224ResponsesDoneRepeatsKeepTheSplitHeld(t *testing.T) {
	gap2224CheckDoneRows(t, gap2224DoneRows)
}

func gap2224CheckDoneRows(t *testing.T, rowsOf func(t *testing.T, tier, pack string, managed bool) []gap1265Row) {
	t.Helper()
	path := gap0429PathsNamed(t, "passthrough/openai-responses")[0]
	var rows []gap1265Row
	for _, tier := range streamTailTiers {
		if hookAnswerRaceBuild && !tier.blocks {
			continue
		}
		rows = append(rows, rowsOf(t, tier.name, tier.pack, tier.managed)...)
	}
	results, _ := gap1265Serve(t, path, rows)
	for i, row := range rows {
		res := results[i]
		name := path.name + "/" + row.tier + "/" + row.name
		n := row.secret.end - row.secret.body
		t.Logf("%s: before=%d final=%d blocked=%v", name, gap0429Released(res.snapRaw, row.secret), gap0429Released(res.bodyRaw, row.secret), res.blocked)
		if b := gap0429Released(res.snapRaw, row.secret); b > 0 {
			t.Errorf("%s: %d of %d value bytes reached the client before the verdict", name, b, n)
		}
		if b := gap0429Released(res.bodyRaw, row.secret); res.blocked && b > 0 {
			t.Errorf("%s: blocked, but %d of %d value bytes reached the client", name, b, n)
		}
		if row.wantBlocked && !res.blocked {
			t.Errorf("%s: the value is not blocked once whole", name)
		}
	}
}
