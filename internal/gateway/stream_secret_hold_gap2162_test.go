// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"
)

// rel-1-0-10:GAP-2162 (P4, security, found by CHK-OPUS on GAP-2154): the
// GAP-2154 lane end ended an open token or digit run at a block stop, but
// the same lane can resume in a later block (text on both sides of a tool
// call, Responses summary parts). The first
// part of a token or a card cut by the stop went out once a check that
// cannot match half a secret had read it; the rest, resumed past the end,
// was not held either, so the block came after the first part had reached
// the client. rel/1.0.11 held the run across the stop. Now a block stop
// parks the run until its lane resumes, the message ends, or
// streamRunParkMax bytes of other text follow.

// gap2162Pause is longer than the hold's age bound (streamHoldMaxAge).
const gap2162Pause = 400 * time.Millisecond

// gap2162Event is one raw SSE event of type typ (Anthropic, Responses).
func gap2162Event(typ string, fields map[string]any) string {
	fields["type"] = typ
	return gap1265Raw + "event: " + typ + "\ndata: " + streamTailJSON(fields) + "\n\n"
}

func gap2162AnthropicDelta(index int, kind, text string) string {
	key := map[string]string{"text_delta": "text", "thinking_delta": "thinking"}[kind]
	return gap2162Event("content_block_delta", map[string]any{"index": index, "delta": map[string]any{"type": kind, key: text}})
}

func gap2162AnthropicStart(index int, block map[string]any) string {
	return gap2162Event("content_block_start", map[string]any{"index": index, "content_block": block})
}

func gap2162AnthropicStop(index int) string {
	return gap2162Event("content_block_stop", map[string]any{"index": index})
}

// gap2162Split is one secret cut in two: first ends the piece before the
// stop, rest starts the piece after it.
type gap2162Split struct {
	name        string
	secret      gap0429Secret
	first, rest string
	wantBlocked bool
}

func gap2162Splits(t *testing.T) []gap2162Split {
	t.Helper()
	// The value is measured from the VALUE: label, which only this text
	// has: a token from its first byte (the rule prefix counts), a card
	// from its first digit.
	const label = "VALUE: "
	tok := gap0429Tokens(t)[0]
	card := gap1091Value("card-visa-spaced", gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4))
	tokS := gap0429Secret{name: tok.name, class: tok.class, text: label + tok.text, body: len(label), end: len(label) + tok.end}
	cardS := gap0429Secret{name: card.name, class: card.class, text: label + card.text, body: len(label) + card.body, end: len(label) + card.end}
	half := len(label) + tok.body + (tok.end-tok.body)/2
	cut := len(label) + card.body + 10 // "4xxx xxxx ": the run still open
	return []gap2162Split{
		{name: "token", secret: tokS, first: tokS.text[:half], rest: tokS.text[half:]},
		{name: "card", secret: cardS, first: cardS.text[:cut], rest: cardS.text[cut:], wantBlocked: true},
	}
}

// gap2162Rows are the splits of one path: a block stop between the two
// halves on the routes that have one, an interleaved other lane on the
// chat routes (a guard: no stop there).
func gap2162Rows(t *testing.T, path, tier, pack string, managed bool) []gap1265Row {
	t.Helper()
	var rows []gap1265Row
	// The first piece is past the initial stream buffer, so what a check
	// passes goes out at once, and the upstream is idle before the piece
	// that resumes the value (at), so a released first half reaches the
	// client before the rest is read.
	lead := retestFiller(2048)[:2048] + " "
	add := func(name string, s gap2162Split, pieces []string, at int) {
		rows = append(rows, gap1265Row{name: name + "/" + s.name, tier: tier, pack: pack, managed: managed,
			pieces: pieces, at: at, pause: gap2162Pause, secret: s.secret, wantBlocked: s.wantBlocked})
	}
	for _, s := range gap2162Splits(t) {
		switch path {
		case "passthrough/anthropic":
			add("across-a-tool-call", s, []string{
				gap2162AnthropicDelta(0, "text_delta", lead+"Here it is. "+s.first),
				gap2162AnthropicStop(0),
				gap2162AnthropicStart(1, map[string]any{"type": "tool_use", "id": "toolu_1", "name": "Read", "input": map[string]any{}}),
				gap2162Event("content_block_delta", map[string]any{"index": 1, "delta": map[string]any{"type": "input_json_delta", "partial_json": `{"path":"notes.txt"}`}}),
				gap2162AnthropicStop(1),
				gap2162AnthropicStart(2, map[string]any{"type": "text", "text": ""}),
				gap2162AnthropicDelta(2, "text_delta", s.rest+" is it.\n"),
			}, 6)
		case "passthrough/openai-responses":
			summary := func(part int, text string) string {
				return gap2162Event("response.reasoning_summary_text.delta", map[string]any{"item_id": "rs_1", "output_index": 0, "summary_index": part, "delta": text})
			}
			partDone := func(part int) string {
				return gap2162Event("response.reasoning_summary_part.done", map[string]any{"item_id": "rs_1", "output_index": 0, "summary_index": part})
			}
			add("across-summary-parts", s, []string{
				summary(0, lead+"I read it. "+s.first), partDone(0),
				summary(1, s.rest+" is the one."), partDone(1),
				"Done.\n",
			}, 2)
		default:
			add("across-an-interleaved-choice", s, []string{
				lead + "Here it is. " + s.first,
				gap1265Choice1 + "The other choice says hello. ",
				s.rest + " is it.\n",
			}, 2)
		}
	}
	return rows
}

// TestGAP2162SecretSplitAcrossABlockStopIsHeld: on the /llm, raw forward
// and passthrough (OpenAI chat, Anthropic, OpenAI Responses) routes, in
// every tier, a token or a card cut by a block stop (a tool call, a
// Responses summary part) or by another choice's text has no byte out before
// its verdict, and a card is blocked once whole. GAP-2166 covers the
// separate reasoning-to-answer boundary.
func TestGAP2162SecretSplitAcrossABlockStopIsHeld(t *testing.T) {
	paths := gap0429PathsNamed(t, "llm", "raw-forward", "passthrough/"+gap0429OpenAIChat.name, "passthrough/anthropic", "passthrough/openai-responses")
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			for _, tier := range streamTailTiers {
				if hookAnswerRaceBuild && !tier.blocks {
					continue
				}
				rows = append(rows, gap2162Rows(t, path.name, tier.name, tier.pack, tier.managed)...)
			}
			results, log := gap1265Serve(t, path, rows)
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
			gap1265NoTruncated(t, path.name, log)
		})
	}
}
