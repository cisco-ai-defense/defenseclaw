// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-2224: a run parked at a block end or a tool switch (the
// streamRunParkMax park) expired only on model text, so server tool result
// blocks with no text (web_fetch, web_search, code execution results) after
// thinking that ends in a number never let it go: past streamSecretMaxHeld
// the bound gave the GAP-1767 TRUNCATED verdict, and strict and
// managed-strict cut a benign reply that rel sends. Now, at the held bound,
// a parked run that is over it only by the events read while it was parked
// that carry no model text goes out with no verdict, as on rel; below the
// bound the park still holds it (GAP-2250).

const (
	gap2224End     = "GAP2224-END-MARK"
	gap2224Results = 20       // web_fetch result blocks
	gap2224Chunk   = 60 << 10 // base64 bytes of the document in each
)

// gap2224Pieces: thinking that ends in an open digit run, its block end, a
// web_fetch server tool call, gap2224Results result blocks (a PDF document
// each, more than streamSecretMaxHeld bytes in all, no text), then an answer
// with an end marker (Anthropic passthrough wire events).
func gap2224Pieces() []string {
	pdf := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("%PDF-1.4 1 0 obj << /Type /Page >> endobj\n", gap2224Chunk/32)))[:gap2224Chunk]
	pieces := []string{
		gap2162AnthropicDelta(0, "thinking_delta", "Let me count the rows: step 3"),
		gap2162AnthropicStop(0),
		gap2162AnthropicStart(1, map[string]any{"type": "server_tool_use", "id": "srvtoolu_gap2224", "name": "web_fetch", "input": map[string]any{}}),
		gap2162Event("content_block_delta", map[string]any{"index": 1, "delta": map[string]any{"type": "input_json_delta", "partial_json": `{"url":"https://example.com/report.pdf"}`}}),
		gap2162AnthropicStop(1),
	}
	for n := 0; n < gap2224Results; n++ {
		index := 2 + n
		pieces = append(pieces,
			gap2162AnthropicStart(index, map[string]any{"type": "web_fetch_tool_result", "tool_use_id": "srvtoolu_gap2224", "content": map[string]any{
				"type": "web_fetch_result", "url": "https://example.com/report.pdf",
				"content": map[string]any{"type": "document", "source": map[string]any{"type": "base64", "media_type": "application/pdf", "data": pdf}},
			}}),
			gap2162AnthropicStop(index))
	}
	answer := 2 + gap2224Results
	return append(pieces,
		gap2162AnthropicStart(answer, map[string]any{"type": "text", "text": ""}),
		gap2162AnthropicDelta(answer, "text_delta", "The report has 12 pages. "+gap2224End+"\n"),
		gap2162AnthropicStop(answer))
}

// TestGAP2224ServerToolResultsExpireTheThinkingPark: on the Anthropic
// passthrough, in every tier, a benign reply whose thinking ends in a number
// and whose web_fetch results pass streamSecretMaxHeld goes out whole with
// no TRUNCATED verdict, as on rel (red at 02adc33853: every tier TRUNCATED,
// strict and managed-strict cut). The GAP-1767 and GAP-2218 rows keep their
// verdict.
func TestGAP2224ServerToolResultsExpireTheThinkingPark(t *testing.T) {
	path := gap0429PathsNamed(t, "passthrough/anthropic")[0]
	var rows []gap1265Row
	for _, tier := range streamTailTiers {
		rows = append(rows, gap1265Row{name: "server-tool-results-after-thinking-number", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: gap2224Pieces()})
	}
	results, log := gap1265Serve(t, path, rows)
	if n := strings.Count(log, "STREAM-TRUNCATED"); n != 0 {
		t.Errorf("%d TRUNCATED line(s) for a benign reply behind server tool results, want 0: %s", n, gap1265LogLine(log, "TRUNCATED"))
	}
	for i, row := range rows {
		res := results[i]
		if res.blocked || !strings.Contains(res.got, gap2224End) {
			t.Errorf("%s/%s/%s: a benign reply was cut or blocked (blocked=%v, %d bytes, end present=%v)", path.name, row.tier, row.name, res.blocked, len(res.got), strings.Contains(res.got, gap2224End))
		}
	}
}

// TestGAP2224ResponsesImageAfterSummaryNumberIsSent: on the OpenAI Responses
// passthrough, in every tier, a benign reply whose reasoning summary ends in
// a number, then an image_generation_call whose image (more than
// streamSecretMaxHeld of base64) only its output_item.done carries, goes out
// whole with no TRUNCATED verdict, as on rel: the image adds no model text,
// so the held bound does not count it against the parked summary run
// (CHK-T23E2224B N1; red at 517024b369: 3 TRUNCATED, strict and
// managed-strict cut).
func TestGAP2224ResponsesImageAfterSummaryNumberIsSent(t *testing.T) {
	const end = "GAP2224-IMAGE-END-MARK"
	path := gap0429PathsNamed(t, "passthrough/openai-responses")[0]
	img := streamTailImage()
	ev := func(typ string, part int, extra map[string]any) string {
		f := map[string]any{"item_id": "rs_1", "output_index": 0, "summary_index": part}
		for k, v := range extra {
			f[k] = v
		}
		return gap2162Event(typ, f)
	}
	sum := "Let me count the rows: step 3"
	pieces := []string{
		ev("response.reasoning_summary_part.added", 0, map[string]any{"part": map[string]any{"type": "summary_text", "text": ""}}),
		ev("response.reasoning_summary_text.delta", 0, map[string]any{"delta": sum}),
		ev("response.reasoning_summary_text.done", 0, map[string]any{"text": sum}),
		ev("response.reasoning_summary_part.done", 0, map[string]any{"part": map[string]any{"type": "summary_text", "text": sum}}),
		gap2162Event("response.output_item.added", map[string]any{"output_index": 1, "item": map[string]any{"type": "image_generation_call", "id": "ig_1", "status": "in_progress"}}),
		gap2162Event("response.image_generation_call.generating", map[string]any{"output_index": 1, "item_id": "ig_1"}),
		gap2162Event("response.image_generation_call.completed", map[string]any{"output_index": 1, "item_id": "ig_1"}),
		gap2162Event("response.output_item.done", map[string]any{"output_index": 1, "item": map[string]any{"type": "image_generation_call", "id": "ig_1", "status": "completed", "result": img}}),
		"The image is ready. " + end + "\n",
	}
	var rows []gap1265Row
	for _, tier := range streamTailTiers {
		rows = append(rows, gap1265Row{name: "image-after-summary-number", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: pieces})
	}
	results, log := gap1265Serve(t, path, rows)
	if n := strings.Count(log, "STREAM-TRUNCATED"); n != 0 {
		t.Errorf("%d TRUNCATED line(s) for a benign image reply, want 0: %s", n, gap1265LogLine(log, "TRUNCATED"))
	}
	for i, row := range rows {
		res := results[i]
		if res.blocked || !strings.Contains(res.got, end) {
			t.Errorf("%s/%s: a benign image reply was cut or blocked (blocked=%v, %d bytes)", path.name, row.tier, res.blocked, len(res.got))
		}
	}
}

// TestGAP2224ResponsesEncryptedReasoningOverBoundIsSent: on the OpenAI
// Responses passthrough, in every tier, a benign reply whose reasoning
// summary ends in a number, then the reasoning item's output_item.done with
// an encrypted_content over streamSecretMaxHeld, then the answer, goes out
// whole with no TRUNCATED verdict, as on rel: encrypted_content adds no
// model text, so the held bound does not count it against the parked run
// (CHK-T23E2224C N1; red at 5ca5483b49: 3 TRUNCATED, strict and
// managed-strict cut).
func TestGAP2224ResponsesEncryptedReasoningOverBoundIsSent(t *testing.T) {
	const end = "GAP2224-ENCRYPTED-END-MARK"
	path := gap0429PathsNamed(t, "passthrough/openai-responses")[0]
	sum := "Let me count the rows: step 3"
	part := func(typ string, extra map[string]any) string {
		f := map[string]any{"item_id": "rs_1", "output_index": 0, "summary_index": 0}
		for k, v := range extra {
			f[k] = v
		}
		return gap2162Event(typ, f)
	}
	answer := "The table has 3 rows. " + end
	pieces := []string{
		part("response.reasoning_summary_part.added", map[string]any{"part": map[string]any{"type": "summary_text", "text": ""}}),
		part("response.reasoning_summary_text.delta", map[string]any{"delta": sum}),
		part("response.reasoning_summary_text.done", map[string]any{"text": sum}),
		part("response.reasoning_summary_part.done", map[string]any{"part": map[string]any{"type": "summary_text", "text": sum}}),
		gap2162Event("response.output_item.done", map[string]any{"output_index": 0, "item": map[string]any{
			"type": "reasoning", "id": "rs_1", "summary": []any{map[string]any{"type": "summary_text", "text": sum}}, "encrypted_content": streamTailImage()}}),
		gap2162Event("response.output_item.added", map[string]any{"output_index": 1, "item": map[string]any{"type": "message", "id": "msg_1", "role": "assistant", "content": []any{}}}),
		gap2162Event("response.content_part.added", map[string]any{"item_id": "msg_1", "output_index": 1, "content_index": 0, "part": map[string]any{"type": "output_text", "text": ""}}),
		gap2162Event("response.output_text.delta", map[string]any{"item_id": "msg_1", "output_index": 1, "content_index": 0, "delta": answer}),
		gap2162Event("response.output_text.done", map[string]any{"item_id": "msg_1", "output_index": 1, "content_index": 0, "text": answer}),
	}
	var rows []gap1265Row
	for _, tier := range streamTailTiers {
		rows = append(rows, gap1265Row{name: "encrypted-reasoning-over-bound", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: pieces})
	}
	results, log := gap1265Serve(t, path, rows)
	if n := strings.Count(log, "STREAM-TRUNCATED"); n != 0 {
		t.Errorf("%d TRUNCATED line(s) for a benign encrypted reasoning reply, want 0: %s", n, gap1265LogLine(log, "TRUNCATED"))
	}
	for i, row := range rows {
		res := results[i]
		if res.blocked || !strings.Contains(res.got, end) {
			t.Errorf("%s/%s: a benign encrypted reasoning reply was cut or blocked (blocked=%v, %d bytes)", path.name, row.tier, res.blocked, len(res.got))
		}
	}
}
