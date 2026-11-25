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
// managed-strict cut a benign reply that rel sends. Now the bytes of the
// events that add no typed text count against the park too.

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
