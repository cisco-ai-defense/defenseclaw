// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"math/rand"
	"testing"
)

// rel-1-0-10:GAP-2250 (CHK-T23E-P48): a secret split across two answer
// lane halves with a non-text item between them stays held until it is
// whole, as on rel: the bytes that carry no model text (an encrypted
// reasoning item, an image item, an Anthropic web_fetch result) must not end
// the park of the first half. GAP-2224's park spend (4a64bc1aa8 ..
// 0ad2294ebf) let 22 of 40 token and 10 of 19 card bytes out first; GAP-2224
// is now decided at the held bound instead.

func gap2250B64(n int, seed int64) string {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return "gAAAAA" + base64.StdEncoding.EncodeToString(b)[:n]
}

func gap2250ResponsesPieces(s gap2162Split, enc string) []string {
	lead := retestFiller(2048)[:2048] + " "
	t0 := lead + "Here it is. " + s.first
	t1 := s.rest + " is it."
	msg := func(oi int, id string) []string {
		return []string{
			gap2162Event("response.output_item.added", map[string]any{"output_index": oi, "item": map[string]any{"type": "message", "id": id, "role": "assistant", "status": "in_progress", "content": []any{}}}),
			gap2162Event("response.content_part.added", map[string]any{"item_id": id, "output_index": oi, "content_index": 0, "part": map[string]any{"type": "output_text", "text": ""}}),
		}
	}
	done := func(oi int, id, text string) []string {
		return []string{
			gap2162Event("response.output_text.done", map[string]any{"item_id": id, "output_index": oi, "content_index": 0, "text": text}),
			gap2162Event("response.content_part.done", map[string]any{"item_id": id, "output_index": oi, "content_index": 0, "part": map[string]any{"type": "output_text", "text": text}}),
			gap2162Event("response.output_item.done", map[string]any{"output_index": oi, "item": map[string]any{"type": "message", "id": id, "role": "assistant", "status": "completed",
				"content": []any{map[string]any{"type": "output_text", "text": text}}}}),
		}
	}
	var p []string
	p = append(p, msg(0, "msg_1")...)
	p = append(p, gap2162Event("response.output_text.delta", map[string]any{"item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": t0}))
	p = append(p, done(0, "msg_1", t0)...)
	p = append(p,
		gap2162Event("response.output_item.added", map[string]any{"output_index": 1, "item": map[string]any{"type": "reasoning", "id": "rs_1", "summary": []any{}}}),
		gap2162Event("response.output_item.done", map[string]any{"output_index": 1, "item": map[string]any{"type": "reasoning", "id": "rs_1", "summary": []any{}, "encrypted_content": enc}}))
	p = append(p, msg(2, "msg_2")...)
	// index 9: the piece that resumes the value (the pause is before it)
	p = append(p, gap2162Event("response.output_text.delta", map[string]any{"item_id": "msg_2", "output_index": 2, "content_index": 0, "delta": t1}))
	p = append(p, done(2, "msg_2", t1)...)
	return p
}

func gap2250Run(t *testing.T, pathName string, build func(gap2162Split, string) []string, at int) {
	path := gap0429PathsNamed(t, pathName)[0]
	var rows []gap1265Row
	for _, tier := range streamTailTiers {
		for _, s := range gap2162Splits(t) {
			for _, sz := range []struct {
				name string
				n    int
			}{{"enc-16k", 16 << 10}, {"enc-2k", 2 << 10}} {
				rows = append(rows, gap1265Row{name: sz.name + "/" + s.name, tier: tier.name, pack: tier.pack, managed: tier.managed,
					pieces: build(s, gap2250B64(sz.n, 7)), at: at, pause: gap2162Pause, secret: s.secret, wantBlocked: s.wantBlocked})
			}
		}
	}
	results, _ := gap1265Serve(t, path, rows)
	for i, row := range rows {
		res := results[i]
		name := path.name + "/" + row.tier + "/" + row.name
		n := row.secret.end - row.secret.body
		before, final := gap0429Released(res.snapRaw, row.secret), gap0429Released(res.bodyRaw, row.secret)
		t.Logf("ROW %s: before=%d/%d final=%d blocked=%v", name, before, n, final, res.blocked)
		if before > 0 {
			t.Errorf("%s: %d of %d value bytes reached the client before the verdict", name, before, n)
		}
		if res.blocked && final > 0 {
			t.Errorf("%s: blocked, but %d of %d value bytes reached the client", name, final, n)
		}
		if row.wantBlocked && !res.blocked {
			t.Errorf("%s: the value is not blocked once whole", name)
		}
	}
}

// TestGAP2250ResponsesSplitAcrossEncryptedReasoning: every tier, 16 KiB and
// 2 KiB items.
func TestGAP2250ResponsesSplitAcrossEncryptedReasoning(t *testing.T) {
	gap2250Run(t, "passthrough/openai-responses", gap2250ResponsesPieces, 9)
}

// The answer split across two Responses message items with an
// image_generation_call item (its result only in its output_item.done, media
// the walker skips) between them.
func gap2250ImagePieces(s gap2162Split, img string) []string {
	p := gap2250ResponsesPieces(s, "")
	// replace the reasoning item (pieces 5 and 6) with an image item
	p[5] = gap2162Event("response.output_item.added", map[string]any{"output_index": 1, "item": map[string]any{"type": "image_generation_call", "id": "ig_1", "status": "in_progress"}})
	p[6] = gap2162Event("response.output_item.done", map[string]any{"output_index": 1, "item": map[string]any{"type": "image_generation_call", "id": "ig_1", "status": "completed", "result": img}})
	return p
}

func TestGAP2250ResponsesSplitAcrossImageItem(t *testing.T) {
	gap2250Run(t, "passthrough/openai-responses", gap2250ImagePieces, 9)
}

// An Anthropic answer split across two text blocks with a web_fetch server
// tool call and its result (a base64 PDF, no text) between them.
func gap2250WebFetchPieces(s gap2162Split, doc string) []string {
	lead := retestFiller(2048)[:2048] + " "
	return []string{
		gap2162AnthropicDelta(0, "text_delta", lead+"Here it is. "+s.first),
		gap2162AnthropicStop(0),
		gap2162AnthropicStart(1, map[string]any{"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_fetch", "input": map[string]any{}}),
		gap2162Event("content_block_delta", map[string]any{"index": 1, "delta": map[string]any{"type": "input_json_delta", "partial_json": `{"url":"https://example.com/r.pdf"}`}}),
		gap2162AnthropicStop(1),
		gap2162AnthropicStart(2, map[string]any{"type": "web_fetch_tool_result", "tool_use_id": "srvtoolu_1", "content": map[string]any{
			"type": "web_fetch_result", "url": "https://example.com/r.pdf",
			"content": map[string]any{"type": "document", "source": map[string]any{"type": "base64", "media_type": "application/pdf", "data": doc}},
		}}),
		gap2162AnthropicStop(2),
		gap2162AnthropicStart(3, map[string]any{"type": "text", "text": ""}),
		gap2162AnthropicDelta(3, "text_delta", s.rest+" is it.\n"),
		gap2162AnthropicStop(3),
	}
}

func TestGAP2250AnthropicSplitAcrossWebFetch(t *testing.T) {
	gap2250Run(t, "passthrough/anthropic", gap2250WebFetchPieces, 8)
}
