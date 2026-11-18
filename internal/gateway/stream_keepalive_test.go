// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// TestGAP1307MaskHeldBedrock: the masked release (option b, GAP-1307)
// masks exactly the bytes of the open run in Bedrock frames, an invoke
// chunk (base64 Anthropic event) and a ConverseStream delta, also when the
// run is JSON-escaped or split across frames, and refuses (nothing goes
// out) when a run cannot be found in the held frames.
func TestGAP1307MaskHeldBedrock(t *testing.T) {
	s := &passthroughStream{bedrock: &bedrockEventStreamText{}}
	invoke := func(text string) []byte {
		return []byte(streamTailFrame(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":` + streamTailJSON(text) + `}}`))
	}
	invokeText := func(evs [][]byte) string {
		var sb strings.Builder
		for _, ev := range evs {
			for _, e := range streamTailUpstreamEvents(string(ev)) {
				sb.WriteString(streamTailEventText("anthropic", e))
			}
		}
		return sb.String()
	}
	converse := func(raw string) []byte {
		return []byte(gap1307ConverseFrame("contentBlockDelta", map[string]any{"contentBlockIndex": 0, "delta": map[string]any{"text": raw}, "p": "abc"}))
	}
	converseText := func(evs [][]byte) string {
		var sb strings.Builder
		for _, ev := range evs {
			sb.WriteString(gap1307ConverseText(string(ev)))
		}
		return sb.String()
	}
	type tc struct {
		name   string
		queue  [][]byte
		runs   []openRun
		text   func([][]byte) string
		want   string
		wantOK bool
	}
	for _, c := range []tc{
		{"invoke-split", [][]byte{invoke("on port 80"), invoke("80")}, []openRun{{text: "8080"}}, invokeText, "on port ****", true},
		{"converse-token", [][]byte{converse("key sk-ab"), converse("c-12")}, []openRun{{text: "sk-abc-12"}}, converseText, "key **-***-**", true},
		{"converse-not-held", [][]byte{converse("port 80")}, []openRun{{text: "8080"}}, converseText, "", false},
		{"invoke-other-text", [][]byte{invoke("version 7")}, []openRun{{text: "12"}}, invokeText, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, ok := s.maskHeld(c.queue, len(c.queue), c.runs, map[int][2]int{})
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v", ok, c.wantOK)
			}
			if ok {
				if got := c.text(out); got != c.want {
					t.Fatalf("got %q, want %q", got, c.want)
				}
			}
		})
	}
	// A run whose start went out masked before is found in part.
	out, ok := s.maskHeld([][]byte{converse("80")}, 1, []openRun{{lane: 0, start: 5, text: "8080"}}, map[int][2]int{0: {5, 7}})
	if !ok || converseText(out) != "**" {
		t.Fatalf("continued run: ok=%v got %q", ok, converseText(out))
	}
	// JSON-escaped digits are masked as the text they decode to.
	m := newRunMask([]openRun{{text: "8080"}})
	b, ok := m.maskJSON([]byte(`{"delta":{"text":"port \u00380\u00380"}}`))
	if !ok || string(b) != `{"delta":{"text":"port ****"}}` {
		t.Fatalf("escaped: ok=%v %s", ok, b)
	}
}
