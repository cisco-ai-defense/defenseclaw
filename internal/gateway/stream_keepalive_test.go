// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestGAP1307MaskHeldBedrock: the masked release (option b, GAP-1307)
// masks exactly the bytes of the open run in Bedrock frames, an invoke
// chunk (base64 Anthropic event) and a ConverseStream delta, also when the
// run is JSON-escaped or split across frames, and refuses (nothing goes
// out) when a run cannot be found in the held frames. A later string of a
// frame that ends like the run (Bedrock's "p" padding, an event type) never
// takes the match: the run start went out raw (GAP-1320, review s7-rv1307).
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
	alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	conversePad := func(raw, pad string) []byte {
		return []byte(gap1307ConverseFrame("contentBlockDelta", map[string]any{"contentBlockIndex": 0, "delta": map[string]any{"text": raw}, "p": pad}))
	}
	llama := func(text, pad string) []byte {
		var buf bytes.Buffer
		inner := `{"generation":` + streamTailJSON(text) + `,"stop_reason":null}`
		_ = writeBedrockEventStreamFrame(&buf, "chunk", map[string]any{"bytes": base64.StdEncoding.EncodeToString([]byte(inner)), "p": pad})
		return buf.Bytes()
	}
	llamaText := func(evs [][]byte) string {
		var sb strings.Builder
		for _, ev := range evs {
			for _, e := range streamTailUpstreamEvents(string(ev)) {
				var c struct {
					Generation string `json:"generation"`
				}
				_ = json.Unmarshal([]byte(e), &c)
				sb.WriteString(c.Generation)
			}
		}
		return sb.String()
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
		// GAP-1320: the padding of the frame holding the run start ends with
		// it (one letter, one digit, an ascending digit fragment).
		{"converse-pad-token-start", [][]byte{conversePad("key s", alpha[:19]), conversePad("k-abc-12", alpha[:3])}, []openRun{{text: "sk-abc-12"}}, converseText, "key **-***-**", true},
		{"converse-pad-card-start", [][]byte{conversePad("card 4", alpha[:57]), conversePad("111111111111111", alpha[:5])}, []openRun{{text: "4111111111111111"}}, converseText, "card ****************", true},
		{"converse-pad-card-4567", [][]byte{conversePad("card 4567", alpha[:60]), conversePad("123412341234", alpha[:5])}, []openRun{{text: "4567123412341234"}}, converseText, "card ****************", true},
		{"converse-pad-no-collision", [][]byte{conversePad("key s", alpha[:7]), conversePad("k-abc-12", alpha[:3])}, []openRun{{text: "sk-abc-12"}}, converseText, "key **-***-**", true},
		// The event type of an Anthropic invoke event (text_delta) ends with
		// the run start.
		{"invoke-type-collision", [][]byte{invoke("key ta"), invoke("12345678")}, []openRun{{text: "ta12345678"}}, invokeText, "key **********", true},
		// A Llama invoke chunk with the padding on the frame.
		{"invoke-llama-frame-pad", [][]byte{llama("key s", alpha[:19]), llama("k-abc-12", alpha[:3])}, []openRun{{text: "sk-abc-12"}}, llamaText, "key **-***-**", true},
		// A run that no text field holds is not found in the padding that
		// ends like it: nothing goes out.
		{"converse-run-only-in-pad", [][]byte{conversePad("hello", alpha[:4])}, []openRun{{text: "cd"}}, converseText, "", false},
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
	esc := []byte(gap1307ConverseFrame("contentBlockDelta", map[string]any{"contentBlockIndex": 0, "delta": json.RawMessage(`{"text":"port \u00380\u00380"}`), "p": "abc"}))
	out, ok = s.maskHeld([][]byte{esc}, 1, []openRun{{text: "8080"}}, map[int][2]int{})
	if !ok || converseText(out) != "port ****" {
		t.Fatalf("escaped: ok=%v got %q", ok, converseText(out))
	}
}
