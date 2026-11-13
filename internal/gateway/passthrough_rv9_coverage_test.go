// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// RV9's review of the guardrail proxy's request and reply coverage
// (GAP-0238 to GAP-0242), as committed tests. Benign marker and dummy tool
// name only.

// GAP-0238: binary media is skipped by where it sits (an image, audio or
// document field of a wire format), never by what the value looks like. The
// same value in a text position is text and is inspected.
func TestPassthroughMediaIsSkippedByPositionOnly(t *testing.T) {
	b64 := strings.Repeat("QUJDREVGR0hJSktM", 8)
	img := "data:image/png;base64," + b64
	pdf := "data:application/pdf;base64," + b64
	type tc struct {
		name string
		body string
		in   []string // must be inspected
		out  []string // binary media: must be skipped
	}
	tj := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	cases := []tc{
		{"chat image_url", `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"image_url","image_url":{"url":` + tj(img) + `}}]}]}`, []string{"hello"}, []string{b64}},
		{"responses input_image", `{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"},{"type":"input_image","image_url":` + tj(img) + `}]}]}`, []string{"hello"}, []string{b64}},
		{"responses input_file", `{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"},{"type":"input_file","filename":"a.pdf","file_data":` + tj(pdf) + `}]}]}`, []string{"hello"}, []string{b64}},
		{"anthropic image", `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + b64 + `"}}]}]}`, []string{"hello"}, []string{b64}},
		{"chat input_audio", `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"input_audio","input_audio":{"data":"` + b64 + `","format":"wav"}}]}]}`, []string{"hello"}, []string{b64}},
		{"gemini inlineData", `{"contents":[{"role":"user","parts":[{"text":"hello"},{"inlineData":{"mimeType":"image/png","data":"` + b64 + `"}}]}]}`, []string{"hello"}, []string{b64}},
		{"converse image", `{"messages":[{"role":"user","content":[{"text":"hello"},{"image":{"format":"png","source":{"bytes":"` + b64 + `"}}}]}]}`, []string{"hello"}, []string{b64}},
		{"ollama images", `{"model":"m","prompt":"hello","images":["` + b64 + `"]}`, []string{"hello"}, []string{b64}},
		// The same strings in a text position are text.
		{"data URL as system text", `{"model":"m","system":` + tj(img) + `,"messages":[{"role":"user","content":"hello"}]}`, []string{img, "hello"}, nil},
		{"data:x, as system text", `{"model":"m","system":"data:x,` + covMarker + `","messages":[{"role":"user","content":"hello"}]}`, []string{"data:x," + covMarker}, nil},
		{"data URL in a text part", `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":` + tj(img) + `}]}]}`, []string{img}, nil},
		{"long base64 as text", `{"model":"m","system":"` + b64 + `","messages":[{"role":"user","content":"hello"}]}`, []string{b64}, nil},
		{"data URL in a tool result", `{"model":"m","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"dc_test_read","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":` + tj(img) + `}]}]}`, []string{img}, nil},
		{"media type text is text even in an image field", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:text/plain;base64,` + b64 + `"}}]}]}`, []string{"data:text/plain;base64," + b64}, nil},
		{"plain URL in an image field", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/a.png"}}]}]}`, []string{"https://example.invalid/a.png"}, nil},
		// A tool call's or tool result's own payload has no protocol fields:
		// a key called status, type or user in it holds text.
		{"gemini functionResponse payload", `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"status":"` + covMarker + `","user":"` + covMarker + `-2"}}}]}]}`, []string{covMarker, covMarker + "-2"}, nil},
		{"converse toolResult json payload", `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"t1","content":[{"json":{"type":"` + covMarker + `","status":"` + covMarker + `-2"}}]}}]}]}`, []string{covMarker, covMarker + "-2"}, nil},
		{"responses function_call_output payload", `{"model":"m","input":[{"type":"function_call_output","call_id":"c1","output":{"model":"` + covMarker + `","role":"` + covMarker + `-2"}}]}`, []string{covMarker, covMarker + "-2"}, nil},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := passthroughPromptFor([]byte(c.body), false)
			all := strings.Join(got.Segments, "\n")
			for _, w := range c.in {
				if !strings.Contains(all, w) {
					t.Errorf("not inspected: %.60s (segments %.200q, unreadable %q)", w, all, got.Unreadable)
				}
			}
			for _, w := range c.out {
				if strings.Contains(all, w) {
					t.Errorf("binary media was inspected as text: %.60s", w)
				}
			}
		})
	}
}

// GAP-0238, end to end: system text and a tool result that start with
// data:<type>, reach the guardrail, in managed and OSS.
func TestPassthroughDataPrefixTextIsInspected(t *testing.T) {
	covAllowPrivate(t)
	m := "data:x," + covMarker
	bodies := map[string]map[string]any{
		"anthropic-system": {"model": "dc-test-model", "max_tokens": 16, "system": m,
			"messages": []any{map[string]any{"role": "user", "content": "hello there"}}},
		"anthropic-tool-result": {"model": "dc-test-model", "max_tokens": 16, "messages": []any{
			map[string]any{"role": "user", "content": "hello there"},
			map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "dc_test_read", "input": map[string]any{}}}},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": m}}}}},
	}
	for _, managed := range []bool{false, true} {
		for name, b := range bodies {
			t.Run(fmt.Sprintf("managed=%v/%s", managed, name), func(t *testing.T) {
				covSetManaged(t, managed)
				up := newCovUpstream(t)
				insp := &covInspector{}
				proxy := covProxy(t, up, "anthropic", insp)
				up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
				covPost(proxy, up, "/v1/messages", covJSON(t, b), nil)
				if !insp.saw("prompt") || up.count() != 0 {
					t.Errorf("text after a data: prefix was not inspected (saw=%v, upstream hits=%d)", insp.saw("prompt"), up.count())
				}
			})
		}
	}
}

// GAP-0240: a reply whose structural keys can be read two ways (a repeated
// or differently spelled key) takes the fail mode, as an ambiguous request
// does: a managed install refuses it, so the dummy blocked tool never
// reaches the agent; the OSS default forwards it with an alert.
func TestPassthroughReplyAmbiguousKeysTakeTheFailMode(t *testing.T) {
	covAllowPrivate(t)
	req := covJSON(t, map[string]any{"model": "dc-test-model", "max_tokens": 16, "messages": []any{map[string]any{"role": "user", "content": "hello there"}}})
	bedrockEvent := func(ev string) []byte {
		p, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(ev))})
		return covBedrockFrame(t, "chunk", p)
	}
	type tc struct {
		name, provider, path, ctype string
		body                        []byte
	}
	sse := func(events ...string) []byte { return covFrame(events, "lf-space") }
	cases := []tc{
		{"buffered chat function/Function", "openai", "/v1/completions", "application/json",
			[]byte(`{"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"` + covBlockedTool + `","arguments":"{}"},"Function":{"name":"` + covAllowedTool + `","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`)},
		{"buffered anthropic type/Type", "anthropic", "/v1/messages", "application/json",
			[]byte(`{"type":"message","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"` + covBlockedTool + `","input":{},"Type":"text"}]}`)},
		{"buffered anthropic repeated name", "anthropic", "/v1/messages", "application/json",
			[]byte(`{"type":"message","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"` + covBlockedTool + `","name":"` + covAllowedTool + `","input":{}}]}`)},
		{"stream anthropic content_block/Content_Block", "anthropic", "/v1/messages", "text/event-stream",
			sse(`{"type":"message_start","message":{"id":"m1","model":"x"}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"`+covBlockedTool+`","input":{}},"Content_Block":{"type":"text","text":""}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}`,
				`{"type":"content_block_stop","index":0}`, `{"type":"message_stop"}`)},
		{"stream chat delta/Delta", "openai", "/v1/completions", "text/event-stream",
			sse(`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"`+covBlockedTool+`","arguments":"{}"}}]},"Delta":{"content":"x"}}]}`,
				`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`, `[DONE]`)},
		{"bedrock invoke stream content_block/Content_Block", "bedrock", "/model/dc-test-model/invoke-with-response-stream", "application/vnd.amazon.eventstream",
			bytes.Join([][]byte{
				bedrockEvent(`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"` + covBlockedTool + `","input":{}},"Content_Block":{"type":"text","text":""}}`),
				bedrockEvent(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}`),
				bedrockEvent(`{"type":"content_block_stop","index":0}`),
				bedrockEvent(`{"type":"message_stop"}`),
			}, nil)},
	}
	for _, managed := range []bool{true, false} {
		for _, c := range cases {
			c, managed := c, managed
			t.Run(fmt.Sprintf("managed=%v/%s", managed, c.name), func(t *testing.T) {
				covSetManaged(t, managed)
				up := newCovUpstream(t)
				proxy := covProxy(t, up, c.provider, &covInspector{})
				up.set(c.ctype, "", c.body, 0)
				rec := covPost(proxy, up, c.path, req, nil)
				if managed {
					if strings.Contains(rec.Body.String(), covBlockedTool) || bytes.Contains(rec.Body.Bytes(), c.body) {
						t.Errorf("an ambiguous reply reached the agent on a managed install: %.300s", rec.Body)
					}
					if rec.Body.Len() == 0 {
						t.Errorf("the agent got an empty reply, not a block")
					}
				} else if !bytes.Equal(rec.Body.Bytes(), c.body) {
					t.Errorf("OSS default: the reply was not forwarded with an alert (%d of %d bytes)", rec.Body.Len(), len(c.body))
				}
			})
		}
	}
}

// GAP-0239: a Bedrock stream is read by the same walker as every other
// reply: any text-bearing string of any event reaches the guardrail and,
// when the guardrail blocks it, never the agent; a benign stream is
// forwarded as it was sent, at any split of the reads.
func TestPassthroughCoverageBedrockStreamProperty(t *testing.T) {
	covAllowPrivate(t)
	req := covJSON(t, map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"text": "hello there"}}}}})
	chunk := func(e string) [2]string {
		p, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(e))})
		return [2]string{"chunk", string(p)}
	}
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	type slot struct {
		name, path string
		frames     func(m string) [][2]string
	}
	converse := func(delta func(m string) string) func(m string) [][2]string {
		return func(m string) [][2]string {
			return [][2]string{{"messageStart", `{"role":"assistant"}`},
				{"contentBlockDelta", `{"contentBlockIndex":0,"delta":` + delta(m) + `}`},
				{"contentBlockStop", `{"contentBlockIndex":0}`},
				{"messageStop", `{"stopReason":"end_turn"}`}}
		}
	}
	invoke := func(delta func(m string) string, start string) func(m string) [][2]string {
		return func(m string) [][2]string {
			return [][2]string{chunk(`{"type":"message_start","message":{"model":"x"}}`),
				chunk(`{"type":"content_block_start","index":0,"content_block":` + start + `}`),
				chunk(`{"type":"content_block_delta","index":0,"delta":` + delta(m) + `}`),
				chunk(`{"type":"content_block_stop","index":0}`),
				chunk(`{"type":"message_stop"}`)}
		}
	}
	const cs = "/model/dc-test-model/converse-stream"
	const is = "/model/dc-test-model/invoke-with-response-stream"
	slots := []slot{
		{"converse-text", cs, converse(func(m string) string { return `{"text":` + q(m) + `}` })},
		{"converse-reasoning", cs, converse(func(m string) string { return `{"reasoningContent":{"text":` + q(m) + `}}` })},
		{"converse-citation", cs, converse(func(m string) string { return `{"citation":{"title":` + q(m) + `}}` })},
		{"invoke-text", is, invoke(func(m string) string { return `{"type":"text_delta","text":` + q(m) + `}` }, `{"type":"text","text":""}`)},
		{"invoke-thinking", is, invoke(func(m string) string { return `{"type":"thinking_delta","thinking":` + q(m) + `}` }, `{"type":"thinking","thinking":""}`)},
		{"invoke-model-native", is, func(m string) [][2]string {
			return [][2]string{chunk(`{"outputText":` + q(m) + `}`), chunk(`{"generation":"ok"}`)}
		}},
	}
	rnd := rand.New(rand.NewSource(0xbed0))
	for _, s := range slots {
		for _, pfx := range []string{"", "data:x,"} {
			for _, split := range []int{0, 1, 5, 17, 64 + rnd.Intn(200)} {
				s, pfx, split := s, pfx, split
				t.Run(fmt.Sprintf("%s/pfx=%s/split=%d", s.name, pfx, split), func(t *testing.T) {
					up := newCovUpstream(t)
					insp := &covInspector{}
					proxy := covProxy(t, up, "bedrock", insp)
					frames := func(m string) []byte {
						var all []byte
						for _, f := range s.frames(m) {
							all = append(all, covBedrockFrame(t, f[0], []byte(f[1]))...)
						}
						return all
					}
					up.set("application/vnd.amazon.eventstream", "", frames(pfx+covMarker), split)
					rec := covPost(proxy, up, s.path, req, nil)
					dec := newBedrockEventStreamText()
					text := dec.Feed(rec.Body.Bytes())
					if !insp.saw("completion") {
						t.Errorf("the marker never reached the guardrail")
					}
					if strings.Contains(text, covMarker) || bytes.Contains(rec.Body.Bytes(), []byte(covMarker)) {
						t.Errorf("the marker reached the agent")
					}
					// Benign: forwarded byte for byte.
					benign := frames("a harmless sentence")
					up.set("application/vnd.amazon.eventstream", "", benign, split)
					if rec := covPost(proxy, up, s.path, req, nil); !bytes.Equal(rec.Body.Bytes(), benign) {
						t.Errorf("a benign stream changed (%d of %d bytes)", rec.Body.Len(), len(benign))
					}
				})
			}
		}
	}
}

// GAP-0241: an SSE event over sseEventMax takes the fail mode as a whole.
// The OSS default forwards every byte (after the alert); a managed install
// refuses the stream and the agent reads a block, not a stream with a hole.
func TestPassthroughOversizeEventTakesTheFailMode(t *testing.T) {
	covAllowPrivate(t)
	req := covJSON(t, map[string]any{"model": "dc-test-model", "input": "hello there"})
	big, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "item_id": "m1", "delta": strings.Repeat("harmless words ", (5<<20)/15)})
	raw := covFrame([]string{`{"type":"response.created","response":{"id":"r"}}`, string(big), `{"type":"response.completed","response":{"id":"r"}}`}, "lf-space")
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprintf("managed=%v", managed), func(t *testing.T) {
			covSetManaged(t, managed)
			up := newCovUpstream(t)
			proxy := covProxy(t, up, "openai", &covInspector{})
			up.set("text/event-stream", "", raw, 0)
			rec := covPost(proxy, up, "/v1/responses", req, nil)
			if !managed {
				if !bytes.Equal(rec.Body.Bytes(), raw) {
					t.Errorf("OSS fail mode changed the stream: sent %d bytes, the agent got %d", len(raw), rec.Body.Len())
				}
				return
			}
			if strings.Contains(rec.Body.String(), "harmless words") || rec.Body.Len() == 0 {
				t.Errorf("managed: the oversized event was not refused as a whole (%d bytes)", rec.Body.Len())
			}
		})
	}
}

// GAP-0242: the framer resumes its search for a line end where the last read
// stopped; one long line in small reads is read once, not once per read.
func TestSSEFramerLongLineIsLinear(t *testing.T) {
	line := append([]byte("data: "), bytes.Repeat([]byte("a"), (4<<20)-64)...)
	line = append(line, '\n', '\n')
	start := time.Now()
	f := &sseFramer{}
	n := 0
	for off := 0; off < len(line); off += 4096 {
		n += len(f.Write(line[off:min(off+4096, len(line))], false))
	}
	if n != 1 {
		t.Fatalf("%d events, want 1", n)
	}
	if d := time.Since(start); d > 750*time.Millisecond {
		t.Errorf("a 4 MiB line took %v in 4 KiB reads", d)
	}
}
