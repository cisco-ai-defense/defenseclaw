// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// GAP-0249: a stream is held for a call the agent will execute, not for a call
// the provider runs itself (web search, file search, code interpreter, image
// generation, an MCP server the provider calls, Anthropic server and MCP
// tools). The progress events and keep-alives of such an item go through at
// once, do not count toward the 1 MiB hold cap, and the text it returns is
// still inspected. A real tool call next to it is held as before.

func covServerHeldProxy(t *testing.T, insp *covInspector) *GuardrailProxy {
	t.Helper()
	proxy := newTestProxy(t, &mockProvider{}, insp, "action")
	proxy.toolCallVerdictForTest = covToolVerdict
	return proxy
}

type covServerCase struct {
	name, path, wire string
	// open starts the server-side item and shows progress; progress is one
	// more progress event (repeated to fill the item); done ends the item.
	open     []string
	progress func(i int) string
	done     []string
	// after is the text of the reply after the item; the real call, when
	// asked for, comes after the item has ended.
	after func(m string) []string
	call  func() (open, closeEvents []string, marks []string)
	// seen is a string of the item's progress that must reach the agent
	// before the item ends.
	seen string
}

func covServerCases() []covServerCase {
	enc := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	resp := func(typ, extraOpen string, deltaType string) covServerCase {
		c := covServerCase{name: "responses/" + typ, path: "/v1/responses", wire: "openai", seen: "srv_item_1"}
		c.open = []string{`{"type":"response.output_item.added","output_index":0,"item":{"id":"srv_item_1","type":"` + typ + `","status":"in_progress"` + extraOpen + `}}`,
			`{"type":"response.` + typ + `.in_progress","output_index":0,"item_id":"srv_item_1"}`}
		c.progress = func(i int) string {
			if deltaType != "" {
				return enc(map[string]any{"type": "response." + deltaType + ".delta", "output_index": 0, "item_id": "srv_item_1", "delta": strings.Repeat("progress text. ", 40)})
			}
			return enc(map[string]any{"type": "response." + typ + ".searching", "output_index": 0, "item_id": "srv_item_1", "n": i})
		}
		c.done = []string{`{"type":"response.output_item.done","output_index":0,"item":{"id":"srv_item_1","type":"` + typ + `","status":"completed"` + extraOpen + `}}`}
		c.after = func(m string) []string {
			return []string{enc(map[string]any{"type": "response.output_text.delta", "item_id": "msg_1", "delta": m}),
				`{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`}
		}
		c.call = func() ([]string, []string, []string) {
			return []string{`{"type":"response.output_item.added","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"` + covBlockedTool + `","arguments":""}}`,
					`{"type":"response.function_call_arguments.delta","output_index":1,"item_id":"fc_1","delta":"{\"note\":"}`},
				[]string{`{"type":"response.function_call_arguments.delta","output_index":1,"item_id":"fc_1","delta":"\"x\"}"}`,
					`{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"` + covBlockedTool + `","arguments":"{\"note\":\"x\"}"}}`},
				[]string{covBlockedTool, "call_1", "fc_1"}
		}
		return c
	}
	anth := func(typ string) covServerCase {
		c := covServerCase{name: "anthropic/" + typ, path: "/v1/messages", wire: "anthropic", seen: "srv_tu_1"}
		c.open = []string{`{"type":"content_block_start","index":0,"content_block":{"type":"` + typ + `","id":"srv_tu_1","name":"web_search","input":{}}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"harmless\"}"}}`}
		c.progress = func(i int) string {
			return enc(map[string]any{"type": "ping", "n": i, "pad": strings.Repeat("keep-alive. ", 40)})
		}
		c.done = []string{`{"type":"content_block_stop","index":0}`}
		c.after = func(m string) []string {
			return []string{`{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
				enc(map[string]any{"type": "content_block_delta", "index": 1, "delta": map[string]any{"type": "text_delta", "text": m}}),
				`{"type":"content_block_stop","index":1}`, `{"type":"message_stop"}`}
		}
		c.call = func() ([]string, []string, []string) {
			return []string{`{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"real_call_1","name":"` + covBlockedTool + `","input":{}}}`,
					`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"note\":"}}`},
				[]string{`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"\"x\"}"}}`, `{"type":"content_block_stop","index":2}`},
				[]string{covBlockedTool, "real_call_1", `"type":"tool_use"`}
		}
		return c
	}
	return []covServerCase{
		resp("web_search_call", `,"action":{"type":"search","query":"harmless"}`, ""),
		resp("file_search_call", `,"queries":["harmless"]`, ""),
		resp("code_interpreter_call", `,"container_id":"cntr_1","code":""`, "code_interpreter_call_code"),
		resp("mcp_call", `,"server_label":"srv","name":"lookup","arguments":""`, "mcp_call_arguments"),
		resp("image_generation_call", "", ""),
		anth("server_tool_use"),
		anth("mcp_tool_use"),
	}
}

func TestPassthroughServerSideCallsAreNotHeld(t *testing.T) {
	covAllowPrivate(t)
	req := covJSON(t, map[string]any{"model": "dc-test-model", "input": "hello there", "max_tokens": 16, "messages": []any{map[string]any{"role": "user", "content": "hello there"}}})
	for _, c := range covServerCases() {
		for _, fr := range []string{"lf-space", "crlf", "lf-nospace"} {
			for _, size := range []int{0, 1300 << 10} { // progress inside the item: none, and past the 1 MiB hold cap
				for _, managed := range []bool{false, true} {
					c, fr, size, managed := c, fr, size, managed
					t.Run(fmt.Sprintf("%s/%s/size=%d/managed=%v", c.name, fr, size, managed), func(t *testing.T) {
						covSetManaged(t, managed)
						insp := &covInspector{}
						proxy := covServerHeldProxy(t, insp)
						text := []string{`{"type":"response.output_text.delta","item_id":"msg_0","delta":"` + strings.Repeat("working on it. ", 150) + `"}`}
						if strings.HasPrefix(c.name, "anthropic") {
							text = []string{`{"type":"content_block_start","index":9,"content_block":{"type":"text","text":""}}`,
								`{"type":"content_block_delta","index":9,"delta":{"type":"text_delta","text":"` + strings.Repeat("working on it. ", 150) + `"}}`, `{"type":"content_block_stop","index":9}`}
						}
						var sent []byte
						early, final := covHeldRun(t, proxy, c.path, c.wire, "text/event-stream", req,
							func(w io.Writer, flush func()) int {
								write := func(events []string) {
									b := covFrame(events, fr)
									if len(sent) > 0 {
										b = bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF"))
									}
									sent = append(sent, b...)
									_, _ = w.Write(b)
									flush()
								}
								write(text)
								write(c.open)
								for n, i := 0, 0; n < size; i++ {
									ev := c.progress(i)
									write([]string{ev})
									n += len(ev)
								}
								return len(sent)
							},
							func(w io.Writer, flush func()) {
								b := covFrame(append(append([]string{}, c.done...), c.after(covMarker)...), fr)
								sent = append(sent, bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF"))...)
								_, _ = w.Write(bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF")))
								flush()
							})
						if !bytes.Contains(early, []byte(c.seen)) {
							t.Errorf("the open server-side item was held: the agent has %d of %d bytes and none of its progress", len(early), len(sent))
						}
						if size > 0 && (bytes.Contains(final, []byte("could not be inspected")) || !bytes.HasPrefix(final, early)) {
							t.Errorf("the item's progress past the hold cap was refused: %.200s", final)
						}
						if !insp.saw("completion") {
							t.Errorf("the reply text after the item never reached the guardrail")
						}
					})
				}
			}
		}
	}
}

// A real call next to an open server-side item: the item's progress goes
// through, the real call is held until its verdict and never reaches the agent.
func TestPassthroughRealCallIsHeldNextToAServerSideItem(t *testing.T) {
	covAllowPrivate(t)
	req := covJSON(t, map[string]any{"model": "dc-test-model", "input": "hello there", "max_tokens": 16, "messages": []any{map[string]any{"role": "user", "content": "hello there"}}})
	for _, c := range covServerCases() {
		for _, fr := range []string{"lf-space", "crlf"} {
			for _, managed := range []bool{false, true} {
				c, fr, managed := c, fr, managed
				t.Run(fmt.Sprintf("%s/%s/managed=%v", c.name, fr, managed), func(t *testing.T) {
					covSetManaged(t, managed)
					proxy := covServerHeldProxy(t, &covInspector{})
					openCall, closeCall, marks := c.call()
					early, final := covHeldRun(t, proxy, c.path, c.wire, "text/event-stream", req,
						func(w io.Writer, flush func()) int {
							// Text past the initial buffer, then the server-side item, still open
							// when the real call starts.
							lead := []string{`{"type":"response.output_text.delta","item_id":"msg_0","delta":"` + strings.Repeat("working on it. ", 150) + `"}`}
							if strings.HasPrefix(c.name, "anthropic") {
								lead = []string{`{"type":"content_block_start","index":9,"content_block":{"type":"text","text":""}}`,
									`{"type":"content_block_delta","index":9,"delta":{"type":"text_delta","text":"` + strings.Repeat("working on it. ", 150) + `"}}`, `{"type":"content_block_stop","index":9}`}
							}
							b := covFrame(append(append(append([]string{}, lead...), c.open...), openCall...), fr)
							_, _ = w.Write(b)
							flush()
							return len(b)
						},
						func(w io.Writer, flush func()) {
							events := append(append([]string{}, closeCall...), c.done...)
							events = append(events, c.after("a harmless sentence")...)
							_, _ = w.Write(bytes.TrimPrefix(covFrame(events, fr), []byte("\xEF\xBB\xBF")))
							flush()
						})
					if !bytes.Contains(early, []byte(c.seen)) {
						t.Errorf("the server-side item was held with the real call")
					}
					for _, m := range marks {
						if bytes.Contains(early, []byte(m)) {
							t.Errorf("part of the real call reached the agent before its verdict (%q)", m)
						}
						if bytes.Contains(final, []byte(m)) {
							t.Errorf("the refused real call reached the agent (%q)", m)
						}
					}
				})
			}
		}
	}
}

// The same for a Bedrock InvokeModelWithResponseStream reply with an Anthropic
// server tool block: no hold, and the block's frames reach the agent at once.
func TestPassthroughBedrockServerToolBlockIsNotHeld(t *testing.T) {
	covAllowPrivate(t)
	chunk := func(ev string) []byte {
		p, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(ev))})
		return covBedrockFrame(t, "chunk", p)
	}
	for _, typ := range []string{"server_tool_use", "mcp_tool_use"} {
		t.Run(typ, func(t *testing.T) {
			text := chunk(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + strings.Repeat("working on it. ", 150) + `"}}`)
			open := chunk(`{"type":"content_block_start","index":1,"content_block":{"type":"` + typ + `","id":"srv_tu_1","name":"web_search","input":{}}}`)
			delta := chunk(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"query\":\"harmless\"}"}}`)
			rest := bytes.Join([][]byte{chunk(`{"type":"content_block_stop","index":1}`), chunk(`{"type":"message_stop"}`)}, nil)
			proxy := covServerHeldProxy(t, &covInspector{})
			early, final := covHeldRun(t, proxy, "/model/dc-test-model/invoke-with-response-stream", "bedrock", "application/vnd.amazon.eventstream",
				[]byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`),
				func(w io.Writer, flush func()) int {
					b := bytes.Join([][]byte{text, open, delta}, nil)
					_, _ = w.Write(b)
					flush()
					return len(b)
				},
				func(w io.Writer, flush func()) { _, _ = w.Write(rest); flush() })
			if !bytes.Contains(early, open) || !bytes.Contains(early, delta) {
				t.Errorf("the open server tool block was held (%d bytes at the agent)", len(early))
			}
			if want := bytes.Join([][]byte{text, open, delta, rest}, nil); !bytes.Equal(final, want) {
				t.Errorf("the stream changed (%d of %d bytes)", len(final), len(want))
			}
		})
	}
}
