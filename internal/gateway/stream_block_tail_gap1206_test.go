// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// rel-1-0-10:GAP-1206: a streamed tool call refused after reply bytes went
// out ends the stream with the block in the stream's own shape, after the
// last content block the agent got. Before the fix every SSE or NDJSON
// stream got an OpenAI chunk and [DONE], and a Bedrock tail counted the
// held (never sent) tool block in its index.

// gap1206Text is reply text sent before the call arrives.
var gap1206Text = strings.Repeat("working on it, reading the files one by one. ", 8)

// gap1206SendFirst makes the proxy send held text without an initial buffer.
func gap1206SendFirst(t *testing.T, proxy *GuardrailProxy) {
	t.Helper()
	if proxy.cfg == nil {
		t.Fatal("the test proxy has no guardrail config")
	}
	proxy.cfg.StreamBufferBytes = 1
}

// gap1206Upstream sends first, pauses past the stream hold (so the text is
// sent to the agent), then sends second.
func gap1206Upstream(t *testing.T, ctype string, first, second [][]byte) *covUpstream {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ctype)
		f, _ := w.(http.Flusher)
		for _, part := range first {
			_, _ = w.Write(part)
			f.Flush()
		}
		time.Sleep(4 * streamHoldMaxAge) // the text goes out before the call
		for _, part := range second {
			_, _ = w.Write(part)
			f.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return &covUpstream{srv: srv}
}

func gap1206SSE(events ...string) [][]byte {
	out := make([][]byte, len(events))
	for i, ev := range events {
		out[i] = []byte("data: " + ev + "\n\n")
	}
	return out
}

// gap1206Data is the data of each SSE event of out.
func gap1206Data(out string) []string {
	var data []string
	for _, ev := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n\n") {
		for _, line := range strings.Split(ev, "\n") {
			if d, ok := strings.CutPrefix(line, "data:"); ok {
				data = append(data, strings.TrimSpace(d))
			}
		}
	}
	return data
}

func gap1206NotOpenAI(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "chat.completion.chunk") || strings.Contains(out, "[DONE]") {
		t.Fatalf("the block tail is an OpenAI chunk inside a native stream:\n%s", out)
	}
	if strings.Contains(out, covBlockedTool) {
		t.Fatalf("the refused call reached the agent:\n%s", out)
	}
	if !strings.Contains(out, gap1206Text) {
		t.Fatalf("precondition: no reply text was sent before the call, so no tail:\n%.400s", out)
	}
}

func TestStreamBlockTailKeepsTheAnthropicMessageShape(t *testing.T) {
	covAllowPrivate(t)
	text, _ := json.Marshal(gap1206Text)
	name, _ := json.Marshal(covBlockedTool)
	up := gap1206Upstream(t, "text/event-stream",
		gap1206SSE(`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}}`,
			`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(text)+`}}`,
			`{"type":"content_block_stop","index":0}`),
		gap1206SSE(`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_1","name":`+string(name)+`,"input":{}}}`,
			`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"note\":\"x\"}"}}`,
			`{"type":"content_block_stop","index":1}`,
			`{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
			`{"type":"message_stop"}`))
	proxy := covProxy(t, up, "anthropic", &covInspector{})
	gap1206SendFirst(t, proxy)
	req := covJSON(t, map[string]any{"model": "dc-test-model", "stream": true, "messages": []any{map[string]any{"role": "user", "content": "hello there"}}})
	out := covPost(proxy, up, "/v1/messages", req, nil).Body.String()
	gap1206NotOpenAI(t, out)

	open, starts := -1, []int{}
	var types []string
	tailText := ""
	for _, d := range gap1206Data(out) {
		var ev struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
			Block struct {
				Type string `json:"type"`
			} `json:"content_block"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(d), &ev); err != nil {
			t.Fatalf("an event the Messages client cannot read: %q", d)
		}
		types = append(types, ev.Type)
		switch ev.Type {
		case "content_block_start":
			if open >= 0 {
				t.Fatalf("block %d starts while block %d is open:\n%s", ev.Index, open, out)
			}
			if len(starts) > 0 && ev.Index <= starts[len(starts)-1] {
				t.Fatalf("block index %d after %v:\n%s", ev.Index, starts, out)
			}
			open, starts = ev.Index, append(starts, ev.Index)
		case "content_block_stop":
			if ev.Index != open {
				t.Fatalf("block %d stops while %d is open:\n%s", ev.Index, open, out)
			}
			open = -1
		case "content_block_delta":
			if ev.Index == 1 {
				tailText += ev.Delta.Text
			}
		}
	}
	if len(types) == 0 || types[len(types)-1] != "message_stop" || open >= 0 {
		t.Fatalf("the stream does not end as one whole message (types %v, open %d):\n%s", types, open, out)
	}
	if len(starts) != 2 || starts[1] != 1 || !strings.Contains(strings.ToLower(tailText), "defenseclaw") {
		t.Fatalf("want the block as text block 1, the index after the one the agent got (starts %v, text %q):\n%s", starts, tailText, out)
	}
}

func TestStreamBlockTailKeepsTheGeminiShape(t *testing.T) {
	covAllowPrivate(t)
	text, _ := json.Marshal(gap1206Text)
	up := gap1206Upstream(t, "text/event-stream",
		gap1206SSE(`{"candidates":[{"content":{"role":"model","parts":[{"text":`+string(text)+`}]}}]}`),
		gap1206SSE(`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"`+covBlockedTool+`","args":{"note":"x"}}}]},"finishReason":"STOP"}]}`))
	proxy := covProxy(t, up, "gemini", &covInspector{})
	gap1206SendFirst(t, proxy)
	req := covJSON(t, map[string]any{"contents": []any{map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hello there"}}}}})
	out := covPost(proxy, up, "/v1beta/models/dc-test:streamGenerateContent", req, nil).Body.String()
	gap1206NotOpenAI(t, out)
	data := gap1206Data(out)
	var last struct {
		Candidates []struct {
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		Blocked bool `json:"defenseclaw_blocked"`
	}
	if len(data) == 0 || json.Unmarshal([]byte(data[len(data)-1]), &last) != nil || len(last.Candidates) != 1 ||
		last.Candidates[0].FinishReason != "SAFETY" || !last.Blocked {
		t.Fatalf("want a last Gemini frame with finishReason SAFETY and defenseclaw_blocked:\n%s", out)
	}
}

func TestStreamBlockTailKeepsTheOllamaShape(t *testing.T) {
	covAllowPrivate(t)
	line := func(v any) []byte { b, _ := json.Marshal(v); return append(b, '\n') }
	up := gap1206Upstream(t, "application/x-ndjson",
		[][]byte{line(map[string]any{"model": "x", "message": map[string]any{"role": "assistant", "content": gap1206Text}, "done": false})},
		[][]byte{line(map[string]any{"model": "x", "message": map[string]any{"role": "assistant", "content": "",
			"tool_calls": []any{map[string]any{"function": map[string]any{"name": covBlockedTool, "arguments": map[string]any{"note": "x"}}}}}, "done": false}),
			line(map[string]any{"model": "x", "message": map[string]any{"role": "assistant", "content": ""}, "done": true, "done_reason": "stop"})})
	proxy := covProxy(t, up, "ollama", &covInspector{})
	gap1206SendFirst(t, proxy)
	req := covJSON(t, map[string]any{"model": "x", "messages": []any{map[string]any{"role": "user", "content": "hello there"}}})
	out := covPost(proxy, up, "/api/chat", req, nil).Body.String()
	gap1206NotOpenAI(t, out)
	if strings.Contains(out, "data:") {
		t.Fatalf("an SSE frame inside an NDJSON stream:\n%s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var last struct {
		Done       bool   `json:"done"`
		DoneReason string `json:"done_reason"`
		Message    struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if json.Unmarshal([]byte(lines[len(lines)-1]), &last) != nil || !last.Done || last.DoneReason != "guardrail_intervened" ||
		!strings.Contains(strings.ToLower(last.Message.Content), "defenseclaw") {
		t.Fatalf("want a last /api/chat object done:true done_reason guardrail_intervened with the block:\n%s", out)
	}
}

// The Bedrock tail index counts the blocks the agent got, not the held
// tool block it never got: text block 0 was sent, the refused call was
// block 1, so the block text is block 1.
func TestBedrockBlockTailIndexFollowsTheSentBlocks(t *testing.T) {
	covAllowPrivate(t)
	text, _ := json.Marshal(gap1206Text)
	name, _ := json.Marshal(covBlockedTool)
	chunk := func(ev string) []byte {
		p, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(ev))})
		return covBedrockFrame(t, "chunk", p)
	}
	for _, st := range []struct {
		name, path    string
		first, second [][]byte
	}{
		{"invoke", "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream",
			[][]byte{chunk(`{"type":"message_start","message":{"model":"claude-haiku-4-5-20251001","usage":{"input_tokens":5}}}`),
				chunk(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`),
				chunk(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":` + string(text) + `}}`),
				chunk(`{"type":"content_block_stop","index":0}`)},
			[][]byte{chunk(`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_1","name":` + string(name) + `,"input":{}}}`),
				chunk(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"note\":\"x\"}"}}`),
				chunk(`{"type":"content_block_stop","index":1}`),
				chunk(`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":20}}`),
				chunk(`{"type":"message_stop"}`)}},
		{"converse", "/model/dc-test-model/converse-stream",
			[][]byte{covBedrockFrame(t, "messageStart", []byte(`{"role":"assistant"}`)),
				covBedrockFrame(t, "contentBlockDelta", []byte(`{"contentBlockIndex":0,"delta":{"text":`+string(text)+`}}`)),
				covBedrockFrame(t, "contentBlockStop", []byte(`{"contentBlockIndex":0}`))},
			[][]byte{covBedrockFrame(t, "contentBlockStart", []byte(`{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tu_1","name":`+string(name)+`}}}`)),
				covBedrockFrame(t, "contentBlockDelta", []byte(`{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"note\":\"x\"}"}}}`)),
				covBedrockFrame(t, "contentBlockStop", []byte(`{"contentBlockIndex":1}`)),
				covBedrockFrame(t, "messageStop", []byte(`{"stopReason":"tool_use"}`))}},
	} {
		t.Run(st.name, func(t *testing.T) {
			up := gap1206Upstream(t, "application/vnd.amazon.eventstream", st.first, st.second)
			proxy, insp := bedrockPassthroughProxy(t, up.srv)
			proxy.toolCallVerdictForTest = covToolVerdict
			insp.setVerdict("completion", allowVerdict("mock"))
			gap1206SendFirst(t, proxy)
			rec := httptest.NewRecorder()
			proxy.handlePassthrough(rec, bedrockRequest(up.srv.URL, st.path))
			out := rec.Body.Bytes()
			if !bytes.Contains(out, st.first[len(st.first)-1]) {
				t.Fatalf("precondition: the text block was not sent before the call (%d bytes)", len(out))
			}
			idx := -1
			dec := eventstream.NewDecoder()
			r := bytes.NewReader(out)
			for r.Len() > 0 {
				msg, err := dec.Decode(r, nil)
				if err != nil {
					t.Fatalf("the agent did not get whole frames: %v", err)
				}
				payload := msg.Payload
				if v := msg.Headers.Get(":event-type"); v != nil && v.String() == "chunk" {
					var c struct {
						Bytes []byte `json:"bytes"`
					}
					_ = json.Unmarshal(payload, &c)
					payload = c.Bytes
				}
				if !strings.Contains(strings.ToLower(string(payload)), "defenseclaw") {
					continue
				}
				var ev struct {
					Index      *int `json:"index"`
					BlockIndex *int `json:"contentBlockIndex"`
				}
				_ = json.Unmarshal(payload, &ev)
				switch {
				case ev.Index != nil:
					idx = *ev.Index
				case ev.BlockIndex != nil:
					idx = *ev.BlockIndex
				}
			}
			if idx != 1 {
				t.Fatalf("the block text is content block %d, want 1 (the agent got block 0 only)", idx)
			}
		})
	}
}
