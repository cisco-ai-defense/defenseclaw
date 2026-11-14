// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// GAP-0098 and GAP-0225 together: the tool call of a Bedrock stream is held
// until the tool-call rules decide, wherever the upstream cut its reads, and
// a refused call never reaches the agent, which reads a block it can show.
// The dummy tool dc_test_blocked_tool is refused through the test-only seam
// (toolCallVerdictForTest), so the case needs no real command content.

// covBedrockStream is one scripted Bedrock stream: its frames, and the frame
// numbers (first and last, inclusive) that carry the tool call.
type covBedrockStream struct {
	name     string
	path     string
	frames   [][]byte
	toolFrom int
	toolTo   int
}

func (s covBedrockStream) wire() []byte { return bytes.Join(s.frames, nil) }

// covBedrockFrame is one eventstream "event" message.
func covBedrockFrame(t *testing.T, eventType string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: eventstream.Headers{
		{Name: ":message-type", Value: eventstream.StringValue("event")},
		{Name: ":event-type", Value: eventstream.StringValue(eventType)},
	}, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// covBedrockStreams are an InvokeModelWithResponseStream reply (Anthropic
// events in base64 chunks) and a ConverseStream reply, each with some text
// and then one tool call by name.
func covBedrockStreams(t *testing.T, tool string) []covBedrockStream {
	t.Helper()
	chunk := func(ev string) []byte {
		p, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(ev))})
		return covBedrockFrame(t, "chunk", p)
	}
	name, _ := json.Marshal(tool)
	invoke := covBedrockStream{
		name: "invoke", path: "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream",
		frames: [][]byte{
			chunk(`{"type":"message_start","message":{"model":"claude-haiku-4-5-20251001","usage":{"input_tokens":5}}}`),
			chunk(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`),
			chunk(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"working on it, one moment please"}}`),
			chunk(`{"type":"content_block_stop","index":0}`),
			chunk(`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_1","name":` + string(name) + `,"input":{}}}`),
			chunk(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"note\":"}}`),
			chunk(`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"x\"}"}}`),
			chunk(`{"type":"content_block_stop","index":1}`),
			chunk(`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":20}}`),
			chunk(`{"type":"message_stop"}`),
		},
		toolFrom: 4, toolTo: 7,
	}
	converse := covBedrockStream{
		name: "converse", path: "/model/dc-test-model/converse-stream",
		frames: [][]byte{
			covBedrockFrame(t, "messageStart", []byte(`{"role":"assistant"}`)),
			covBedrockFrame(t, "contentBlockDelta", []byte(`{"contentBlockIndex":0,"delta":{"text":"working on it, one moment please"}}`)),
			covBedrockFrame(t, "contentBlockStop", []byte(`{"contentBlockIndex":0}`)),
			covBedrockFrame(t, "contentBlockStart", []byte(`{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tu_1","name":`+string(name)+`}}}`)),
			covBedrockFrame(t, "contentBlockDelta", []byte(`{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"note\":"}}}`)),
			covBedrockFrame(t, "contentBlockDelta", []byte(`{"contentBlockIndex":1,"delta":{"toolUse":{"input":"\"x\"}"}}}`)),
			covBedrockFrame(t, "contentBlockStop", []byte(`{"contentBlockIndex":1}`)),
			covBedrockFrame(t, "messageStop", []byte(`{"stopReason":"tool_use"}`)),
		},
		toolFrom: 3, toolTo: 6,
	}
	return []covBedrockStream{invoke, converse}
}

// covBedrockCheckRefused fails when a frame of the call reached the agent or
// the reply is not a stream the agent can read with a block it can show.
func covBedrockCheckRefused(t *testing.T, s covBedrockStream, out []byte, ctx string) {
	t.Helper()
	for i := s.toolFrom; i <= s.toolTo; i++ {
		if bytes.Contains(out, s.frames[i]) {
			t.Fatalf("%s: frame %d of the refused call reached the agent", ctx, i)
		}
	}
	dec := newBedrockEventStreamText()
	text := dec.Feed(out)
	if dec.Broken() || dec.PartialLen() != 0 {
		t.Fatalf("%s: the agent did not get whole frames (broken=%v, %d bytes pending)", ctx, dec.Broken(), dec.PartialLen())
	}
	if !strings.Contains(strings.ToLower(text), "defenseclaw") {
		t.Fatalf("%s: the agent did not get a block it can show: %q", ctx, text)
	}
}

func TestPassthroughBedrockToolCallHeldAtEverySplit(t *testing.T) {
	covAllowPrivate(t)
	for _, tool := range []string{covBlockedTool, covAllowedTool} {
		for _, st := range covBedrockStreams(t, tool) {
			st, tool := st, tool
			wire := st.wire()
			t.Run(st.name+"/"+tool, func(t *testing.T) {
				var mu sync.Mutex
				var cuts []int
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					mu.Lock()
					cs := append(append([]int(nil), cuts...), len(wire))
					mu.Unlock()
					w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
					f, _ := w.(http.Flusher)
					prev := 0
					for _, c := range cs {
						_, _ = w.Write(wire[prev:c])
						f.Flush()
						prev = c
					}
				}))
				defer up.Close()
				// Both buffer sizes: the call is held before the first flush
				// (the whole block reply) and after it (the block as the last
				// text of the message under way).
				for _, buf := range []int{1, 0} {
					proxy, insp := bedrockPassthroughProxy(t, up)
					proxy.toolCallVerdictForTest = covToolVerdict
					insp.setVerdict("completion", allowVerdict("mock"))
					if proxy.cfg != nil && buf > 0 {
						proxy.cfg.StreamBufferBytes = buf
					}
					run := func(cs []int) []byte {
						mu.Lock()
						cuts = cs
						mu.Unlock()
						rec := httptest.NewRecorder()
						proxy.handlePassthrough(rec, bedrockRequest(up.URL, st.path))
						return rec.Body.Bytes()
					}
					check := func(cs []int, ctx string) {
						out := run(cs)
						if tool == covBlockedTool {
							covBedrockCheckRefused(t, st, out, ctx)
						} else if !bytes.Equal(out, wire) {
							t.Fatalf("%s: the allowed call changed (%d of %d bytes)", ctx, len(out), len(wire))
						}
					}
					for _, cut := range covCutPoints(st.frames) {
						check([]int{cut}, fmt.Sprintf("buffer=%d cut=%d", buf, cut))
					}
					every := make([]int, 0, len(wire))
					for c := 1; c < len(wire); c++ {
						every = append(every, c)
					}
					check(every, fmt.Sprintf("buffer=%d byte-by-byte", buf))
				}
			})
		}
	}
}
