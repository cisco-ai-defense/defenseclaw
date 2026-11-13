// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// GAP-0098 and its residual (R3a): the post-flush hold path of a Bedrock
// invoke-with-response-stream. The agent gets whole eventstream frames only,
// so a refused tool call whose start frame arrives in two reads leaves a
// stream the block text can follow (it was forwarded in part, then the block
// frames came after a half frame and the agent could not decode them).

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

func splitFrameFrame(t *testing.T, etype string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: eventstream.Headers{
		{Name: ":message-type", Value: eventstream.StringValue("event")},
		{Name: ":event-type", Value: eventstream.StringValue(etype)},
	}, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func splitFrameChunk(t *testing.T, event string) []byte {
	payload, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(event))})
	return splitFrameFrame(t, "chunk", payload)
}

// splitFrameDecode reads every frame the agent got: the decoded inner events, and
// whether the stream could be framed to its end.
func splitFrameDecode(body []byte) (string, bool) {
	dec := eventstream.NewDecoder()
	rd := bytes.NewReader(body)
	var sb strings.Builder
	for rd.Len() > 0 {
		msg, err := dec.Decode(rd, nil)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return sb.String(), false
			}
			return sb.String(), false
		}
		var c struct {
			Bytes string `json:"bytes"`
		}
		if json.Unmarshal(msg.Payload, &c) == nil && c.Bytes != "" {
			inner, _ := base64.StdEncoding.DecodeString(c.Bytes)
			sb.Write(inner)
		} else {
			sb.Write(msg.Payload)
		}
		sb.WriteString("\n")
	}
	return sb.String(), true
}

// splitFrameStream serves the parts one write and flush at a time.
func splitFrameStream(parts [][]byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		f, _ := w.(http.Flusher)
		for _, p := range parts {
			_, _ = w.Write(p)
			if f != nil {
				f.Flush()
			}
			time.Sleep(40 * time.Millisecond)
		}
	}))
}

func splitFrameInvokeParts(t *testing.T, splitStart bool) [][]byte {
	long := strings.Repeat("Looking at the instance configuration now. ", 40) // > 1024 chars: the initial buffer flushes
	lb, _ := json.Marshal(long)
	start := splitFrameChunk(t, `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"Bash","input":{}}}`)
	parts := [][]byte{
		splitFrameChunk(t, `{"type":"message_start","message":{"model":"claude-haiku-5-5","usage":{"input_tokens":5}}}`),
		append(append(splitFrameChunk(t, `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`),
			splitFrameChunk(t, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(lb)+`}}`)...),
			splitFrameChunk(t, `{"type":"content_block_stop","index":0}`)...),
	}
	if splitStart {
		parts = append(parts, start[:10], start[10:])
	} else {
		parts = append(parts, start)
	}
	return append(parts,
		splitFrameChunk(t, `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"curl -s http://169.254.169.254/"}}`),
		splitFrameChunk(t, `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"latest/meta-data/iam/security-credentials/\"}"}}`),
		splitFrameChunk(t, `{"type":"content_block_stop","index":1}`),
		splitFrameChunk(t, `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":20}}`),
		splitFrameChunk(t, `{"type":"message_stop"}`))
}

func splitFrameRun(t *testing.T, parts [][]byte, path string) []byte {
	t.Helper()
	up := splitFrameStream(parts)
	defer up.Close()
	proxy, insp := bedrockPassthroughProxy(t, up)
	insp.setVerdict("completion", allowVerdict("mock"))
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, bedrockRequest(up.URL, path))
	return rec.Body.Bytes()
}

// GAP-0098, after the first flush: the refused tool call is held and the
// agent reads a framed block (frames aligned with the reads).
func TestSplitFrameBedrockToolHeldAfterFlush(t *testing.T) {
	body := splitFrameRun(t, splitFrameInvokeParts(t, false), "/model/us.anthropic.claude-haiku-5-5/invoke-with-response-stream")
	got, framed := splitFrameDecode(body)
	if strings.Contains(got, "169.254") {
		t.Fatalf("the refused tool call reached the agent:\n%s", got)
	}
	if !framed || !strings.Contains(strings.ToLower(got), "defenseclaw") {
		t.Fatalf("no readable block: framed=%v\n%s", framed, got)
	}
}

// GAP-0098, after the first flush, the tool_use start frame split across two
// reads: the first part of the frame is forwarded before the proxy can decode
// it, the rest is held and dropped, and the block frames follow a partial
// frame, so the agent cannot frame the block (expected to fail: readable
// block shape, not a bypass).
func TestSplitFrameBedrockBlockTailAfterSplitFrame(t *testing.T) {
	body := splitFrameRun(t, splitFrameInvokeParts(t, true), "/model/us.anthropic.claude-haiku-5-5/invoke-with-response-stream")
	got, framed := splitFrameDecode(body)
	if strings.Contains(got, "169.254") {
		t.Fatalf("the refused tool call reached the agent:\n%s", got)
	}
	if !framed || !strings.Contains(strings.ToLower(got), "defenseclaw") {
		t.Fatalf("the agent cannot frame the block after a split frame: framed=%v (%d bytes)", framed, len(body))
	}
}
