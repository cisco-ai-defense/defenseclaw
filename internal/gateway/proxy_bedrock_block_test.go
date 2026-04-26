// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	eventstream "github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

func TestBedrockActionFromPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{"converse-stream", "/model/global.amazon.nova-2-lite-v1%3A0/converse-stream", "converse-stream"},
		{"converse (decoded)", "/model/global.amazon.nova-2-lite-v1:0/converse", "converse"},
		{"invoke", "/model/anthropic.claude-3-5-sonnet-20240620-v1:0/invoke", "invoke"},
		{"invoke-with-response-stream", "/model/foo/invoke-with-response-stream", "invoke-with-response-stream"},
		{"apply-guardrail-skipped", "/guardrail/abc/version/1/apply", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bedrockActionFromPath(tc.path)
			if got != tc.want {
				t.Errorf("bedrockActionFromPath(%q) = %q; want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestBedrockModelFromPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{"encoded colon", "/model/global.amazon.nova-2-lite-v1%3A0/converse-stream", "global.amazon.nova-2-lite-v1:0"},
		{"decoded", "/model/anthropic.claude-3-5-sonnet-20240620-v1:0/invoke", "anthropic.claude-3-5-sonnet-20240620-v1:0"},
		{"no match", "/v1/chat/completions", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bedrockModelFromPath(tc.path)
			if got != tc.want {
				t.Errorf("bedrockModelFromPath(%q) = %q; want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestWriteBlockedResponseBedrockConverse(t *testing.T) {
	p := &GuardrailProxy{}
	rec := httptest.NewRecorder()

	p.writeBlockedResponseBedrockConverse(rec, "amazon.nova-lite-v1:0", "blocked by DefenseClaw")

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q; want application/json", got)
	}
	if got := rec.Header().Get("X-DefenseClaw-Blocked"); got != "true" {
		t.Fatalf("X-DefenseClaw-Blocked = %q; want true", got)
	}

	var resp struct {
		Output struct {
			Message struct {
				Role    string `json:"role"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"message"`
		} `json:"output"`
		StopReason         string `json:"stopReason"`
		DefenseClawBlocked bool   `json:"defenseclaw_blocked"`
		DefenseClawReason  string `json:"defenseclaw_reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if resp.Output.Message.Role != "assistant" {
		t.Errorf("role = %q; want assistant", resp.Output.Message.Role)
	}
	if len(resp.Output.Message.Content) != 1 || resp.Output.Message.Content[0].Text != "blocked by DefenseClaw" {
		t.Errorf("content text = %+v; want [{Text: blocked by DefenseClaw}]", resp.Output.Message.Content)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("stopReason = %q; want end_turn", resp.StopReason)
	}
	if !resp.DefenseClawBlocked || resp.DefenseClawReason != "blocked by DefenseClaw" {
		t.Errorf("missing defenseclaw metadata: %+v", resp)
	}
}

// TestWriteBlockedStreamBedrockConverseRoundTrip feeds the frames produced by
// the Bedrock stream writer back through the AWS SDK's event-stream decoder
// to verify the binary framing is exactly what the client-side AWS SDK
// expects. A mismatch here is precisely what caused the client to error
// with "Truncated event message received".
func TestWriteBlockedStreamBedrockConverseRoundTrip(t *testing.T) {
	p := &GuardrailProxy{}
	rec := httptest.NewRecorder()

	p.writeBlockedStreamBedrockConverse(rec, "amazon.nova-lite-v1:0", "blocked by DefenseClaw")

	if got := rec.Header().Get("Content-Type"); got != "application/vnd.amazon.eventstream" {
		t.Fatalf("Content-Type = %q; want application/vnd.amazon.eventstream", got)
	}
	if got := rec.Header().Get("X-DefenseClaw-Blocked"); got != "true" {
		t.Fatalf("X-DefenseClaw-Blocked = %q; want true", got)
	}

	decoder := eventstream.NewDecoder()
	r := bytes.NewReader(rec.Body.Bytes())

	wantOrder := []string{
		"messageStart",
		"contentBlockDelta",
		"contentBlockStop",
		"messageStop",
		"metadata",
	}
	var (
		gotTypes    []string
		deltaText   string
		stopReason  string
		messageMeta = map[string]any{}
	)
	for i := 0; i < len(wantOrder)+1; i++ {
		msg, err := decoder.Decode(r, nil)
		if err != nil {
			break
		}
		et := msg.Headers.Get(":event-type")
		if et == nil {
			t.Fatalf("frame %d missing :event-type header", i)
		}
		if mt := msg.Headers.Get(":message-type"); mt == nil || mt.String() != "event" {
			t.Fatalf("frame %d :message-type = %v; want event", i, mt)
		}
		if ct := msg.Headers.Get(":content-type"); ct == nil || ct.String() != "application/json" {
			t.Fatalf("frame %d :content-type = %v; want application/json", i, ct)
		}
		gotTypes = append(gotTypes, et.String())

		var payload map[string]any
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			t.Fatalf("frame %d payload not valid JSON: %v\nraw=%q", i, err, msg.Payload)
		}
		switch et.String() {
		case "contentBlockDelta":
			if d, ok := payload["delta"].(map[string]any); ok {
				if s, ok := d["text"].(string); ok {
					deltaText = s
				}
			}
		case "messageStop":
			if s, ok := payload["stopReason"].(string); ok {
				stopReason = s
			}
			messageMeta = payload
		}
	}

	if len(gotTypes) != len(wantOrder) {
		t.Fatalf("frame count = %d; want %d (types=%v)", len(gotTypes), len(wantOrder), gotTypes)
	}
	for i := range wantOrder {
		if gotTypes[i] != wantOrder[i] {
			t.Errorf("frame[%d] event-type = %q; want %q", i, gotTypes[i], wantOrder[i])
		}
	}
	if deltaText != "blocked by DefenseClaw" {
		t.Errorf("deltaText = %q; want blocked by DefenseClaw", deltaText)
	}
	if stopReason != "end_turn" {
		t.Errorf("stopReason = %q; want end_turn", stopReason)
	}
	if blocked, _ := messageMeta["defenseclaw_blocked"].(bool); !blocked {
		t.Errorf("messageStop missing defenseclaw_blocked=true: %+v", messageMeta)
	}
}

func TestWriteBlockedPassthroughBedrockRoutes(t *testing.T) {
	// Confirm the dispatcher picks the right writer based solely on the
	// request path. We verify the emitted Content-Type since the two
	// shapes (JSON vs event-stream) are easy to tell apart.
	cases := []struct {
		name string
		path string
		want string
	}{
		{"stream path", "/model/foo/converse-stream", "application/vnd.amazon.eventstream"},
		{"non-stream path", "/model/foo/converse", "application/json"},
		{"invoke-stream path", "/model/foo/invoke-with-response-stream", "application/vnd.amazon.eventstream"},
		{"invoke path", "/model/foo/invoke", "application/json"},
		{"unknown action falls back to JSON", "/model/foo/bar", "application/json"},
	}
	p := &GuardrailProxy{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			p.writeBlockedPassthroughBedrock(rec, tc.path, "", "blocked")
			if got := rec.Header().Get("Content-Type"); got != tc.want {
				t.Fatalf("Content-Type = %q; want %q", got, tc.want)
			}
			if got := rec.Header().Get("X-DefenseClaw-Blocked"); got != "true" {
				t.Fatalf("X-DefenseClaw-Blocked = %q; want true", got)
			}
		})
	}
}
