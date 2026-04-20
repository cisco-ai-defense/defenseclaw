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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	eventstream "github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// Bedrock path suffixes used to pick the right blocked-response format.
// The full path is of the form /model/{modelId}/{action}, and the
// request may arrive either URL-encoded or decoded depending on how
// the client signed it.
const (
	bedrockActionConverse             = "converse"
	bedrockActionConverseStream       = "converse-stream"
	bedrockActionInvoke               = "invoke"
	bedrockActionInvokeResponseStream = "invoke-with-response-stream"
	bedrockApplyGuardrailActionSuffix = "/apply"
)

// writeBlockedPassthroughBedrock dispatches a DefenseClaw-block response in
// the Bedrock-native shape expected by the AWS SDK on the client side. The
// stream flag is inferred from the URL path because Bedrock has no
// `"stream": true` body field — the action in the path determines the
// codec.
func (p *GuardrailProxy) writeBlockedPassthroughBedrock(w http.ResponseWriter, path, model, msg string) {
	action := bedrockActionFromPath(path)
	// If the request body doesn't contain a model (Bedrock puts it in the
	// URL), fall back to the one embedded in the path.
	if model == "" {
		model = bedrockModelFromPath(path)
	}

	switch action {
	case bedrockActionConverseStream, bedrockActionInvokeResponseStream:
		p.writeBlockedStreamBedrockConverse(w, model, msg)
	case bedrockActionConverse, bedrockActionInvoke:
		p.writeBlockedResponseBedrockConverse(w, model, msg)
	default:
		// Unknown Bedrock action — default to non-streaming JSON so the
		// client at least gets a parseable body instead of binary
		// framing it cannot decode.
		fmt.Fprintf(os.Stderr, "[guardrail] bedrock block: unknown action %q — defaulting to converse JSON\n", action)
		p.writeBlockedResponseBedrockConverse(w, model, msg)
	}
}

// bedrockActionFromPath returns the trailing Bedrock action ("converse",
// "converse-stream", "invoke", "invoke-with-response-stream") from a URL
// path like "/model/{modelId}/{action}". The modelId itself may contain
// URL-encoded bytes (e.g. "%3A" for the region-prefixed ARN form), but
// the action is always a plain ASCII suffix.
func bedrockActionFromPath(path string) string {
	if path == "" {
		return ""
	}
	// /guardrail/... /apply for ApplyGuardrail — not a model call.
	if strings.HasSuffix(path, bedrockApplyGuardrailActionSuffix) &&
		strings.Contains(path, "/guardrail/") {
		return ""
	}
	// Strip any trailing slash.
	trimmed := strings.TrimRight(path, "/")
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 && idx < len(trimmed)-1 {
		return trimmed[idx+1:]
	}
	return ""
}

// bedrockModelFromPath extracts the modelId segment from a Bedrock URL.
// Returns the raw (un-decoded) slice so the value round-trips safely
// through response metadata. Returns an empty string if no "/model/"
// segment is present.
func bedrockModelFromPath(path string) string {
	const marker = "/model/"
	idx := strings.Index(path, marker)
	if idx < 0 {
		return ""
	}
	rest := path[idx+len(marker):]
	// Strip the action suffix.
	if slash := strings.LastIndex(rest, "/"); slash > 0 {
		rest = rest[:slash]
	}
	// Decode %3A → : for human-readability when the caller logs it.
	if decoded, err := url.PathUnescape(rest); err == nil {
		return decoded
	}
	return rest
}

// bedrockBlockedConverseBody returns the JSON body of a Bedrock
// Converse (non-streaming) block response. It is shared with the
// streaming writer as the payload of the (single) contentBlockDelta.
func bedrockBlockedConverseBody(model, msg string) map[string]any {
	return map[string]any{
		"output": map[string]any{
			"message": map[string]any{
				"role": "assistant",
				"content": []map[string]any{
					{"text": msg},
				},
			},
		},
		"stopReason": "guardrail_intervened",
		"usage": map[string]int{
			"inputTokens":  0,
			"outputTokens": 1,
			"totalTokens":  1,
		},
		"metrics": map[string]int{
			"latencyMs": 0,
		},
		"defenseclaw_blocked": true,
		"defenseclaw_reason":  msg,
		"defenseclaw_model":   model,
	}
}

// writeBlockedResponseBedrockConverse returns a DefenseClaw block response
// in Bedrock Converse (non-streaming) JSON shape.
func (p *GuardrailProxy) writeBlockedResponseBedrockConverse(w http.ResponseWriter, model, msg string) {
	resp := bedrockBlockedConverseBody(model, msg)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-DefenseClaw-Blocked", "true")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeBlockedStreamBedrockConverse returns a DefenseClaw block response as
// an AWS `application/vnd.amazon.eventstream` message sequence matching the
// Bedrock ConverseStream API. Five frames are emitted:
//
//  1. messageStart       — role=assistant
//  2. contentBlockDelta  — delta.text = <block message>
//  3. contentBlockStop   — contentBlockIndex=0
//  4. messageStop        — stopReason=guardrail_intervened
//  5. metadata           — usage + metrics
//
// Each frame is framed with the AWS event-stream codec (preamble length +
// headers length + prelude CRC32 + headers + payload + message CRC32).
// Without this, the AWS SDK on the client side aborts the stream with
// "Truncated event message received" because it expects binary framing
// but DefenseClaw was returning OpenAI-style SSE `data:` lines.
func (p *GuardrailProxy) writeBlockedStreamBedrockConverse(w http.ResponseWriter, model, msg string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Cannot flush frames incrementally — fall back to JSON so the
		// client gets at least a parseable body.
		p.writeBlockedResponseBedrockConverse(w, model, msg)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
	w.Header().Set("X-DefenseClaw-Blocked", "true")
	w.WriteHeader(http.StatusOK)

	emit := func(eventType string, payload map[string]any) {
		if err := writeBedrockEventStreamFrame(w, eventType, payload); err != nil {
			fmt.Fprintf(os.Stderr, "[guardrail] bedrock block-stream frame %q error: %v\n", eventType, err)
		}
		flusher.Flush()
	}

	emit("messageStart", map[string]any{
		"role": "assistant",
		"p":    "",
	})
	emit("contentBlockDelta", map[string]any{
		"contentBlockIndex": 0,
		"delta":             map[string]any{"text": msg},
		"p":                 "",
	})
	emit("contentBlockStop", map[string]any{
		"contentBlockIndex": 0,
		"p":                 "",
	})
	emit("messageStop", map[string]any{
		"stopReason":          "guardrail_intervened",
		"defenseclaw_blocked": true,
		"defenseclaw_reason":  msg,
		"defenseclaw_model":   model,
		"p":                   "",
	})
	emit("metadata", map[string]any{
		"usage": map[string]int{
			"inputTokens":  0,
			"outputTokens": 1,
			"totalTokens":  1,
		},
		"metrics": map[string]int{"latencyMs": 0},
		"p":       "",
	})
}

// writeBedrockEventStreamFrame encodes and writes a single Bedrock-style
// event-stream message to w. The headers are the three required Bedrock
// event headers (`:event-type`, `:message-type`, `:content-type`) and the
// payload is JSON-encoded.
//
// Framing is delegated to the AWS SDK's eventstream encoder to avoid
// hand-rolling CRC32 checksum and header encoding (which the AWS SDK
// client is notoriously strict about).
func writeBedrockEventStreamFrame(w io.Writer, eventType string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	msg := eventstream.Message{
		Headers: eventstream.Headers{
			{Name: ":event-type", Value: eventstream.StringValue(eventType)},
			{Name: ":message-type", Value: eventstream.StringValue("event")},
			{Name: ":content-type", Value: eventstream.StringValue("application/json")},
		},
		Payload: body,
	}
	return eventstream.NewEncoder().Encode(w, msg)
}
