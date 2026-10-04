// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
)

// GAP-2558: the input of a Claude Code tool_batch span lists its calls by
// tool name and ID, the identifiers the span of each call shows in clear. The
// content redaction profile replaced them with tokens; it now replaces only
// content, such as the command of the call.
func TestHookClaudeCodeToolBatchKeepsCallIdentifiersUnderContentProfile(t *testing.T) {
	api, spans := hookGalileoSpanCaptureWithProfile(t, "content")
	const session = "claude-tool-batch-content"
	ctx := context.Background()
	api.emitClaudeCodeHookLLMEvent(ctx, claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit", SessionID: session, Prompt: "Use the Bash tool", Payload: map[string]any{},
	}, nil, []byte(`{"prompt":"Use the Bash tool"}`))
	toolInput := map[string]any{"command": "echo v25-content-ok"}
	api.emitClaudeCodeHookLLMEvent(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: session, ToolName: "Bash", ToolUseID: "toolu_v25batch",
		ToolInput: toolInput, Payload: map[string]any{},
	}, nil, nil)
	api.emitClaudeCodeHookLLMEvent(ctx, claudeCodeHookRequest{
		HookEventName: "PostToolUse", SessionID: session, ToolName: "Bash", ToolUseID: "toolu_v25batch",
		ToolInput: toolInput, ToolResponse: map[string]any{"stdout": "v25-content-ok"}, Payload: map[string]any{},
	}, nil, nil)
	api.emitClaudeCodeHookLLMEvent(ctx, claudeCodeHookRequest{
		HookEventName: "PostToolBatch", SessionID: session, Payload: map[string]any{},
		ToolCalls: []any{map[string]any{"tool_name": "Bash", "tool_use_id": "toolu_v25batch", "tool_input": toolInput}},
	}, nil, nil)
	for _, span := range waitHookGalileoSpans(spans, "execute_tool tool_batch", 1) {
		if span.Name != "execute_tool tool_batch" {
			continue
		}
		input := hookModelV8ProtoAttributes(span)["input.value"]
		if !strings.Contains(input, `"tool_name": "Bash"`) && !strings.Contains(input, `"tool_name":"Bash"`) {
			t.Fatalf("tool_batch input=%q, want the tool name in clear", input)
		}
		if !strings.Contains(input, "toolu_v25batch") {
			t.Fatalf("tool_batch input=%q, want the tool_use_id in clear", input)
		}
		for _, other := range spans() {
			if other.Name == "execute_tool Bash" && strings.Contains(hookModelV8ProtoAttributes(other)["input.value"], "v25-content-ok") {
				t.Fatalf("Bash span input kept its command under the content profile")
			}
		}
		return
	}
	names := []string{}
	for _, span := range spans() {
		names = append(names, span.Name)
	}
	t.Fatalf("galileo got no tool_batch span, spans=%q", names)
}
