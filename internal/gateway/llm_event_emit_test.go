// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	osuser "os/user"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func captureGatewayEvents(t *testing.T) *[]gatewaylog.Event {
	t.Helper()
	prev := EventWriter()
	w, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	var events []gatewaylog.Event
	w.WithFanout(func(e gatewaylog.Event) {
		events = append(events, e)
	})
	SetEventWriter(w)
	t.Cleanup(func() {
		SetEventWriter(prev)
		_ = w.Close()
	})
	return &events
}

func TestLLMEventEmit_RedactsByDefaultAndSendsRawWhenDisabled(t *testing.T) {
	events := captureGatewayEvents(t)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	meta := llmEventMeta{
		Source:    "codex",
		Provider:  "openai",
		Model:     "gpt-4o",
		SessionID: "sess-1",
		RequestID: "req-1",
		AgentType: "codex",
		UserID:    "alice",
	}

	redaction.SetDisableAll(false)
	emitLLMPromptEvent(context.Background(), meta, "raw user prompt", []byte(`{"messages":[{"role":"user","content":"raw user prompt"}]}`))
	if len(*events) != 1 {
		t.Fatalf("events=%d want 1", len(*events))
	}
	redacted := (*events)[0]
	if redacted.LLMPrompt == nil {
		t.Fatalf("missing llm_prompt payload: %+v", redacted)
	}
	if redacted.LLMPrompt.Prompt == "raw user prompt" {
		t.Fatalf("prompt leaked with redaction enabled")
	}
	if !strings.HasPrefix(redacted.LLMPrompt.Prompt, "<redacted") {
		t.Fatalf("prompt was not redacted placeholder: %q", redacted.LLMPrompt.Prompt)
	}
	if redacted.UserID != "alice" || redacted.AgentType != "codex" {
		t.Fatalf("envelope lost user/agent type: %+v", redacted)
	}

	redaction.SetDisableAll(true)
	emitLLMPromptEvent(context.Background(), meta, "raw user prompt", []byte(`{"raw":true}`))
	if len(*events) != 2 {
		t.Fatalf("events=%d want 2", len(*events))
	}
	raw := (*events)[1]
	if raw.LLMPrompt.Prompt != "raw user prompt" {
		t.Fatalf("prompt=%q, want raw prompt", raw.LLMPrompt.Prompt)
	}
	if raw.LLMPrompt.RawRequestBody != `{"raw":true}` {
		t.Fatalf("raw_request_body=%q", raw.LLMPrompt.RawRequestBody)
	}
}

func TestClaudeCodeHookResponseLinksToLastPrompt(t *testing.T) {
	events := captureGatewayEvents(t)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)

	api := &APIServer{}
	api.emitClaudeCodeHookLLMEvent(context.Background(), claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit",
		SessionID:     "sess-claude",
		Model:         "claude-3-5-sonnet",
		Prompt:        "write tests",
		AgentType:     "claude-code",
	}, nil, []byte(`{"hook_event_name":"UserPromptSubmit","prompt":"write tests"}`))
	api.emitClaudeCodeHookLLMEvent(context.Background(), claudeCodeHookRequest{
		HookEventName:        "Stop",
		SessionID:            "sess-claude",
		Model:                "claude-3-5-sonnet",
		LastAssistantMessage: "done",
		AgentType:            "claude-code",
	}, nil, []byte(`{"hook_event_name":"Stop","last_assistant_message":"done"}`))

	if len(*events) != 2 {
		t.Fatalf("events=%d want 2", len(*events))
	}
	prompt := (*events)[0].LLMPrompt
	response := (*events)[1].LLMResponse
	if prompt == nil || response == nil {
		t.Fatalf("unexpected events: %+v", *events)
	}
	if response.ReplyToPromptID != prompt.PromptID {
		t.Fatalf("reply_to_prompt_id=%q want %q", response.ReplyToPromptID, prompt.PromptID)
	}
	if response.Response != "done" {
		t.Fatalf("response=%q", response.Response)
	}
}

func TestCodexHookSameTurnPromptsGetDistinctIDsAndCorrelateToLatest(t *testing.T) {
	events := captureGatewayEvents(t)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)

	api := &APIServer{}
	base := codexHookRequest{
		SessionID: "sess-codex",
		TurnID:    "turn-1",
		Model:     "gpt-5.5",
		AgentType: "codex",
		Payload: map[string]interface{}{
			"user_id":   "alice-id",
			"user_name": "alice",
		},
	}
	first := base
	first.HookEventName = "UserPromptSubmit"
	first.Prompt = "first prompt"
	api.emitCodexHookLLMEvent(context.Background(), first, nil, []byte(`{"hook_event_name":"UserPromptSubmit","prompt":"first prompt"}`))

	second := base
	second.HookEventName = "UserPromptSubmit"
	second.Prompt = "second prompt"
	api.emitCodexHookLLMEvent(context.Background(), second, nil, []byte(`{"hook_event_name":"UserPromptSubmit","prompt":"second prompt"}`))

	tool := base
	tool.HookEventName = "PreToolUse"
	tool.ToolName = "shell"
	tool.ToolUseID = "tool-1"
	tool.ToolInput = map[string]interface{}{"cmd": "echo ok"}
	api.emitCodexHookLLMEvent(context.Background(), tool, nil, []byte(`{"hook_event_name":"PreToolUse"}`))

	stop := base
	stop.HookEventName = "Stop"
	stop.LastAssistantMessage = "done"
	api.emitCodexHookLLMEvent(context.Background(), stop, nil, []byte(`{"hook_event_name":"Stop","last_assistant_message":"done"}`))

	if len(*events) != 4 {
		t.Fatalf("events=%d want 4", len(*events))
	}
	firstPrompt := (*events)[0].LLMPrompt
	secondPrompt := (*events)[1].LLMPrompt
	toolEvent := (*events)[2].Tool
	response := (*events)[3].LLMResponse
	if firstPrompt == nil || secondPrompt == nil || toolEvent == nil || response == nil {
		t.Fatalf("unexpected events: %+v", *events)
	}
	if firstPrompt.PromptID == secondPrompt.PromptID {
		t.Fatalf("same-turn prompt ids collided: %q", firstPrompt.PromptID)
	}
	if toolEvent.ReplyToPromptID != secondPrompt.PromptID {
		t.Fatalf("tool reply_to_prompt_id=%q want latest prompt %q", toolEvent.ReplyToPromptID, secondPrompt.PromptID)
	}
	if response.ReplyToPromptID != secondPrompt.PromptID {
		t.Fatalf("response reply_to_prompt_id=%q want latest prompt %q", response.ReplyToPromptID, secondPrompt.PromptID)
	}
	if got := (*events)[1].UserID; got != "alice-id" {
		t.Fatalf("user_id=%q want alice-id", got)
	}
	if got := (*events)[2].DestinationApp; got != "builtin" {
		t.Fatalf("destination_app=%q want builtin", got)
	}
}

func TestCodexHookMCPToolSetsDestinationApp(t *testing.T) {
	events := captureGatewayEvents(t)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)

	api := &APIServer{}
	req := codexHookRequest{
		HookEventName: "PreToolUse",
		SessionID:     "sess-codex",
		TurnID:        "turn-1",
		Model:         "gpt-5.5",
		ToolName:      "mcp__github__search_issues",
		ToolUseID:     "tool-1",
		Payload: map[string]interface{}{
			"mcp_server_name": "github",
		},
	}
	api.emitCodexHookLLMEvent(context.Background(), req, nil, []byte(`{"hook_event_name":"PreToolUse"}`))

	if len(*events) != 1 {
		t.Fatalf("events=%d want 1", len(*events))
	}
	if got := (*events)[0].DestinationApp; got != "mcp:github" {
		t.Fatalf("destination_app=%q want mcp:github", got)
	}
}

func TestHookLLMEventMetaFallsBackToLocalUser(t *testing.T) {
	current, err := osuser.Current()
	if err != nil || current == nil {
		t.Skipf("os/user current unavailable: %v", err)
	}

	meta := hookLLMEventMeta("codex", "sess", "turn", "gpt-5.5", "openai", "", "codex", map[string]interface{}{})
	if meta.UserID == "" && meta.UserName == "" {
		t.Fatalf("expected local user fallback, got user_id=%q user_name=%q", meta.UserID, meta.UserName)
	}
}

func TestHookToolDestinationApp(t *testing.T) {
	cases := []struct {
		name       string
		serverName string
		toolName   string
		want       string
	}{
		{name: "explicit server", serverName: "github", toolName: "Bash", want: "mcp:github"},
		{name: "mcp tool name", toolName: "mcp__filesystem__read_file", want: "mcp:filesystem"},
		{name: "builtin tool", toolName: "apply_patch", want: "builtin"},
		{name: "empty tool", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hookToolDestinationApp(tc.serverName, tc.toolName); got != tc.want {
				t.Fatalf("hookToolDestinationApp(%q, %q) = %q, want %q", tc.serverName, tc.toolName, got, tc.want)
			}
		})
	}
}
