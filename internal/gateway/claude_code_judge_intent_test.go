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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// newClaudeCodeToolJudgeServer wires a Claude Code gateway whose tool-call
// lane runs the judge and whose prompt lane stays regex-only, so every
// provider call the mock captures is a tool-judge request.
func newClaudeCodeToolJudgeServer(t *testing.T, mock *mockLLMProvider) *APIServer {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.DetectionStrategy = "regex_only"
	cfg.Guardrail.DetectionStrategyToolCall = "judge_first"
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, ToolInjection: true, HookConnectors: []string{"claudecode"}}
	a := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	a.SetHookJudge(&LLMJudge{
		cfg:      &cfg.Guardrail.Judge,
		model:    "test-model",
		provider: mock,
		rp:       &guardrail.RulePack{},
	})
	return a
}

func postClaudeCodeHook(t *testing.T, a *APIServer, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	http.HandlerFunc(a.handleAgentHook("claudecode")).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("claude code hook status = %d body=%s", w.Code, w.Body.String())
	}
}

// lastToolJudgeSample returns the user message of the newest judge request.
func lastToolJudgeSample(t *testing.T, mock *mockLLMProvider) string {
	t.Helper()
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.captured) == 0 {
		t.Fatal("the tool judge was never called for the Claude Code PreToolUse")
	}
	var b strings.Builder
	for _, m := range mock.captured[len(mock.captured)-1].Messages {
		b.WriteString(m.Content)
		b.WriteString("\n")
	}
	return b.String()
}

const claudeCodeIntentToolCall = `{"session_id":"cc-intent-1","hook_event_name":"PreToolUse","cwd":"/tmp",` +
	`"tool_name":"Bash","tool_use_id":"toolu_1","tool_input":{"command":"ls -la ./fixtures/reports"}}`

// The Claude Code route seeds the tool judge's SESSION_USER_INTENT from
// UserPromptSubmit, as the Codex and generic routes do: before the fix the
// typed evaluator never observed the prompt, so every Claude Code tool-judge
// request went out without the user's task.
func TestClaudeCodeUserPromptSubmitSeedsToolJudgeIntent(t *testing.T) {
	mock := injectionHitProvider()
	a := newClaudeCodeToolJudgeServer(t, mock)

	postClaudeCodeHook(t, a, `{"session_id":"cc-intent-1","hook_event_name":"UserPromptSubmit","cwd":"/tmp",`+
		`"prompt":"list the quarterly report fixtures"}`)
	postClaudeCodeHook(t, a, claudeCodeIntentToolCall)

	sample := lastToolJudgeSample(t, mock)
	if !strings.Contains(sample, "<SESSION_USER_INTENT") ||
		!strings.Contains(sample, "list the quarterly report fixtures") {
		t.Fatalf("tool-judge request has no user intent after UserPromptSubmit: %q", sample)
	}
}

// A UserPromptExpansion carries command text the user did not type; it must
// not seed or replace the task the judge weighs tool calls against.
func TestClaudeCodeUserPromptExpansionDoesNotReplaceToolJudgeIntent(t *testing.T) {
	mock := injectionHitProvider()
	a := newClaudeCodeToolJudgeServer(t, mock)

	postClaudeCodeHook(t, a, `{"session_id":"cc-intent-1","hook_event_name":"UserPromptSubmit","cwd":"/tmp",`+
		`"prompt":"list the quarterly report fixtures"}`)
	postClaudeCodeHook(t, a, `{"session_id":"cc-intent-1","hook_event_name":"UserPromptExpansion","cwd":"/tmp",`+
		`"expansion_type":"slash_command","command_name":"expand-marker","prompt":"expanded command body marker"}`)
	postClaudeCodeHook(t, a, claudeCodeIntentToolCall)

	sample := lastToolJudgeSample(t, mock)
	if !strings.Contains(sample, "list the quarterly report fixtures") {
		t.Fatalf("UserPromptExpansion dropped the typed prompt from the judge intent: %q", sample)
	}
	if strings.Contains(sample, "expanded command body marker") {
		t.Fatalf("UserPromptExpansion replaced the judge intent: %q", sample)
	}
}
