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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func newOpenCodeToolJudgeServer(t *testing.T, mock *mockLLMProvider) *APIServer {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "opencode"
	cfg.Guardrail.DetectionStrategy = "regex_only"
	cfg.Guardrail.DetectionStrategyToolCall = "judge_first"
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, ToolInjection: true, HookConnectors: []string{"opencode"}}
	a := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	a.SetHookJudge(&LLMJudge{
		cfg: &cfg.Guardrail.Judge, model: "test-model", rp: &guardrail.RulePack{},
		provider: slowToolJudgeProvider{mockLLMProvider: mock, delay: 20 * time.Millisecond},
	})
	return a
}

func postOpenCodeHook(t *testing.T, a *APIServer, body map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/opencode/hook", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	http.HandlerFunc(a.handleAgentHook("opencode")).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("opencode hook status = %d body=%s", w.Code, w.Body.String())
	}
}

// openCodePromptEvent is the session.prompt lifecycle post of the OpenCode 2.x
// bridge: the turn's text is the post's prompt field.
func openCodePromptEvent(session, messageID, prompt string) map[string]any {
	return map[string]any{
		"hook_event_name": "session.prompt", "event_type": "session.prompt", "source_event_id": messageID,
		"session_id": session, "cwd": "/tmp", "load_heartbeat": true, "prompt": prompt,
		"event": map[string]any{"sessionID": session, "messageID": messageID},
	}
}

// TestGAP0032OpenCodeSessionPromptIsTheJudgeTask: the user's turn that the
// OpenCode 2.x bridge reports as session.prompt is the task the tool judge is
// shown with the session's next tool call, as a Claude Code UserPromptSubmit
// is. At 1.0.10 the event was not a prompt event and the judge saw the call
// with no task. A session with no prompt event keeps no task.
func TestGAP0032OpenCodeSessionPromptIsTheJudgeTask(t *testing.T) {
	const task = "refactor the config loader and keep the tests green"
	mock := injectionHitProvider()
	a := newOpenCodeToolJudgeServer(t, mock)
	postOpenCodeHook(t, a, openCodePromptEvent("oc-task", "msg-1", task))
	postOpenCodeHook(t, a, openCodeToolEvent("tool.execute.before", "oc-task", "call-1", "ls ./fixtures"))
	sample := waitJudgeSample(t, mock, "./fixtures", 1)
	if !strings.Contains(sample, "<SESSION_USER_INTENT") || !strings.Contains(sample, task) {
		t.Fatalf("the OpenCode user's turn is not the judge's task:\n%s", sample)
	}

	// Control: another session with no prompt event has no task, and a
	// lifecycle event with no prompt text does not make one.
	mock = injectionHitProvider()
	a = newOpenCodeToolJudgeServer(t, mock)
	status := openCodePromptEvent("oc-none", "msg-2", "")
	status["hook_event_name"], status["event_type"] = "session.status", "session.status"
	postOpenCodeHook(t, a, status)
	postOpenCodeHook(t, a, openCodePromptEvent("oc-none", "msg-3", ""))
	postOpenCodeHook(t, a, openCodeToolEvent("tool.execute.before", "oc-none", "call-2", "ls ./fixtures"))
	control := waitJudgeSample(t, mock, "./fixtures", 1)
	if strings.Contains(control, "<SESSION_USER_INTENT") && strings.Contains(control, task) {
		t.Fatalf("a session with no prompt event carries a task:\n%s", control)
	}
}
