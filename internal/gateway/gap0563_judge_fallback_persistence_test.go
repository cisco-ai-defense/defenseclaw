// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The final audit row and its projected record must see the decision made
// after the hook's earlier telemetry context was created.
func TestGAP0563HookJudgeFallbackPersistsAfterEarlyTelemetry(t *testing.T) {
	for _, tc := range []struct {
		name, connector, answerWithin, reason string
		progress                              bool
		delay                                 time.Duration
		hookTimeout                           float64
		judgeErr                              error
	}{
		{name: "claude window header", connector: "claudecode", answerWithin: "450", delay: 500 * time.Millisecond, reason: judgeFallbackLate},
		{name: "claude default window", connector: "claudecode", delay: 2300 * time.Millisecond, reason: judgeFallbackLate},
		{name: "agent gateway window", connector: connector.AgentGatewayConnectorName, progress: true, delay: 3700 * time.Millisecond, reason: judgeFallbackLate},
		{name: "judge error", connector: "claudecode", judgeErr: errors.New("judge unavailable"), reason: judgeFallbackError},
		{name: "judge timeout", connector: "claudecode", delay: 500 * time.Millisecond, hookTimeout: 0.1, reason: judgeFallbackTimeout},
		{name: "judge answered", connector: "claudecode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := "gap0563-" + strings.ReplaceAll(tc.name, " ", "-")
			t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
			if tc.connector == connector.AgentGatewayConnectorName {
				installDefaultProfileConnector(t, connector.AgentGatewayConnectorName)
			}
			fixture := newAuditFailureHookFixture(t, "")
			cfg := fixture.api.scannerCfg
			cfg.Guardrail.Connector = tc.connector
			cfg.Guardrail.DetectionStrategy = "regex_judge"
			hookTimeout := tc.hookTimeout
			if hookTimeout == 0 {
				hookTimeout = 5
			}
			cfg.Guardrail.Judge = config.JudgeConfig{
				Enabled: true, Injection: true, ToolInjection: true,
				HookConnectors: []string{tc.connector}, HookTimeout: hookTimeout,
			}
			cfg.Connectors.AgentGateway.Enabled = true
			provider := &slowLLMProvider{
				mockLLMProvider: mockLLMProvider{
					response: &ChatResponse{Model: "test-model", Choices: []ChatChoice{{Message: &ChatMessage{Content: `{"findings":[]}`}}}},
					err:      tc.judgeErr,
				},
				delay: tc.delay, finished: make(chan error, 8),
			}
			fixture.api.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: provider, rp: &guardrail.RulePack{}})

			var body []byte
			var path string
			var handler http.Handler
			if tc.connector == connector.AgentGatewayConnectorName {
				body, _ = json.Marshal(map[string]any{
					"event": "pre_tool", "session_id": session, "tool_use_id": "tool-1", "cwd": t.TempDir(),
					"tool": map[string]any{"name": "bash", "kind": "shell", "input": "make ok"},
				})
				path, handler = connector.AgentGatewayHookPath, fixture.api.handleAgentGatewayHook()
			} else {
				body, _ = json.Marshal(map[string]any{
					"hook_event_name": "PreToolUse", "session_id": session, "tool_use_id": "tool-1", "cwd": t.TempDir(),
					"tool_name": "Bash", "tool_input": map[string]any{"command": "make ok"},
				})
				path, handler = "/api/v1/claudecode/hook", fixture.api.handleAgentHook("claudecode")
			}
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tc.answerWithin != "" {
				req.Header.Set(hookexec.HookAnswerWithinHeader, tc.answerWithin)
			}
			if tc.progress {
				req.Header.Set(hookexec.HookProgressHeader, "1")
			}
			w := &gap0563FinalRecorder{ResponseRecorder: httptest.NewRecorder()}
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("hook status %d: %s", w.Code, w.Body.String())
			}
			var answer struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || answer.Action != "allow" {
				t.Fatalf("ordinary tool answer %+v, error %v, body %s", answer, err, w.Body.String())
			}
			select {
			case <-provider.finished:
			case <-time.After(5 * time.Second):
				t.Fatal("judge call did not finish")
			}
			row := newestHookDecision(t, fixture.api.store, session)
			extra, _ := row.Structured["extra"].(map[string]any)
			if got, _ := extra[hookJudgeFallbackExtraKey].(string); got != tc.reason {
				t.Errorf("audit fallback = %q, want %q", got, tc.reason)
			}
			if got := gap0563ProjectedFallback(t, fixture.path); got != tc.reason {
				t.Errorf("projected fallback = %q, want %q", got, tc.reason)
			}
		})
	}
}

// The evaluated redaction directive follows the same persistence lifetime
// as the hook decision, including when telemetry was emitted first.
func TestGAP0563HookDecisionKeepsEvaluatedRedaction(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	fixture := newAuditFailureHookFixture(t, "")
	redactionEnabled := false
	injectAnswerEvaluator(t, "claudecode", func(string) agentHookResponse {
		return agentHookResponse{
			Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
			RedactionEnabled: &redactionEnabled,
		}
	})
	var seen *bool
	previous := hookStagePanicHook
	hookStagePanicHook = func(ctx context.Context, stage string) {
		if stage == "finalize_audit" {
			seen = redactionDecisionFromContext(ctx)
		}
	}
	t.Cleanup(func() { hookStagePanicHook = previous })
	body := preToolUseBody(t, "gap0563-redaction")
	w := httptest.NewRecorder()
	fixture.api.handleAgentHook("claudecode").ServeHTTP(w,
		httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
	if w.Code != http.StatusOK || seen == nil || *seen != redactionEnabled {
		t.Fatalf("status=%d finalization redaction=%v, want the evaluated decision", w.Code, seen)
	}
}

// An informational progress response precedes the final hook answer.
type gap0563FinalRecorder struct{ *httptest.ResponseRecorder }

func (w *gap0563FinalRecorder) WriteHeader(status int) {
	if status >= 200 {
		w.ResponseRecorder.WriteHeader(status)
	}
}

func gap0563ProjectedFallback(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow(`SELECT projected_record_json FROM audit_events WHERE event_name = 'hook_decision' ORDER BY rowid DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var record struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		t.Fatal(err)
	}
	value, _ := record.Body["defenseclaw.guardrail.judge_fallback"].(string)
	return value
}
