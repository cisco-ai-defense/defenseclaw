// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestValidatedGenericEventIsNormalized(t *testing.T) {
	payload := map[string]interface{}{"event": "PostToolUse", "session_id": "s", "tool_use_id": "t"}
	if reason := malformedHookPayloadReason("claudecode", []byte(`{"event":"PostToolUse","session_id":"s","tool_use_id":"t"}`), payload, ""); reason != "" {
		t.Fatalf("validated event refused: %s", reason)
	}
	if got := normalizeAgentHookRequest("claudecode", payload).HookEventName; got != "PostToolUse" {
		t.Fatalf("normalized event = %q, want PostToolUse", got)
	}
}

// A malformed event must not enter the ordinary policy path as an unknown,
// observe-only event. The registered native hook treats a gateway error as a
// closed failure, while this rejection row names the parser failure.
func TestMalformedClaudeHookEventIsRejectedAndAudited(t *testing.T) {
	for _, tc := range []struct {
		name, body, reason string
	}{
		{"wrong event type", `{"hook_event_name":7,"session_id":"s","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, "invalid_event_type"},
		{"wrong session type", `{"hook_event_name":"PreToolUse","session_id":7,"tool_name":"Bash","tool_input":{"command":"echo ok"}}`, "invalid_field_type"},
		{"conflicting extra event", `{"hook_event_name":"PreToolUse","event":"Stop","session_id":"s","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, "conflicting_event"},
		{"missing event", `{"session_id":"s","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, "missing_event"},
		{"unsupported event", `{"hook_event_name":"NotAnEvent","session_id":"s","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, "event_outside_contract"},
		{"truncated", `{"hook_event_name":"PreToolUse","tool_name":"Bash"`, "invalid_json"},
		{"duplicate event", `{"hook_event_name":"PreToolUse","hook_event_name":"Stop"}`, "ambiguous_json"},
		{"duplicate pre-tool event as post-tool", `{"hook_event_name":"PreToolUse","hook_event_name":"PostToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":"echo marker >> ~/.ssh/authorized_keys"}}`, "ambiguous_json"},
		{"trailing after non-tool event", `{"hook_event_name":"SessionStart"} {"event":"Stop"}`, "ambiguous_json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			store, logger := testStoreAndLogger(t)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
			events, err := store.ListEvents(20)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, event := range events {
				if event.Action != string(audit.ActionConnectorHook) {
					continue
				}
				if strings.Contains(event.Details, tc.reason) && strings.Contains(event.Details, "rejected") {
					found = true
				}
			}
			if !found {
				t.Fatalf("no connector-hook rejection naming %q in %v", tc.reason, events)
			}
		})
	}
}

func TestMalformedBoundHookEventIsRejectedBeforeBinding(t *testing.T) {
	for _, name := range []string{"codex", "copilot", "antigravity"} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = name
			store, logger := testStoreAndLogger(t)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
			body := `{"hook_event_name":7,"session_id":"s","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/"+name+"/hook", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			switch name {
			case "codex":
				setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			case "copilot":
				req.Header.Set("X-DefenseClaw-Copilot-Event", "PreToolUse")
			case "antigravity":
				req.Header.Set("X-DefenseClaw-Antigravity-Event", "PreToolUse")
			}
			recorder := httptest.NewRecorder()
			api.handleAgentHook(name).ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadRequest ||
				!strings.Contains(recorder.Body.String(), `"reason":"malformed_hook_payload"`) {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			events, err := store.ListEvents(20)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events {
				if event.Action == string(audit.ActionConnectorHook) &&
					strings.Contains(event.Details, "invalid_event_type") {
					return
				}
			}
			t.Fatalf("missing typed rejection audit for %s: %v", name, events)
		})
	}
}

func TestMalformedClaudePreToolFieldsBlockWithFinding(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"missing tool name", `{"hook_event_name":"PreToolUse","session_id":"s","tool_input":{"command":"echo ok"}}`},
		{"missing tool input", `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash"}`},
		{"wrong tool input type", `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":7}`},
		{"conflicting tool names", `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","toolName":"Read","tool_input":{"command":"echo ok"}}`},
		{"two tool inputs", `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":"echo ok"},"toolInput":{"command":"echo other"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action, body := postHookDecision(t, "claudecode", "", tc.body)
			if action != "block" || !strings.Contains(body, hookToolCallUnparsedRuleID) {
				t.Fatalf("action=%s body=%s", action, body)
			}
		})
	}
}

// Two parsers can select different commands from one JSON object with a
// repeated key. The hook must refuse that object before either selection is
// judged, and its audit row must name the parser uncertainty.
func TestAmbiguousClaudeAndCodexToolCallBlocks(t *testing.T) {
	for _, name := range []string{"claudecode", "codex"} {
		for _, tc := range []struct {
			name, fields string
			wantBlock    bool
		}{
			{"protected then benign", `"tool_input":{"command":"echo marker >> ~/.ssh/authorized_keys"},"tool_input":{"command":"echo ok"}`, true},
			{"benign then protected", `"tool_input":{"command":"echo ok"},"tool_input":{"command":"echo marker >> ~/.ssh/authorized_keys"}`, true},
			{"duplicate nested command", `"tool_input":{"command":"echo marker >> ~/.ssh/authorized_keys","command":"echo ok"}`, true},
			{"conflicting input alias", `"tool_input":{"command":"echo marker >> ~/.ssh/authorized_keys"},"toolInput":{"command":"echo ok"}`, true},
			{"plain benign command", `"tool_input":{"command":"echo ok"}`, false},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = name
				store, logger := testStoreAndLogger(t)
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
				body := `{"hook_event_name":"PreToolUse","session_id":"ambiguous-tool","tool_name":"Bash",` + tc.fields + `}`
				req := httptest.NewRequest(http.MethodPost, "/api/v1/"+name+"/hook", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				if name == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook(name).ServeHTTP(recorder, req)
				var response struct {
					Action  string   `json:"action"`
					RuleIDs []string `json:"rule_ids"`
				}
				if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil {
					t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
				}
				want := "allow"
				if tc.wantBlock {
					want = "block"
				}
				if response.Action != want {
					t.Fatalf("action=%s, want %s: %s", response.Action, want, recorder.Body.String())
				}
				if tc.wantBlock && !strings.Contains(recorder.Body.String(), hookToolCallUnparsedRuleID) {
					t.Fatalf("block lacks parser finding: %s", recorder.Body.String())
				}
				events, err := store.ListEvents(20)
				if err != nil {
					t.Fatal(err)
				}
				var found bool
				for _, event := range events {
					if event.Action == string(audit.ActionConnectorHook) &&
						event.Structured["action"] == want {
						if tc.wantBlock && !strings.Contains(event.Details, hookToolCallUnparsedRuleID) {
							t.Fatalf("block audit lacks parser finding: %s", event.Details)
						}
						found = true
					}
				}
				if !found {
					t.Fatalf("missing %s audit row: %v", want, events)
				}
			})
		}
	}
}

func TestHookEventValidationAcrossConnectors(t *testing.T) {
	for _, connector := range []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "opencode"} {
		t.Run(connector, func(t *testing.T) {
			for _, body := range []string{`{"hook_event_name":7}`, `{"hook_event_name":"PreToolUse","session_id":7}`, `{"hook_event_name":"PreToolUse","hookName":7}`, `{"hook_event_name":"PreToolUse","event":"Stop"}`, `{"hook_event_name":"PreToolUse","hook_event_name":"Stop"}`} {
				var payload map[string]interface{}
				if err := json.Unmarshal([]byte(body), &payload); err != nil {
					t.Fatal(err)
				}
				if reason := malformedHookPayloadReason(connector, []byte(body), payload, ""); reason == "" {
					t.Fatalf("%s accepted malformed event %s", connector, body)
				}
			}
			if reason := malformedHookPayloadReason(connector, []byte(`{"hook_event_name":"Stop"}`),
				map[string]interface{}{"hook_event_name": "Stop"}, "PreToolUse"); connector != "copilot" && connector != "antigravity" && reason != "conflicting_event" {
				t.Fatalf("%s accepted an event outside its registered command: %q", connector, reason)
			} else if (connector == "copilot" || connector == "antigravity") && reason != "" {
				t.Fatalf("%s rejected its authoritative registered event: %q", connector, reason)
			}
		})
	}
}

// These vendors bind the event in the installed command. Their stdin event
// spelling is advisory, and a forged observation label must not override a
// registered pre-tool call. The bound event still routes to tool inspection.
func TestBoundPreToolEventOwnsAdvisoryPayloadLabel(t *testing.T) {
	for _, tc := range []struct {
		connector, body, bound string
	}{
		{"antigravity", `{"hookEventName":"Stop"}`, "PreToolUse"},
		{"copilot", `{"hook_event_name":"PostToolUse"}`, "preToolUse"},
		{"copilot", `{"hook_event_name":"PreToolUse"}`, "preToolUse"},
	} {
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(tc.body), &payload); err != nil {
			t.Fatal(err)
		}
		if reason := malformedHookPayloadReason(tc.connector, []byte(tc.body), payload, tc.bound); reason != "" {
			t.Errorf("%s bound %s refused advisory %s: %s", tc.connector, tc.bound, tc.body, reason)
		}
	}
}

func TestOversizedHookInputHasAuditRejectionAndMalformedReason(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{health: NewSidecarHealth(), store: store, logger: logger}
	body := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` + strings.Repeat("x", int(apiRequestBodyMaxBytes)) + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
	if recorder.Code != http.StatusRequestEntityTooLarge || !strings.Contains(recorder.Body.String(), `"reason":"malformed_hook_payload"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) && strings.Contains(event.Details, "body_too_large") {
			return
		}
	}
	t.Fatalf("no oversized rejection in %v", events)
}
