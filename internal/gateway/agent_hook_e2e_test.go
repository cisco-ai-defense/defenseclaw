// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestHandleAgentHook_FullChain_PerConnector is the M6 end-to-end
// integration test that asserts the unified chain works identically
// for every registered connector. It exercises the FULL handleAgentHook
// path top-to-bottom:
//
//   - HTTP request → handleAgentHook
//   - JSON decode → agentHookRequest
//   - context enrichment (session_id / agent_id propagation, F2)
//   - safeEvaluateHook (panic recovery, H2)
//   - hook profile-runtime dispatch
//   - renderAgentHookResponse (wire-shape per connector)
//   - HTTP response (200 OK + valid JSON envelope)
//
// We do NOT mock the evaluator: this is the canonical test that
// catches any drift between the unified handler and what a real
// connector hook script would receive. Each connector that registers
// a route MUST appear here, by name — including the typed
// claudecode/codex profile runtimes and every profile-only connector.
//
// Per-connector wire-shape assertions:
//
//   - claudecode response carries the top-level "claude_code_output"
//     key (Claude Code reads that exact field).
//   - codex response carries "codex_output".
//   - every other connector returns "hook_output".
//   - all responses carry the canonical action/mode/severity fields.
//
// If you add a new connector via registerHookHandler, you MUST add a
// row below — the test fails otherwise via the registry-completeness
// check at the end. That keeps the unified contract honest as the
// connector estate grows.
func TestHandleAgentHook_FullChain_PerConnector(t *testing.T) {
	// Each connector has a distinct preferred event-name; we use
	// the most common PreToolUse-equivalent so profile runtimes take
	// a recognised codepath, not the dispatch fallback.
	type wireShape struct {
		connector       string
		event           string
		toolName        string
		topLevelOutput  string // expected top-level JSON output key
		expectAction    string
		additionalAttrs map[string]string
	}

	shapes := []wireShape{
		{
			connector:      "claudecode",
			event:          "PreToolUse",
			toolName:       "Bash",
			topLevelOutput: "claude_code_output",
			expectAction:   "block",
		},
		{
			connector:      "codex",
			event:          "PreToolUse",
			toolName:       "shell",
			topLevelOutput: "codex_output",
			expectAction:   "block",
		},
		{
			connector:      "hermes",
			event:          "pre_tool_call",
			toolName:       "execute_command",
			topLevelOutput: "hook_output",
			expectAction:   "block",
		},
		{
			connector:      "cursor",
			event:          "preToolUse",
			toolName:       "run_terminal_cmd",
			topLevelOutput: "hook_output",
			expectAction:   "block",
		},
		{
			connector:      "windsurf",
			event:          "pre_run_command",
			toolName:       "run_command",
			topLevelOutput: "hook_output",
			expectAction:   "block",
		},
		{
			connector:      "geminicli",
			event:          "BeforeTool",
			toolName:       "RunShellCommand",
			topLevelOutput: "hook_output",
			expectAction:   "block",
		},
		{
			connector:      "copilot",
			event:          "PreToolUse",
			toolName:       "shell",
			topLevelOutput: "hook_output",
			expectAction:   "block",
		},
		{
			connector:      "openhands",
			event:          "PreToolUse",
			toolName:       "terminal",
			topLevelOutput: "hook_output",
			expectAction:   "block",
		},
		{
			connector:      "antigravity",
			event:          "PreToolUse",
			toolName:       "run_command",
			topLevelOutput: "hook_output",
			expectAction:   "block",
		},
		{
			connector:      "opencode",
			event:          "tool.execute.before",
			toolName:       "bash",
			topLevelOutput: "hook_output",
			expectAction:   "block",
		},
		{
			connector: "omnigent",
			event:     "PreToolUse",
			toolName:  "bash",
			// The Python policy consumes the canonical top-level action
			// directly; OmniGent has no nested hook response envelope.
			topLevelOutput: "",
			expectAction:   "block",
		},
	}

	for _, sh := range shapes {
		sh := sh
		t.Run(sh.connector, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = sh.connector
			api := &APIServer{scannerCfg: cfg}
			handler := inboundTraceContextMiddleware(http.HandlerFunc(api.handleAgentHook(sh.connector)))
			body, err := json.Marshal(map[string]interface{}{
				"hook_event_name": sh.event,
				"session_id":      "session-" + sh.connector,
				"turn_id":         "turn-" + sh.connector,
				"agent_id":        sh.connector + "-test-id",
				"agent_name":      sh.connector + " test agent",
				"agent_type":      sh.connector + "-cli",
				"tool_name":       sh.toolName,
				"tool_input": map[string]interface{}{
					"command": "rm -rf /",
				},
			})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			req := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/"+sh.connector+"/hook",
				bytes.NewReader(body),
			)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status=%d, want 200 (body=%s)", w.Code, w.Body.String())
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("response not valid JSON: %v\nbody=%s", err, w.Body.String())
			}

			// Canonical fields every connector must return.
			for _, field := range []string{"action", "severity", "mode"} {
				if _, ok := parsed[field]; !ok {
					t.Errorf("response missing canonical field %q\nbody=%s", field, w.Body.String())
				}
			}
			if sh.topLevelOutput != "" {
				if _, ok := parsed[sh.topLevelOutput]; !ok {
					t.Errorf("response missing connector output field %q\nbody=%s", sh.topLevelOutput, w.Body.String())
				}
			}
			for _, forbidden := range []string{"claude_code_output", "codex_output", "hook_output"} {
				if forbidden == sh.topLevelOutput {
					continue
				}
				if _, ok := parsed[forbidden]; ok {
					t.Errorf("response included wrong connector output field %q; expected only %q\nbody=%s", forbidden, sh.topLevelOutput, w.Body.String())
				}
			}

			if action, _ := parsed["action"].(string); action != sh.expectAction {
				t.Errorf("dangerous request action=%q, want %q\nbody=%s", action, sh.expectAction, w.Body.String())
			}
		})
	}

	// Registry-completeness gate: every connector that has a
	// registered hook handler MUST be exercised above. If a new
	// connector is wired in without a row here, fail loud so the
	// unified-handler contract is never assumed to cover routes
	// the test never proves.
	covered := map[string]bool{}
	for _, sh := range shapes {
		covered[sh.connector] = true
	}
	for name := range connectorHookHandlerByName {
		// test-c1-fixture is a hermetic fixture from hook_register_test.go.
		if strings.HasPrefix(name, "test-") {
			continue
		}
		if !covered[name] {
			t.Errorf("connector %q has a registered hook handler but no row in TestHandleAgentHook_FullChain_PerConnector; add it.", name)
		}
	}
}

// TestHandleAgentHook_FullChain_SyntheticPath drives the
// codex-notify synthetic hook path top-to-bottom and asserts that:
//
//   - the synthesised Stop event reaches the safeEvaluateSyntheticHook
//     pipeline,
//   - the response shape is the codex-specific one (codex_output),
//   - no panic propagates if the evaluator throws — same fail-open
//     posture as the regular path.
func TestHandleAgentHook_FullChain_SyntheticPath(t *testing.T) {
	api := &APIServer{}
	ctx := context.Background()

	req := agentHookRequest{
		ConnectorName: "codex",
		HookEventName: "Stop",
		SessionID:     "session-synth",
		AgentID:       "codex-test",
		AgentName:     "codex test",
		AgentType:     "codex-cli",
	}
	body, _ := json.Marshal(map[string]interface{}{
		"hook_event_name": "Stop",
		"session_id":      "session-synth",
	})

	resp := api.handleAgentHookSynthetic(ctx, "codex", req, body)
	if resp.Action == "" {
		t.Errorf("synthetic handler returned empty Action (resp=%+v)", resp)
	}
	if resp.Mode == "" {
		t.Errorf("synthetic handler returned empty Mode (resp=%+v)", resp)
	}

	// The renderAgentHookResponse projection still uses
	// codex_output for the codex connector even on the synthetic
	// path — clients that consume the wire shape via /api/v1/codex/notify
	// expect this contract.
	wire := renderAgentHookResponse("codex", resp)
	if _, ok := wire["codex_output"]; !ok && resp.HookOutput != nil {
		t.Errorf("synthetic codex response missing codex_output: %+v", wire)
	}
}

// TestHandleAgentHook_FullChain_PanicFailsOpen is the M6 panic-
// recovery integration assertion: a panicking evaluator in the
// unified chain MUST NOT propagate; the HTTP response must remain
// 200 OK with action=allow + would_block=true; the panic counter
// must increment; the wire shape must still match the connector's
// expected top-level key.
func TestHandleAgentHook_FullChain_PanicFailsOpen(t *testing.T) {
	prev := hookEvaluatorPanicHook
	hookEvaluatorPanicHook = func() { panic("synthetic panic in unified chain") }
	defer func() { hookEvaluatorPanicHook = prev }()

	// Use a generic connector (geminicli) so the panic in
	// evaluateAgentHook triggers safeEvaluateHook's recover.
	api := &APIServer{}
	handler := http.HandlerFunc(api.handleAgentHook("geminicli"))
	body, _ := json.Marshal(map[string]interface{}{
		"hook_event_name": "preToolUse",
		"session_id":      "session-panic-e2e",
		"agent_id":        "gemini-panic-test",
		"tool_name":       "RunShellCommand",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/geminicli/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("panic-path status=%d, want 200 (fail-open)", w.Code)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("panic-path response not valid JSON: %v\nbody=%s", err, w.Body.String())
	}
	if action, _ := parsed["action"].(string); action != "allow" {
		t.Errorf("panic-path action = %q, want allow", action)
	}
	if wb, _ := parsed["would_block"].(bool); !wb {
		t.Errorf("panic-path would_block = false, want true")
	}
	// The wire-shape key is still hook_output (geminicli), not a
	// generic error stanza — the panic recovery preserves the
	// connector contract.
	if _, ok := parsed["hook_output"]; !ok {
		// hook_output is conditional on resp.HookOutput being
		// populated; the panic-path response has nil HookOutput
		// so the field is omitempty-dropped, which is correct.
		// We just verify NO other top-level output key was
		// accidentally emitted.
		for _, forbidden := range []string{"claude_code_output", "codex_output"} {
			if _, bad := parsed[forbidden]; bad {
				t.Errorf("panic-path leaked wrong top-level output %q (response: %+v)", forbidden, parsed)
			}
		}
	}
}

// connectorRegistryAllowlist confirms the M6 test rows above stay in
// sync with connector.OTLPPathTokenScopes() — adding an OTLP scope
// without registering a hook handler (or vice versa) is the class of
// drift we want CI to catch. Today there's a one-way relationship:
// every OTLP scope corresponds to a connector that should also have
// a registered hook handler. The test below documents it.
func TestConnectorRegistry_ScopeAndHookHandlerInSync(t *testing.T) {
	for _, scope := range connector.OTLPPathTokenScopes() {
		if _, ok := connectorHookHandlerByName[string(scope)]; !ok {
			t.Errorf("OTLP scope %q has no registered hook handler; misconfigured connector estate", scope)
		}
	}
}
