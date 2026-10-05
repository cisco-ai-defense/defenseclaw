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

// The marker rule helper is unix-only (sandbox_verdict_reason_test.go).

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestCopilotVSCodeLocalHookDialect drives the VS Code Local harness
// dialect through the Copilot hook route: the body's event must be the
// bound one, a marker rule on run_in_terminal is denied with the Local
// harness's hookSpecificOutput, and an allowed call renders no output (a
// Local "allow" would auto-approve the call).
func TestCopilotVSCodeLocalHookDialect(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	handler := http.HandlerFunc(api.handleAgentHook("copilot"))

	post := func(event, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Copilot-Event", event)
		req.Header.Set(connector.HookDialectHeader, connector.CopilotHookSurfaceVSCodeLocal)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	call := func(event, command string) string {
		return `{"timestamp":"2026-09-30T00:00:00Z","hook_event_name":"` + event +
			`","session_id":"s1","tool_name":"run_in_terminal","tool_use_id":"t1",` +
			`"tool_input":{"command":"` + command + `","explanation":"x","isBackground":false}}`
	}

	if w := post("PreToolUse", call("PostToolUse", "echo DCE2E-BLOCK-MARKER")); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "harness_event_mismatch") {
		t.Fatalf("mismatched body event: status=%d body=%s", w.Code, w.Body.String())
	}

	w := post("PreToolUse", call("PreToolUse", "echo DCE2E-BLOCK-MARKER"))
	var denied struct {
		HookOutput struct {
			Specific struct {
				Event    string `json:"hookEventName"`
				Decision string `json:"permissionDecision"`
				Reason   string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		} `json:"hook_output"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &denied); err != nil || w.Code != http.StatusOK {
		t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
	}
	if denied.HookOutput.Specific.Event != "PreToolUse" || denied.HookOutput.Specific.Decision != "deny" ||
		denied.HookOutput.Specific.Reason == "" {
		t.Fatalf("marker rule not denied in the Local dialect: %s", w.Body.String())
	}

	w = post("PreToolUse", call("PreToolUse", "echo hello"))
	var allowed map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &allowed); err != nil || w.Code != http.StatusOK {
		t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
	}
	if out, ok := allowed["hook_output"]; ok && string(out) != "null" && string(out) != "{}" {
		t.Fatalf("allowed call rendered Local output %s; body=%s", out, w.Body.String())
	}
}

// GAP-1903: the VS Code Local harness also runs the per-user Copilot CLI
// hook file and sends a CLI-shaped body with its own tool names. A marker
// rule on run_in_terminal is denied there too, in both decision shapes.
func TestCopilotCLIHookFileRunByVSCodeLocalHarness(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	handler := http.HandlerFunc(api.handleAgentHook("copilot"))

	post := func(command string) map[string]interface{} {
		body := `{"timestamp":1790976011985,"cwd":"/home/alice/w","toolName":"run_in_terminal",` +
			`"toolArgs":{"command":"` + command + `","explanation":"x","goal":"g","mode":"sync"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		var out map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
			t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
		}
		hookOutput, _ := out["hook_output"].(map[string]interface{})
		return hookOutput
	}

	out := post("echo DCE2E-BLOCK-MARKER > /home/alice/w/x.txt")
	specific, _ := out["hookSpecificOutput"].(map[string]interface{})
	if out["permissionDecision"] != "deny" || specific["permissionDecision"] != "deny" ||
		specific["hookEventName"] != "PreToolUse" || specific["permissionDecisionReason"] == "" {
		t.Fatalf("marker command not denied: %v", out)
	}
	if out := post("echo hello"); out["permissionDecision"] != nil || out["hookSpecificOutput"] != nil {
		t.Fatalf("allowed call rendered a decision: %v", out)
	}
}

// GAP-1903: the VS Code Local harness also runs the per-user Copilot CLI
// hook file (bound to the CLI event preToolUse, no dialect header) and sends
// it the Local payload, as VS Code 1.140 did on dc-win2. A marker command in
// run_in_terminal is denied with the Local decision shape, a benign one runs,
// and a body naming another event keeps the CLI handling.
func TestCopilotCLIHookFileLocalPayloadFromVSCode(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	handler := http.HandlerFunc(api.handleAgentHook("copilot"))

	post := func(bodyEvent, command string) map[string]interface{} {
		body := `{"timestamp":"2026-10-03T23:56:24.200Z","hook_event_name":"` + bodyEvent + `",` +
			`"session_id":"s1","transcript_path":"/home/alice/t.jsonl","cwd":"/home/alice/w",` +
			`"tool_name":"run_in_terminal","tool_use_id":"call_1__vscode-1",` +
			`"tool_input":{"command":"` + command + `","explanation":"Run the command.",` +
			`"goal":"Execute requested command","mode":"sync","timeout":120000}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		var out map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
			t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
		}
		hookOutput, _ := out["hook_output"].(map[string]interface{})
		return hookOutput
	}

	out := post("PreToolUse", "echo DCE2E-BLOCK-MARKER > /home/alice/w/x.txt")
	specific, _ := out["hookSpecificOutput"].(map[string]interface{})
	if specific["permissionDecision"] != "deny" || specific["hookEventName"] != "PreToolUse" ||
		specific["permissionDecisionReason"] == "" {
		t.Fatalf("marker command not denied: %v", out)
	}
	if out := post("PreToolUse", "echo hello"); len(out) != 0 {
		t.Fatalf("benign call rendered a decision: %v", out)
	}
	if out := post("PostToolUse", "echo DCE2E-BLOCK-MARKER"); out["hookSpecificOutput"] != nil {
		t.Fatalf("a body naming another event switched dialect: %v", out)
	}
}
