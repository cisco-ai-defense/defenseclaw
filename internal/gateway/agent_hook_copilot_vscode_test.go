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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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

// Strict policy retains the CLI registration's exact-schema refusal.
func TestCopilotCLIHookFileLocalPayloadFromVSCode(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	cfg.Guardrail.RulePack = "strict"
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
	if out := post("PreToolUse", "echo hello"); out["permissionDecision"] != "deny" {
		t.Fatalf("mismatched schema was accepted: %v", out)
	}
	if out := post("PostToolUse", "echo DCE2E-BLOCK-MARKER"); out["permissionDecision"] != "deny" {
		t.Fatalf("a body naming another event switched dialect: %v", out)
	}
}

func TestGAP0691PerUserCopilotCLIRegistrationJudgesLocalToolCalls(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	seq := 0
	post := func(name string, input map[string]any) string {
		t.Helper()
		seq++
		id := "g691-" + name + "-" + strconv.Itoa(seq)
		body, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "session_id": id, "tool_use_id": id,
			"cwd": t.TempDir(), "tool_name": name, "tool_input": input,
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
		w := httptest.NewRecorder()
		api.handleAgentHook("copilot").ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if body := post("run_in_terminal", map[string]any{"command": "echo hello"}); !strings.Contains(body, `"action":"allow"`) || strings.Contains(body, hookToolCallUnparsedRuleID) {
		t.Fatalf("ordinary terminal call: %s", body)
	}
	if body := post("create_file", map[string]any{"filePath": t.TempDir() + "/notes.txt", "content": "hello"}); !strings.Contains(body, `"action":"allow"`) || strings.Contains(body, hookToolCallUnparsedRuleID) {
		t.Fatalf("ordinary project file: %s", body)
	}
	if body := post("run_in_terminal", map[string]any{"command": "echo DCE2E-BLOCK-MARKER"}); !strings.Contains(body, `"action":"block"`) || strings.Contains(body, hookToolCallUnparsedRuleID) ||
		!strings.Contains(body, `"E2E-SANDBOX-MARKER"`) || strings.Count(body, `"permissionDecision":"deny"`) < 2 {
		t.Fatalf("protected terminal call: %s", body)
	}
	if body := post("create_file", map[string]any{"filePath": "/etc/shadow", "content": "example"}); !strings.Contains(body, `"action":"block"`) || strings.Contains(body, hookToolCallUnparsedRuleID) ||
		!strings.Contains(body, `"PATH-ETC-SHADOW"`) {
		t.Fatalf("protected file call: %s", body)
	}
}

// sharedLocalProtectedTarget returns a protected file that exists on this OS,
// outside the project, and the rule that names it once a project link to it is
// resolved. Where the system /etc/shadow exists under that literal name (Linux)
// it is the target. macOS has no /etc/shadow, and /etc there is a link to
// /private/etc, so a link to a name below /etc resolves to a /private/etc
// spelling the exact system-file rule does not name; the fixture is then a real
// credential file (a .netrc in a user-home-shaped directory of its own), which
// the same path rules protect on every OS.
func sharedLocalProtectedTarget(t *testing.T) (target, rule string) {
	t.Helper()
	if physical, err := filepath.EvalSymlinks("/etc/shadow"); err == nil && physical == "/etc/shadow" {
		return "/etc/shadow", "PATH-ETC-SHADOW"
	}
	home := filepath.Join(t.TempDir(), "Users", "fixture")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	target = filepath.Join(home, ".netrc")
	if err := os.WriteFile(target, []byte("machine example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return target, "PATH-NETRC"
}

func TestGAP0691SharedLocalFileTargetsAndEnvelope(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	project := t.TempDir()
	ordinary := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(ordinary, []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(project, "linked.txt")
	protectedTarget, linkedRule := sharedLocalProtectedTarget(t)
	if err := os.Symlink(protectedTarget, linked); err != nil {
		t.Fatal(err)
	}
	ordinaryLink := filepath.Join(project, "ordinary-link.txt")
	if err := os.Symlink(ordinary, ordinaryLink); err != nil {
		t.Fatal(err)
	}
	type call struct {
		name, tool string
		input      any
		cliEvent   bool
		protected  bool
	}
	calls := []call{
		{"ordinary create", "create_file", map[string]any{"filePath": ordinary, "content": "notes"}, false, false},
		{"ordinary read", "read_file", map[string]any{"filePath": ordinary}, false, false},
		{"ordinary linked create", "create_file", map[string]any{"filePath": ordinaryLink, "content": "notes"}, false, false},
		{"ordinary linked read", "read_file", map[string]any{"filePath": ordinaryLink}, false, false},
		{"direct read", "read_file", map[string]any{"filePath": "/etc/shadow"}, false, true},
		{"linked create", "create_file", map[string]any{"filePath": linked, "content": "notes"}, false, true},
		{"linked replace", "replace_string_in_file", map[string]any{"filePath": linked, "oldString": "a", "newString": "b"}, false, true},
		{"linked insert", "insert_edit_into_file", map[string]any{"filePath": linked, "code": "b"}, false, true},
		{"linked read", "read_file", map[string]any{"filePath": linked}, false, true},
		{"linked CLI write", "Write", map[string]any{"path": linked, "file_text": "notes"}, false, true},
		{"linked apply_patch", "apply_patch", "*** Begin Patch\n*** Update File: " + linked + "\n@@\n-a\n+b\n*** End Patch", false, true},
		{"ordinary apply_patch", "apply_patch", "*** Begin Patch\n*** Update File: " + ordinary + "\n@@\n-a\n+b\n*** End Patch", false, false},
		{"ordinary linked apply_patch", "apply_patch", "*** Begin Patch\n*** Update File: " + ordinaryLink + "\n@@\n-a\n+b\n*** End Patch", false, false},
		{"linked Edit patch text", "Edit", "*** Begin Patch\n*** Update File: " + linked + "\n@@\n-a\n+b\n*** End Patch", false, true},
		{"ordinary Edit patch text", "Edit", "*** Begin Patch\n*** Update File: " + ordinaryLink + "\n@@\n-a\n+b\n*** End Patch", false, false},
		{"linked write_file", "write_file", map[string]any{"path": linked, "content": "notes"}, false, true},
		{"ordinary linked write_file", "write_file", map[string]any{"path": ordinaryLink, "content": "notes"}, false, false},
		{"linked append_file", "append_file", map[string]any{"path": linked, "content": "notes"}, false, true},
		{"ordinary linked append_file", "append_file", map[string]any{"path": ordinaryLink, "content": "notes"}, false, false},
		{"direct write_file", "write_file", map[string]any{"path": "/etc/shadow", "content": "notes"}, false, true},
		{"mixed event field", "run_in_terminal", map[string]any{"command": "echo hello"}, true, true},
	}
	for _, tier := range []string{"implicit", "default", "permissive", "strict"} {
		t.Run(tier, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			if tier != "implicit" {
				cfg.Guardrail.RulePack = tier
			}
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			for index, tc := range calls {
				t.Run(tc.name, func(t *testing.T) {
					id := tier + "-" + strconv.Itoa(index)
					body := map[string]any{
						"hook_event_name": "PreToolUse", "session_id": id,
						"tool_use_id": id, "cwd": project,
						"tool_name": tc.tool, "tool_input": tc.input,
					}
					if tc.cliEvent {
						body["hookName"] = "preToolUse"
					}
					raw, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					evidence := hookpaths.ResolveConnector("copilot", "", "preToolUse", raw)
					req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(raw)))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
					req.Header.Set(hookpaths.Header, evidence)
					w := httptest.NewRecorder()
					api.handleAgentHook("copilot").ServeHTTP(w, req)
					var answer struct {
						Action  string   `json:"action"`
						RuleIDs []string `json:"rule_ids"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || w.Code != http.StatusOK {
						t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
					}
					want := "allow"
					if tc.protected || tier == "strict" {
						want = "block"
					}
					if answer.Action != want {
						t.Fatalf("action=%s, want %s; rules=%v", answer.Action, want, answer.RuleIDs)
					}
					wantRule := "PATH-ETC-SHADOW"
					if strings.HasPrefix(tc.name, "linked") {
						wantRule = linkedRule
					}
					if tc.protected && !tc.cliEvent && tier != "strict" && !slices.Contains(answer.RuleIDs, wantRule) {
						t.Fatalf("protected file rule %s absent: %v", wantRule, answer.RuleIDs)
					}
					if tc.cliEvent && !slices.Contains(answer.RuleIDs, hookToolCallUnparsedRuleID) {
						t.Fatalf("mixed body was not refused: %v", answer.RuleIDs)
					}
				})
			}
		})
	}
}

func TestGAP0481MappedLocalEventRejectsCLIFields(t *testing.T) {
	installSandboxMarkerRules(t)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	body := `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"run_in_terminal",
		"tool_input":{"command":"echo DCE2E-BLOCK-MARKER"},"toolName":"view","toolArgs":{"path":"README.md"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	w := httptest.NewRecorder()
	api.handleAgentHook("copilot")(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"permissionDecision":"deny"`) ||
		!strings.Contains(w.Body.String(), hookToolCallUnparsedRuleID) {
		t.Fatalf("mapped Local call changed route: status=%d body=%s", w.Code, w.Body.String())
	}
}
