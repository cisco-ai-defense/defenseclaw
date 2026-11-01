// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-2497: the Copilot CLI (1.0.91) also runs the PascalCase hooks of the
// VS Code Local hook file. There it names its apply_patch tool Edit and sends
// the patch text itself as tool_input (the body below is the live capture,
// with the cwd moved to a test project). That call is the apply_patch call
// its own preToolUse names and is judged as one: a project edit is allowed in
// observe and action, a protected target is refused by its rule, and neither
// is HOOK-TOOL-CALL-UNPARSED. Any other string input stays unread.
func TestCopilotVSCodeLocalEditPatchStringIsJudgedAsApplyPatch(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "b.txt"), []byte("beta1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	body := func(input any) string {
		raw, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "session_id": "97e2936f-4363-4c3f-bc8c-7b4ccdaf1471",
			"timestamp": "2026-10-29T03:37:36.358Z", "cwd": project, "tool_name": "Edit", "tool_input": input,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	post := func(mode, payload string) (string, string) {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = mode
		cfg.Guardrail.Connector = "copilot"
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Copilot-Event", "PreToolUse")
		req.Header.Set(connector.HookDialectHeader, connector.CopilotHookSurfaceVSCodeLocal)
		req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("copilot", connector.CopilotHookSurfaceVSCodeLocal, "PreToolUse", []byte(payload)))
		w := httptest.NewRecorder()
		api.handleAgentHook("copilot").ServeHTTP(w, req)
		var verdict struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil || w.Code != http.StatusOK {
			t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
		}
		return verdict.Action, w.Body.String()
	}

	benign := body("*** Begin Patch\n*** Update File: b.txt\n@@\n-beta1\n+beta2\n*** End Patch\n")
	for _, mode := range []string{"observe", "action"} {
		action, response := post(mode, benign)
		if action != "allow" || strings.Contains(response, hookToolCallUnparsedRuleID) {
			t.Fatalf("%s: benign Local Edit patch action=%s: %s", mode, action, response)
		}
	}

	protected := body("*** Begin Patch\n*** Add File: " + filepath.Join(home, ".ssh", "authorized_keys") +
		"\n+ssh-ed25519 AAAA example\n*** End Patch\n")
	action, response := post("action", protected)
	if action != "block" || strings.Contains(response, hookToolCallUnparsedRuleID) {
		t.Fatalf("protected Local Edit patch action=%s, want a rule block: %s", action, response)
	}

	action, response = post("action", body("change beta1 to beta2"))
	if action != "block" || !strings.Contains(response, hookToolCallUnparsedRuleID) {
		t.Fatalf("a non-patch string tool_input must stay unread: action=%s: %s", action, response)
	}
}

// GAP-2605: the Copilot CLI (1.0.91) sends its create call to the Local
// hooks as Write {"path", "file_text"} (live capture on managed Windows,
// cwd moved to a test project). It is judged as the CLI create call: a
// project file is allowed in observe and action, a protected target is
// refused by its rule, and neither is HOOK-TOOL-CALL-UNPARSED. An argument
// set the gateway cannot read stays unread (fail closed).
func TestCopilotVSCodeLocalWriteIsJudgedAsTheCLICreateCall(t *testing.T) {
	project := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	body := func(input map[string]any) string {
		raw, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "session_id": "e4933380-e456-4247-8a28-e5460345d7cd",
			"timestamp": "2026-10-30T04:16:52.830Z", "cwd": project, "tool_name": "Write", "tool_input": input,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	post := func(mode, payload string) (string, string) {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = mode
		cfg.Guardrail.Connector = "copilot"
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Copilot-Event", "PreToolUse")
		req.Header.Set(connector.HookDialectHeader, connector.CopilotHookSurfaceVSCodeLocal)
		req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("copilot", connector.CopilotHookSurfaceVSCodeLocal, "PreToolUse", []byte(payload)))
		w := httptest.NewRecorder()
		api.handleAgentHook("copilot").ServeHTTP(w, req)
		var verdict struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil || w.Code != http.StatusOK {
			t.Fatalf("status=%d err=%v body=%s", w.Code, err, w.Body.String())
		}
		return verdict.Action, w.Body.String()
	}

	benign := body(map[string]any{"file_text": "delta", "path": filepath.Join(project, "p4.txt")})
	for _, mode := range []string{"observe", "action"} {
		action, response := post(mode, benign)
		if action != "allow" || strings.Contains(response, hookToolCallUnparsedRuleID) {
			t.Fatalf("%s: benign Local Write action=%s: %s", mode, action, response)
		}
	}

	protected := body(map[string]any{"file_text": "ssh-ed25519 AAAA example\n", "path": filepath.Join(home, ".ssh", "authorized_keys")})
	action, response := post("action", protected)
	if action != "block" || strings.Contains(response, hookToolCallUnparsedRuleID) {
		t.Fatalf("protected Local Write action=%s, want a rule block: %s", action, response)
	}

	unread := body(map[string]any{"file_text": "delta", "path": filepath.Join(project, "p5.txt"), "target": filepath.Join(project, "p6.txt")})
	action, response = post("action", unread)
	if action != "block" || !strings.Contains(response, hookToolCallUnparsedRuleID) {
		t.Fatalf("an unknown Write argument must stay unread in action: action=%s: %s", action, response)
	}
}
