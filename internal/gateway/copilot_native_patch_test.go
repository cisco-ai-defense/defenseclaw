// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestCopilotNativeBenignCorpus(t *testing.T) {
	f, err := os.Open("testdata/copilot-native-benign.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
		var item struct {
			ID      string         `json:"id"`
			OS      string         `json:"os"`
			Fixture string         `json:"fixture"`
			Event   string         `json:"event"`
			Input   map[string]any `json:"input"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			t.Fatal(err)
		}
		t.Run(item.ID, func(t *testing.T) {
			if item.Event == "permissionRequest" {
				if args, ok := item.Input["toolInput"].(map[string]any); ok && len(args) == 0 {
					if !copilotEmptyPermissionArgs(item.Input) {
						t.Fatal("empty native permission callback could not join an audited pre-tool allow")
					}
					return
				}
				if len(copilotargs.PermissionToolArgs("edit", item.Input["toolInput"])) == 0 {
					t.Fatal("native creation diff did not project")
				}
				return
			}
			body, err := json.Marshal(item.Input)
			if err != nil {
				t.Fatal(err)
			}
			if item.OS != runtime.GOOS || item.Fixture == "managed-private-home" {
				if _, ok := copilotargs.NativeCalls(item.Input["toolCalls"]); !ok {
					t.Fatalf("%s native tool calls did not project", item.OS)
				}
				return
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("copilot", "", "preToolUse", body))
			w := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(w, req)
			var verdict struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict.Action != "allow" || strings.Contains(w.Body.String(), hookToolCallUnparsedRuleID) {
				t.Fatalf("%s native benign project patch action=%s: %s", item.OS, verdict.Action, w.Body.String())
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 15 {
		t.Fatalf("native benign corpus has %d cases, want 15", count)
	}
}

func TestNativeCopilotPatchProjectAndProtectedTargets(t *testing.T) {
	project := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, target, want string
	}{
		{"native T9 relative project file", "notes07-default.txt", "allow"},
		{"native absolute project file", filepath.Join(project, "README.md"), "allow"},
		{"protected target in native patch", filepath.Join(home, ".ssh", "authorized_keys"), "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			patch := "*** Begin Patch\n*** Add File: " + tc.target + "\n+ordinary edit\n*** End Patch\n"
			body, err := json.Marshal(map[string]any{"sessionId": "native-session", "cwd": project,
				"toolCalls": []any{map[string]any{"id": "custom_call_native", "name": "apply_patch", "args": patch}}})
			if err != nil {
				t.Fatal(err)
			}
			action, response := postHookDecision(t, "copilot", "", string(body))
			if action != tc.want || strings.Contains(response, hookToolCallUnparsedRuleID) {
				t.Fatalf("action=%s want=%s: %s", action, tc.want, response)
			}
			if tc.want == "block" && !strings.Contains(response, "persistence.ssh_authorized_keys_command") {
				t.Fatalf("protected target did not name persistence rule: %s", response)
			}
		})
	}
}

func TestCopilotEmptyPermissionArgsRejectsAmbiguousEnvelope(t *testing.T) {
	base := map[string]any{"hookName": "permissionRequest", "toolName": "edit", "toolInput": map[string]any{}}
	for _, tc := range []struct {
		name, key string
		value     any
	}{
		{"null native calls", "toolCalls", nil},
		{"conflicting snake tool", "tool_name", "powershell"},
		{"conflicting snake input", "tool_input", map[string]any{"file_path": "/home/user/.ssh/authorized_keys"}},
		{"conflicting snake args", "tool_args", map[string]any{"command": "unsafe"}},
		{"conflicting snake event", "hook_event_name", "permissionRequest"},
		{"both argument fields", "toolArgs", map[string]any{}},
		{"null beside argument field", "toolArgs", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := make(map[string]any, len(base)+1)
			for key, value := range base {
				payload[key] = value
			}
			payload[tc.key] = tc.value
			if copilotEmptyPermissionArgs(payload) {
				t.Fatal("ambiguous permission callback reused a prior allow")
			}
		})
	}
}

func TestCopilotPermissionJoinCapacityStillInvalidatesPrior(t *testing.T) {
	ctx := context.Background()
	pre := agentHookRequest{ConnectorName: "copilot", HookEventName: "preToolUse", SessionID: "native",
		CWD: "/tmp/native", ToolName: "apply_patch"}
	scope := copilotPermissionKey(ctx, pre)
	if scope == "" {
		t.Fatal("expected verified per-user scope")
	}
	join := copilotPermissionJoin{entries: map[string]copilotPermissionEntry{
		copilotPermissionToolKey(scope, "apply_patch"): {calls: []copilotargs.NativeCall{{Name: "apply_patch",
			Args: json.RawMessage(`"*** Begin Patch\n*** Add File: README.md\n+x\n*** End Patch\n"`)}}, uses: 1, at: time.Now()},
	}}
	for i := 1; i < copilotPermissionJoinMax; i++ {
		join.entries["other"+strconv.Itoa(i)] = copilotPermissionEntry{at: time.Now()}
	}
	join.record(ctx, pre, false)
	permission := agentHookRequest{ConnectorName: "copilot", HookEventName: "permissionRequest",
		SessionID: "native", CWD: "/tmp/native", ToolName: "edit",
		Payload: map[string]any{"hookName": "permissionRequest", "toolName": "edit", "toolInput": map[string]any{}}}
	if _, _, ok := join.match(ctx, permission, []byte(`{"hookName":"permissionRequest","toolName":"edit","toolInput":{}}`)); ok {
		t.Fatal("protected call left an earlier allowed decision reusable at cache capacity")
	}
}

func TestNativeCopilotEmptyPermissionReusesAuditedPreToolAllow(t *testing.T) {
	project := t.TempDir()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	post := func(event string, input map[string]any) (string, string) {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
		req.Header.Set("X-DefenseClaw-Copilot-Event", event)
		w := httptest.NewRecorder()
		api.handleAgentHook("copilot").ServeHTTP(w, req)
		var verdict struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
			t.Fatalf("invalid response: %v: %s", err, w.Body.String())
		}
		return verdict.Action, w.Body.String()
	}
	permission := func(session string) map[string]any {
		return map[string]any{"hookName": "permissionRequest", "sessionId": session,
			"cwd": project, "toolName": "edit", "toolInput": map[string]any{}}
	}
	if action, _ := post("permissionRequest", permission("native-session")); action != "block" {
		t.Fatalf("permission without prior preToolUse action=%s", action)
	}
	patch := "*** Begin Patch\n*** Add File: README.md\n+ordinary project text\n*** End Patch\n"
	pre := map[string]any{"sessionId": "native-session", "cwd": project,
		"toolCalls": []any{map[string]any{"id": "custom_call_native", "name": "apply_patch", "args": patch}}}
	if action, body := post("preToolUse", pre); action != "allow" {
		t.Fatalf("preToolUse action=%s: %s", action, body)
	}
	if action, body := post("permissionRequest", permission("other-session")); action != "block" {
		t.Fatalf("different session action=%s: %s", action, body)
	}
	if action, body := post("permissionRequest", permission("native-session")); action != "allow" {
		t.Fatalf("matching permission action=%s: %s", action, body)
	}
	if action, body := post("permissionRequest", permission("native-session")); action != "block" {
		t.Fatalf("replayed empty permission action=%s: %s", action, body)
	}
	protected := map[string]any{"sessionId": "blocked-session", "cwd": project,
		"toolCalls": []any{map[string]any{"id": "safe-first", "name": "apply_patch", "args": patch}}}
	if action, body := post("preToolUse", protected); action != "allow" {
		t.Fatalf("preceding safe call action=%s: %s", action, body)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	protected["toolCalls"] = []any{map[string]any{"id": "protected-second", "name": "apply_patch",
		"args": "*** Begin Patch\n*** Add File: " + filepath.Join(home, ".ssh", "authorized_keys") + "\n+ssh-ed25519 example\n*** End Patch\n"}}
	if action, body := post("preToolUse", protected); action != "block" {
		t.Fatalf("protected second call action=%s: %s", action, body)
	}
	if action, body := post("permissionRequest", permission("blocked-session")); action != "block" {
		t.Fatalf("permission after protected call action=%s: %s", action, body)
	}
	pre["sessionId"] = "mismatch-session"
	pre["toolCalls"] = []any{map[string]any{"id": "safe-mismatch", "name": "apply_patch", "args": patch}}
	if action, body := post("preToolUse", pre); action != "allow" {
		t.Fatalf("preToolUse before mismatched permission action=%s: %s", action, body)
	}
	mismatch := permission("mismatch-session")
	mismatch["toolName"] = "powershell"
	if action, body := post("permissionRequest", mismatch); action != "block" {
		t.Fatalf("mismatched permission action=%s: %s", action, body)
	}
	if action, body := post("permissionRequest", permission("mismatch-session")); action != "block" {
		t.Fatalf("permission after mismatched callback action=%s: %s", action, body)
	}
	created := filepath.Join(project, "new.txt")
	gitPath := strings.TrimPrefix(strings.ReplaceAll(created, `\`, "/"), "/")
	diff := "\ndiff --git a/" + gitPath + " b/" + gitPath +
		"\ncreate file mode 100644\nindex 0000000..0000000\n--- a/dev/null\n+++ b/" + gitPath +
		"\n@@ -1,0 +1 @@\n+ordinary content\n"
	if action, body := post("permissionRequest", map[string]any{"hookName": "permissionRequest",
		"sessionId": "diff-session", "cwd": project, "toolName": "edit",
		"toolInput": map[string]any{"file_path": created, "diff": diff}}); action != "allow" {
		t.Fatalf("native created-file diff action=%s: %s", action, body)
	}
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	var audited bool
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) && strings.Contains(event.Details, "permissionRequest") &&
			strings.Contains(event.Details, "action=allow") {
			audited = true
		}
	}
	if !audited {
		t.Fatal("permission allow did not receive its own audit row")
	}
}

func TestNativeCopilotUnparsedObserveWarnsAndStrictCloses(t *testing.T) {
	for _, tc := range []struct{ tier, want string }{{"default", "allow"}, {"permissive", "allow"}, {"strict", "block"}} {
		t.Run(tc.tier, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Connector = "copilot"
			cfg.Guardrail.RulePack = tc.tier
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
			body := `{"sessionId":"unparsed-session","cwd":"/tmp/project","toolCalls":[{"id":"c1","name":"apply_patch","args":"not a patch"}]}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			w := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(w, req)
			var verdict struct {
				Action  string   `json:"action"`
				RuleIDs []string `json:"rule_ids"`
				Reason  string   `json:"reason"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict.Action != tc.want || !strings.Contains(w.Body.String(), hookToolCallUnparsedRuleID) || verdict.Reason == "" {
				t.Fatalf("tier=%s action=%s want=%s: %s", tc.tier, verdict.Action, tc.want, w.Body.String())
			}
			if events, err := store.ListEvents(20); err != nil || len(events) == 0 {
				t.Fatalf("unparsed decision was not audited: %v, %d events", err, len(events))
			}
		})
	}
	t.Run("default action remains closed", func(t *testing.T) {
		action, response := postHookDecision(t, "copilot", "",
			`{"sessionId":"unparsed-action","cwd":"/tmp/project","toolCalls":[{"id":"c1","name":"apply_patch","args":"not a patch"}]}`)
		if action != "block" || !strings.Contains(response, hookToolCallUnparsedRuleID) {
			t.Fatalf("unparsed action-mode request=%s: %s", action, response)
		}
	})
}
