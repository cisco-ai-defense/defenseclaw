// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestR104LeadPrivateKeyReaderForms(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_rsa"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installDefaultProfileConnector(t, "claudecode")
	api := activeClaudeCodeTestAPI()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	for _, command := range []string{
		`cat ~/.ssh/id_rsa`,
		`sed -n 1p ~/.ssh/id_rsa`,
		`gsed -n 1p ~/.ssh/id_rsa`,
		`awk 'NR==1 {print}' ~/.ssh/id_rsa`,
		`tail -n 1 "$HOME/.ssh/id_rsa"`,
		`head -c 0 ~/.ssh/id_rsa`,
		`python3 -c "from pathlib import Path; print(Path.home().joinpath('.ssh/id_rsa').read_text())"`,
	} {
		t.Run(command, func(t *testing.T) {
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "lead-private-key-reader", CWD: cwd,
				ToolName: "Bash", ToolInput: map[string]interface{}{"command": command},
				Payload: map[string]interface{}{"tool_name": "Bash"},
			})
			if resp.Action != "block" || !strings.Contains(strings.Join(resp.Findings, ","), "PATH-SSH-KEY:") {
				t.Fatalf("reader action=%q findings=%v", resp.Action, resp.Findings)
			}
		})
	}
	for _, command := range []string{
		`gsed -n 1p report.txt`,
		`awk 'NR==1 {print}' report.txt`,
		`tail -n 1 "$HOME/report.txt"`,
		`python3 -c "from pathlib import Path; print(Path.home().joinpath('report.txt').read_text())"`,
		`python3 -c "from pathlib import Path; print(Path.home().joinpath('.ssh/id_rsa').stat())"`,
		`ssh -i ~/.ssh/id_rsa build.example.com true`,
	} {
		t.Run("control "+command, func(t *testing.T) {
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "lead-private-key-control", CWD: cwd,
				ToolName: "Bash", ToolInput: map[string]interface{}{"command": command},
				Payload: map[string]interface{}{"tool_name": "Bash"},
			})
			if resp.Action == "block" {
				t.Fatalf("ordinary or metadata-only reader blocked: %q findings=%v", command, resp.Findings)
			}
		})
	}
}

func TestR104LeadProtectedCopyControl(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"GAP-0298 cp Z protected", "cp -Z report.txt " + filepath.Join(home, ".ssh", "authorized_keys"), true},
		{"GAP-0298 cp Z ordinary", "cp -Z report.txt " + filepath.Join(cwd, "ordinary.txt"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, got := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if got != tc.blocked {
					t.Fatalf("route %d blocked=%v, want %v", i, got, tc.blocked)
				}
			}
			args, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			response := api.evaluateAgentHook(withManagedHookPeer(context.Background(), managedHookPeer{Home: home}),
				agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", ToolName: "Bash", ToolArgs: args, CWD: cwd})
			if got := response.Action == "block"; got != tc.blocked {
				t.Fatalf("native Claude copy action=%q findings=%v rules=%v", response.Action, response.Findings, response.RuleIDs)
			}
			body := mustJSON(t, map[string]any{"session_id": "lead-copy", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": cwd, "tool_input": map[string]any{"command": tc.command}})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
			req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			writer := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(writer, req)
			if got := strings.HasPrefix(writer.Body.String(), `{"action":"block"`); got != tc.blocked {
				t.Fatalf("registered Claude copy status=%d body=%s", writer.Code, writer.Body.String())
			}
		})
	}
}

func TestR104LeadHermesPatchLink(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	link := filepath.Join(cwd, "w0-v4a-link")
	if err := os.Symlink(filepath.Join(cwd, "d")+"\n*** Add File: "+filepath.Join(home, ".ssh", "authorized_keys"), link); err != nil {
		t.Fatal(err)
	}
	ordinaryLink := filepath.Join(cwd, "ordinary-newline-link")
	if err := os.Symlink(filepath.Join(cwd, "out\nnotes.txt"), ordinaryLink); err != nil {
		t.Fatal(err)
	}
	for i, blocked := range r104ReviewProtectedWrite(t, `echo marker > ordinary-newline-link`, cwd, home) {
		if blocked {
			t.Fatalf("ordinary shell write through newline link blocked on route %d", i)
		}
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	api := &APIServer{scannerCfg: cfg}
	for _, tc := range []struct {
		name, target string
		blocked      bool
	}{
		{"GAP-0068 directive-bearing link", "w0-v4a-link", true},
		{"GAP-0068 ordinary patch", "ordinary.txt", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			patch := "*** Begin Patch\n*** Add File: " + tc.target + "\n+marker\n*** End Patch\n"
			args, err := json.Marshal(map[string]string{"mode": "patch", "patch": patch})
			if err != nil {
				t.Fatal(err)
			}
			response := api.evaluateAgentHook(withManagedHookPeer(context.Background(), managedHookPeer{Home: home}),
				agentHookRequest{ConnectorName: "hermes", HookEventName: "pre_tool_call", ToolName: "patch", ToolArgs: args, CWD: cwd})
			if got := response.Action == "block"; got != tc.blocked {
				t.Fatalf("Hermes patch action=%q findings=%v rules=%v", response.Action, response.Findings, response.RuleIDs)
			}
		})
	}
	replaceArgs, err := json.Marshal(map[string]string{
		"path": "ordinary-newline-link", "old_string": "marker", "new_string": "updated",
	})
	if err != nil {
		t.Fatal(err)
	}
	replace := api.evaluateAgentHook(withManagedHookPeer(context.Background(), managedHookPeer{Home: home}),
		agentHookRequest{ConnectorName: "hermes", HookEventName: "pre_tool_call", ToolName: "patch", ToolArgs: replaceArgs, CWD: cwd})
	if replace.Action == "block" {
		t.Fatalf("ordinary Hermes replace link blocked: findings=%v rules=%v", replace.Findings, replace.RuleIDs)
	}
}

func TestR104LeadOpenClawInspectHome(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	installDefaultProfileConnector(t, "openclaw")
	api := testAPIServerWithConfig(t, "action")
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"GAP-0304 home path", `echo marker >> ~/.ssh/authorized_keys`, true},
		{"GAP-0304 absolute control", "echo marker >> " + filepath.Join(home, ".ssh", "authorized_keys"), true},
		{"GAP-0304 benign", `echo marker >> report.txt`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]any{"command": tc.command, "workdir": cwd})
			if err != nil {
				t.Fatal(err)
			}
			verdict := api.inspectToolPolicyCtx(ctx, &ToolInspectRequest{Tool: "exec", Args: args, Connector: "openclaw"})
			if got := verdict.Action == "block"; got != tc.blocked {
				t.Fatalf("inspect action=%q severity=%q reason=%q, want blocked=%v", verdict.Action, verdict.Severity, verdict.Reason, tc.blocked)
			}
		})
	}
}
