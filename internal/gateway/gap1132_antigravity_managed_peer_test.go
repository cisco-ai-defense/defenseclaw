// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1132: the agy hook client read only the Claude Code shaped
// tool_name/tool_input, so it listed no write targets for an agy toolCall
// and a managed Linux or macOS gateway (a hook-socket peer that cannot open
// the home) allowed an agy run_command write that only the client can place
// (through a link in the project, or a pwsh write of a hook config), where
// the per-user gateway, and the managed one for Claude Code Bash, block or
// alert. The client now reads the toolCall (antigravityargs) and the command
// under CommandLine (actionfacts.ShellCommandArgument), as the gateway does,
// so agy is judged as Claude Code is on both installs. send_command_input is
// judged as run_command input on both sides.
func TestGAP1132AntigravityManagedPeerPlacesTheCallTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a managed Windows hook client sends no tool-call targets")
	}
	home := filepath.Join(t.TempDir(), "home")
	project := filepath.Join(home, "proj")
	for name, body := range map[string]string{
		filepath.Join(home, ".codex", "config.toml"):       gap0048CodexConfig,
		filepath.Join(home, ".claude", "settings.json"):    "{}\n",
		filepath.Join(home, ".defenseclaw", "config.yaml"): "fixture: 1\n",
		filepath.Join(project, "notes.txt"):                "x\n",
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, key := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	hookRules := []string{agentHookConfigWriteRuleID, agentHookConfigDisableRuleID}
	targets := []struct {
		name, rel string
		rules     []string
	}{
		{"state", ".defenseclaw/config.yaml", []string{"tamper.detector_state_write"}},
		{"codex-config", ".codex/config.toml", hookRules},
		{"claude-settings", ".claude/settings.json", hookRules},
	}
	for _, target := range targets {
		if err := os.Symlink(filepath.Join(home, target.rel), filepath.Join(project, "link-"+target.name)); err != nil {
			t.Fatal(err)
		}
	}
	type row struct{ id, command, tool string }
	rowsFor := func(name, rel string) []row {
		abs := filepath.Join(home, rel)
		return []row{
			{"link redirect", "echo zz >> link-" + name, "run_command"},
			{"link cp", "cp notes.txt link-" + name, "run_command"},
			{"send_command_input link redirect", "echo zz >> link-" + name, "send_command_input"},
			{"pwsh Add-Content", `pwsh -NoProfile -Command "Add-Content -Path ` + abs + ` -Value zz"`, "run_command"},
			{"pwsh Set-Content", `pwsh -NoProfile -Command "Set-Content -Path ` + abs + ` -Value zz"`, "run_command"},
		}
	}
	judge := func(t *testing.T, handler http.HandlerFunc, conn string, r row, peer bool) string {
		t.Helper()
		var payload []byte
		route := "/api/v1/" + conn + "/hook"
		if conn == "antigravity" {
			args := map[string]any{"Cwd": project, "CommandLine": r.command, "WaitMsBeforeAsync": 5000}
			if r.tool == "send_command_input" {
				args = map[string]any{"CommandId": "c1", "Input": r.command, "WaitMs": 500}
			}
			payload = mustJSON(t, map[string]any{"conversationId": "g1132", "stepIdx": 1, "workspacePaths": []string{project},
				"toolCall": map[string]any{"name": r.tool, "args": args}})
		} else {
			route = "/api/v1/hook"
			payload = mustJSON(t, map[string]any{"session_id": "g1132-cc", "hook_event_name": "PreToolUse", "cwd": project,
				"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_g1132", "tool_input": map[string]any{"command": r.command}})
		}
		req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		if conn == "antigravity" {
			req.Header.Set("X-DefenseClaw-Antigravity-Event", "PreToolUse")
		}
		if header := hookpaths.ResolveConnector(conn, "", "PreToolUse", payload); header != "" {
			req.Header.Set(hookpaths.Header, header)
		}
		if peer {
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{UID: 1000, GID: 1000, PID: 1, Name: "g1132", Home: home}))
			// The managed gateway cannot open the caller's home.
			if os.Geteuid() != 0 {
				if err := os.Chmod(home, 0); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(home, 0o700)
			}
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	for _, pack := range []string{"default", "strict"} {
		for _, conn := range []string{"antigravity", "claudecode"} {
			t.Run(pack+"/"+conn, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, conn, pack)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = conn
				store, logger := testStoreAndLogger(t)
				handler := (&APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}).handleAgentHook(conn)
				for _, target := range targets {
					for _, r := range rowsFor(target.name, target.rel) {
						if conn != "antigravity" && r.tool == "send_command_input" {
							continue
						}
						for _, peer := range []bool{false, true} {
							got := judge(t, handler, conn, r, peer)
							hit := false
							for _, rule := range target.rules {
								hit = hit || strings.Contains(got, rule)
							}
							if !hit || hookConfigAction(got) == "allow" {
								t.Errorf("%s|%s|peer=%v: want one of %v, not allow: %.600s", target.name, r.id, peer, target.rules, got)
							}
						}
					}
				}
			})
		}
	}
}
