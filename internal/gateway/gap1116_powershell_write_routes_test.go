// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
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

// GAP-1116 (Devin exec) and GAP-1117 (Antigravity run_command, its command
// under CommandLine) are GAP-1115 on the other routes that carry PowerShell
// on Windows, as is the Claude Code PowerShell tool: a PowerShell write of
// another agent's hook config (Codex's, Claude Code's, written from a Devin
// or Antigravity session), of the connector's own, or of the DefenseClaw
// state is judged as the redirect is, in the default and strict packs, on a
// per-user install and behind a managed standalone gateway. Reads and an
// unprotected write raise none of these rules. Each route is its own test so
// the Windows shard planner can place them apart.
func TestGAP1115PowerShellWriteRouteDevinExec(t *testing.T) {
	gap1116PowerShellWriteRoute(t, "devin", `AppData\Roaming\devin\config.json`)
}

func TestGAP1115PowerShellWriteRouteAntigravityRunCommand(t *testing.T) {
	gap1116PowerShellWriteRoute(t, "antigravity", `.gemini\config\hooks.json`)
}

func TestGAP1115PowerShellWriteRouteClaudeCodePowerShellTool(t *testing.T) {
	gap1116PowerShellWriteRoute(t, "claudecode", `.claude\settings.local.json`)
}

// gap1116PowerShellWriteRoute judges gap1115Forms through conn's hook route
// as the gateway receives that connector's shell tool call; own is the
// connector's own hook config under the home.
func gap1116PowerShellWriteRoute(t *testing.T, conn, own string) {
	if runtime.GOOS != "windows" {
		t.Skip("the PowerShell reading holds for a Windows home on a Windows host")
	}
	home := filepath.Join(t.TempDir(), "home")
	project := filepath.Join(home, "proj")
	for name, body := range map[string]string{
		filepath.Join(home, ".codex", "config.toml"):       gap0048CodexConfig,
		filepath.Join(home, ".claude", "settings.json"):    "{}\n",
		filepath.Join(home, own):                           "{}\n",
		filepath.Join(home, ".defenseclaw", "config.yaml"): "fixture: 1\n",
		filepath.Join(project, "notes.txt"):                "x\n",
		filepath.Join(project, "out.txt"):                  "x\n",
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	for _, key := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	hookRules := []string{agentHookConfigWriteRuleID, agentHookConfigDisableRuleID}
	stateRules := []string{"tamper.detector_state_write"}
	// rules are the rules one of which a write raises; none for the
	// unprotected file.
	targets := []struct {
		name, rel string
		rules     []string
	}{
		{"codex config", `.codex\config.toml`, hookRules},
		{"claude settings", `.claude\settings.json`, hookRules},
		{"own hook config", own, hookRules},
		{"DefenseClaw state", `.defenseclaw\config.yaml`, stateRules},
		{"project file", `proj\out.txt`, nil},
	}
	protectedRules := append(append([]string{}, hookRules...), stateRules...)
	judge := func(t *testing.T, handler http.HandlerFunc, command string, peer bool) string {
		t.Helper()
		event, route := "PreToolUse", "/api/v1/"+conn+"/hook"
		var payload []byte
		switch conn {
		case "devin":
			payload = mustJSON(t, map[string]any{"hook_event_name": event, "session_id": "gap1116", "prompt_id": "p1", "cwd": project,
				"tool_name": "exec", "tool_input": map[string]any{"command": command, "workdir": project}})
		case "antigravity":
			payload = mustJSON(t, map[string]any{"conversationId": "gap1117", "stepIdx": 1, "workspacePaths": []string{project},
				"toolCall": map[string]any{"name": "run_command",
					"args": map[string]any{"Cwd": project, "CommandLine": command, "WaitMsBeforeAsync": 5000}}})
		default:
			route = "/api/v1/hook"
			payload = mustJSON(t, map[string]any{"session_id": "gap1115-cc", "hook_event_name": event, "cwd": project,
				"tool_name": "PowerShell", "tool_input": map[string]any{"command": command}})
		}
		req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		if conn == "antigravity" {
			req.Header.Set("X-DefenseClaw-Antigravity-Event", event)
		}
		if header := hookpaths.ResolveConnector(conn, "", event, payload); header != "" {
			req.Header.Set(hookpaths.Header, header)
		}
		if peer {
			// A managed standalone install: the gateway cannot open the
			// caller's home and places paths from the client map.
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{UID: 1000, GID: 1000, PID: 1, Name: "gap1116", Home: home}))
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	checked := 0
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, conn, pack)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = conn
			store, logger := testStoreAndLogger(t)
			handler := (&APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}).handleAgentHook(conn)
			// The strict pack's absolute spelling is the cert repro; the
			// $HOME spelling is checked in the default pack.
			spellings := []string{"absolute", "$HOME"}
			if pack == "strict" {
				spellings = spellings[:1]
			}
			for _, peer := range []bool{false, true} {
				for _, target := range targets {
					for _, spelling := range spellings {
						for _, form := range gap1115Forms {
							// A .NET argument is an expression: $HOME is
							// expanded inside a double-quoted string there.
							word := "'" + filepath.Join(home, target.rel) + "'"
							if spelling == "$HOME" {
								word = `$HOME\` + target.rel
								if strings.Contains(form.text, "(%s") {
									word = `"` + word + `"`
								}
							}
							name := fmt.Sprintf("%s|peer=%v|%s|%s|%s", conn, peer, target.name, spelling, form.id)
							got := judge(t, handler, fmt.Sprintf(form.text, word), peer)
							checked++
							if form.write && len(target.rules) > 0 {
								hit := false
								for _, rule := range target.rules {
									hit = hit || strings.Contains(got, rule)
								}
								if !hit || hookConfigAction(got) == "allow" {
									t.Errorf("%s: want a block by one of %v as for the redirect: %.600s", name, target.rules, got)
								}
								continue
							}
							for _, rule := range protectedRules {
								if strings.Contains(got, rule) {
									t.Errorf("%s: a read or an unprotected write raised %s: %.600s", name, rule, got)
								}
							}
							// The strict tier keeps its own reading of
							// what it cannot prove.
							if pack != "strict" && len(target.rules) == 0 && hookConfigAction(got) != "allow" {
								t.Errorf("%s: an unprotected write is %s: %.600s", name, hookConfigAction(got), got)
							}
						}
					}
				}
			}
		})
	}
	t.Logf("%s cells checked: %d", conn, checked)
}
