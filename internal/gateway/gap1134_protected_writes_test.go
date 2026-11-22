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
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1134: on Linux and macOS a pwsh -Command write of an agent hook
// config spelled with $HOME or ~ was allowed by a managed gateway (a
// hook-socket peer that cannot open the home) on every connector, where the
// per-user gateway alerts; the pwsh .NET file writes and New-Item -Value of
// a hook config or the DefenseClaw state, the $HOME and ~ pwsh writes of the
// state and a python3 -c open() write of the state were allowed on both
// installs. The PowerShell write reader now also reads the script of each
// pwsh launcher of a Linux or macOS call (actionfacts.PowerShellLauncherScripts,
// with the home the shell expands spelled out), PowerShell's $HOME and ~
// name the home there, the hook client lists that script's targets for the
// peer, and the inline-code hand-off reads the files the code itself opens
// for writing, placed where the hook client ran the call. Every protected
// cell is caught on both installs, in both packs, through every connector;
// the same writes of a project file stay allowed.
//
// GAP-1135: a managed gateway gave a Claude Code or Codex shell call no
// working directory (it cannot resolve the session cwd in the home), so a
// bare name written in the state folder, or a link in the project onto the
// state, was placed nowhere and allowed. The call keeps the cwd it had, and
// the state-write proof also runs on the call placed in the hook client's
// folder (managedLinkWalkView), so these rows block.
// gap1134PwshForms are the pwsh launcher writes of GAP-1134; %s is the
// target, spelled as the row's spelling says. GAP-1214 runs the script of
// each as a PowerShell tool call (gap1214ToolBody).
var gap1134PwshForms = []struct{ id, text string }{
	{"Add-Content", `pwsh -NoProfile -Command "Add-Content -Path %s -Value zz"`},
	{"Set-Content", `pwsh -NoProfile -Command "Set-Content -Path %s -Value zz"`},
	{"New-Item -Value", `pwsh -NoProfile -Command "New-Item -Path %s -ItemType File -Value zz -Force"`},
	{"WriteAllText", `pwsh -NoProfile -Command "[IO.File]::WriteAllText('%s', 'zz')"`},
	{"AppendAllText", `pwsh -NoProfile -Command "[System.IO.File]::AppendAllText('%s', 'zz')"`},
	{"StreamWriter", `pwsh -NoProfile -Command '$w = [System.IO.StreamWriter]::new("%s", $true); $w.WriteLine("zz"); $w.Close()'`},
}

func TestGAP1134ProtectedWritesManagedAndPerUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Linux and macOS pwsh launcher reading; Windows reads the call in PowerShell (GAP-1115)")
	}
	home := filepath.Join(t.TempDir(), "home")
	project := filepath.Join(home, "proj")
	for name, body := range map[string]string{
		filepath.Join(home, ".codex", "config.toml"):       gap0048CodexConfig,
		filepath.Join(home, ".claude", "settings.json"):    "{}\n",
		filepath.Join(home, ".defenseclaw", "config.yaml"): "fixture: 1\n",
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
	for _, key := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	hookRules := []string{agentHookConfigWriteRuleID, agentHookConfigDisableRuleID}
	stateRule := "tamper.detector_state_write"
	allRules := append([]string{stateRule}, hookRules...)
	targets := []struct {
		name, rel string
		rules     []string // nil: the control, a project file
	}{
		{"state", ".defenseclaw/config.yaml", []string{stateRule}},
		{"codex-config", ".codex/config.toml", hookRules},
		{"claude-settings", ".claude/settings.json", hookRules},
		{"project", "proj/out.txt", nil},
	}
	if err := os.Symlink(filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(project, "link-state")); err != nil {
		t.Fatal(err)
	}
	forms := append(slices.Clone(gap1134PwshForms), struct{ id, text string }{"python open", `python3 -c "open('%s','a').write('zz')"`})
	spellings := map[string][]string{
		"Add-Content":     {"$HOME", "~", "abs"},
		"Set-Content":     {"$HOME", "~", "abs"},
		"New-Item -Value": {"$HOME", "~", "abs"},
		"WriteAllText":    {"abs"},
		"AppendAllText":   {"abs"},
		"StreamWriter":    {"abs"},
		"python open":     {"abs"},
	}
	judge := func(t *testing.T, handler http.HandlerFunc, conn, command, cwd string, peer bool) string {
		t.Helper()
		event, route := "PreToolUse", "/api/v1/"+conn+"/hook"
		var payload []byte
		switch conn {
		case "devin":
			payload = mustJSON(t, map[string]any{"hook_event_name": event, "session_id": "g1134", "prompt_id": "p1", "cwd": cwd,
				"tool_name": "exec", "tool_input": map[string]any{"command": command, "workdir": cwd}})
		case "antigravity":
			payload = mustJSON(t, map[string]any{"conversationId": "g1134", "stepIdx": 1, "workspacePaths": []string{project},
				"toolCall": map[string]any{"name": "run_command",
					"args": map[string]any{"Cwd": cwd, "CommandLine": command, "WaitMsBeforeAsync": 5000}}})
		case "codex":
			route = "/api/v1/hook"
			payload = mustJSON(t, map[string]any{"hook_event_name": event, "session_id": "g1134-cx", "cwd": cwd, "tool_name": "Bash",
				"tool_use_id": "t1", "turn_id": "u1", "tool_input": map[string]any{"command": command}})
		default:
			route = "/api/v1/hook"
			payload = mustJSON(t, map[string]any{"session_id": "g1134-cc", "hook_event_name": event, "cwd": cwd,
				"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_g1134", "tool_input": map[string]any{"command": command}})
		}
		req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		switch conn {
		case "antigravity":
			req.Header.Set("X-DefenseClaw-Antigravity-Event", event)
		case "codex":
			setTestCodexHookBinding(req, event, defaultTestCodexHookContract)
		}
		// The hook client runs as the user, before the gateway judges.
		if header := hookpaths.ResolveConnector(conn, "", event, payload); header != "" {
			req.Header.Set(hookpaths.Header, header)
		}
		if peer {
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{UID: 1000, GID: 1000, PID: 1, Name: "g1134", Home: home}))
			// The managed gateway cannot open the home while it judges.
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
	hit := func(body string, rules []string) bool {
		for _, rule := range rules {
			if strings.Contains(body, rule) {
				return true
			}
		}
		return false
	}
	for _, pack := range []string{"default", "strict"} {
		for _, conn := range []string{"claudecode", "codex", "devin", "antigravity"} {
			t.Run(pack+"/"+conn, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, conn, pack)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = conn
				store, logger := testStoreAndLogger(t)
				handler := (&APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}).handleAgentHook(conn)
				for _, target := range targets {
					for _, form := range forms {
						for _, spelling := range spellings[form.id] {
							word := filepath.Join(home, target.rel)
							switch spelling {
							case "$HOME":
								word = "$HOME/" + target.rel
							case "~":
								word = "~/" + target.rel
							}
							command := fmt.Sprintf(form.text, word)
							for _, peer := range []bool{false, true} {
								install := "per-user"
								if peer {
									install = "managed peer"
								}
								got := judge(t, handler, conn, command, project, peer)
								action := hookConfigAction(got)
								switch {
								case target.rules == nil && (action != "allow" || hit(got, allRules)):
									t.Errorf("%s %s %s of the project file: %s, want allow with no protected-write rule\n%s",
										install, form.id, spelling, action, got)
								case target.rules != nil && (action == "allow" || !hit(got, target.rules)):
									t.Errorf("%s %s %s of %s: %s, want %v and not allow\n%s",
										install, form.id, spelling, target.name, action, target.rules, got)
								}
							}
						}
					}
				}
				// GAP-1135: the state written by a bare name in its folder and
				// through a link in the project.
				for _, row := range []struct{ id, cwd, command string }{
					{"bare name in the state folder", filepath.Join(home, ".defenseclaw"), "echo zz >> config.yaml"},
					{"link redirect", project, "echo zz >> link-state"},
					{"link cp", project, "cp out.txt link-state"},
				} {
					for _, peer := range []bool{false, true} {
						got := judge(t, handler, conn, row.command, row.cwd, peer)
						if action := hookConfigAction(got); action == "allow" || !hit(got, []string{stateRule}) {
							t.Errorf("peer=%v %s: %s, want %s and not allow\n%s", peer, row.id, action, stateRule, got)
						}
					}
				}
			})
		}
	}
}
