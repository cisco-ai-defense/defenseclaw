// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap1214ToolBody is the script a gap1134PwshForms launcher runs, which is
// what a Claude Code PowerShell tool call of the same write sends.
func gap1214ToolBody(t *testing.T, launcher string) string {
	t.Helper()
	const prefix = "pwsh -NoProfile -Command "
	rest, ok := strings.CutPrefix(launcher, prefix)
	if !ok || len(rest) < 2 || rest[0] != rest[len(rest)-1] {
		t.Fatalf("not a pwsh launcher form: %s", launcher)
	}
	return rest[1 : len(rest)-1]
}

// TestGAP1214PowerShellToolPOSIXHomeWritesFiveTiers is rel-1-0-10:GAP-1214:
// on Linux and macOS a Claude Code PowerShell tool call that wrote the
// DefenseClaw state or an agent hook config with the home spelled $HOME or
// ~, or through a .NET file write or New-Item -Value, was allowed per-user
// and managed, in every pack, where the same script in a pwsh launcher
// (GAP-1134) or the Set-Content of the path written out was judged. The
// tool's command is the script pwsh runs, so it is read the same way. Each
// write is judged as the Set-Content of the written-out path is, in the five
// tiers of the hook route and in observe mode, through the hook client's
// header; reads of the same files, and the same writes of a project file or
// of another file in the home, stay allowed with no protected-write rule.
// The forms are the GAP-1134 launcher table, run as the tool's command.
func TestGAP1214PowerShellToolPOSIXHomeWritesFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a Linux or macOS home; Windows reads the PowerShell call as before (GAP-1115)")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 home")
	}
	home := filepath.Join(t.TempDir(), "home")
	project := filepath.Join(home, "proj")
	for name, body := range map[string]string{
		filepath.Join(home, ".codex", "config.toml"):       gap0048CodexConfig,
		filepath.Join(home, ".claude", "settings.json"):    "{}\n",
		filepath.Join(home, ".defenseclaw", "config.yaml"): "fixture: 1\n",
		filepath.Join(home, "notes", "todo.txt"):           "x\n",
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
		rules     []string // nil: a file of no protected class
	}{
		{"state", ".defenseclaw/config.yaml", []string{stateRule}},
		{"codex-config", ".codex/config.toml", hookRules},
		{"claude-settings", ".claude/settings.json", hookRules},
		{"project", "proj/out.txt", nil},
		{"home-notes", "notes/todo.txt", nil},
	}
	// The spellings that name the file in each form: a cmdlet expands $HOME
	// and the provider home ~; a .NET method opens the path it is given (a
	// "$HOME/..." argument written out is rel-1-0-10:GAP-1138, the same
	// reader).
	spellings := map[string][]string{
		"Add-Content":     {"$HOME", "~", "abs"},
		"Set-Content":     {"$HOME", "~", "abs"},
		"New-Item -Value": {"$HOME", "~", "abs"},
		"WriteAllText":    {"abs"},
		"AppendAllText":   {"abs"},
		"StreamWriter":    {"abs"},
	}
	reads := []struct{ id, text string }{
		{"Get-Content", "Get-Content -Path %s"},
		{"Test-Path", "Test-Path %s"},
	}
	spell := func(spelling, rel string) string {
		switch spelling {
		case "$HOME":
			return "$HOME/" + rel
		case "~":
			return "~/" + rel
		}
		return filepath.Join(home, rel)
	}
	judge := func(t *testing.T, api *APIServer, command string, managed bool) string {
		t.Helper()
		payload := mustJSON(t, map[string]any{"session_id": "g1214", "hook_event_name": "PreToolUse", "cwd": project,
			"permission_mode": "default", "tool_name": "PowerShell", "tool_use_id": "toolu_g1214",
			"tool_input": map[string]any{"command": command}})
		req := httptest.NewRequest("POST", "/api/v1/hook", strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		// The hook client runs as the user, before the gateway judges.
		if header := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", payload); header != "" {
			req.Header.Set(hookpaths.Header, header)
		}
		if managed {
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{UID: 1000, GID: 1000, PID: 1, Name: "g1214", Home: home}))
			// The managed gateway cannot open the home while it judges.
			if err := os.Chmod(home, 0); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(home, 0o700)
		}
		rec := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(rec, req)
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
	type tier struct {
		pack gap0437Pack
		mode string
	}
	tiers := []tier{{gap0437Packs[1], "observe"}, {gap0437Packs[3], "observe"}}
	for _, p := range gap0437Packs {
		tiers = append(tiers, tier{p, "action"})
	}
	writes := 0
	for _, tr := range tiers {
		t.Run(tr.mode+"/"+tr.pack.name, func(t *testing.T) {
			api := gap0437Server(t, tr.pack, "claudecode", tr.mode)
			installToolCallCorpusProfileConnector(t, "claudecode", tr.pack.pack)
			for _, target := range targets {
				// The reference: Set-Content of the path written out, which
				// every tier already judged. Observe mode allows a hook config
				// write (only a write of the state blocks there), so such a
				// row only keeps the reference's answer.
				var want string
				if target.rules != nil {
					want = hookConfigAction(judge(t, api, fmt.Sprintf("Set-Content -Path %s -Value zz", spell("abs", target.rel)), tr.pack.managed))
					if want == "allow" && (tr.mode == "action" || target.name == "state") {
						t.Fatalf("%s: the written-out Set-Content reference is allowed", target.name)
					}
				}
				for _, form := range gap1134PwshForms {
					for _, spelling := range spellings[form.id] {
						command := fmt.Sprintf(gap1214ToolBody(t, form.text), spell(spelling, target.rel))
						got := judge(t, api, command, tr.pack.managed)
						action := hookConfigAction(got)
						writes++
						switch {
						case target.rules == nil && (action != "allow" || hit(got, allRules)):
							t.Errorf("%s %s of %s: %s, want allow with no protected-write rule\n%s", form.id, spelling, target.name, action, got)
						case target.rules != nil && (action != want || want != "allow" && !hit(got, target.rules)):
							t.Errorf("%s %s of %s: %s, want %s (as the written-out Set-Content) by %v\n%s", form.id, spelling, target.name, action, want, target.rules, got)
						}
					}
				}
				for _, read := range reads {
					for _, spelling := range []string{"$HOME", "~", "abs"} {
						got := judge(t, api, fmt.Sprintf(read.text, spell(spelling, target.rel)), tr.pack.managed)
						if action := hookConfigAction(got); action != "allow" || hit(got, allRules) {
							t.Errorf("%s %s of %s: %s, want allow with no protected-write rule\n%s", read.id, spelling, target.name, action, got)
						}
					}
				}
			}
		})
	}
	if writes == 0 {
		t.Fatal("no write rows ran")
	}
}
