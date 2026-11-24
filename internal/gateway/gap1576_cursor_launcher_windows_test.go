// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
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

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP1576CursorWindowsLauncherLineIsReadAsPowerShell (rel-1-0-10:GAP-1576):
// Cursor runs a beforeShellExecution command in PowerShell on Windows. The
// launcher rows that block on Claude Code, Codex and Copilot (a pwsh -wd
// <state folder> relative write, pwsh/powershell -Command '<key>' with a
// redirect into another account's authorized_keys) were allowed with no
// finding on Cursor in all five tiers, while the Set-Location twins blocked.
// Cursor is now never weaker than Claude Code's PowerShell tool for the same
// command, in every tier, and the benign rows are never blocked.
func TestGAP1576CursorWindowsLauncherLineIsReadAsPowerShell(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{state, filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"), []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	foreign := `C:\Users\bob\.ssh\authorized_keys`
	key := "echo ssh-ed25519 AAAAgap1576 marker"
	rows := []struct {
		id, command string
		attack      bool
	}{
		{"c-wd", "pwsh -NoProfile -wd " + state + ` -Command "Set-Content -Path config.yaml -Value m"`, true},
		{"c-cd", "Set-Location " + state + "; Set-Content -Path config.yaml -Value m", true},
		{"f11", "pwsh -Command '" + key + "' 2>&1 >> " + foreign, true},
		{"f12", "pwsh -Command '" + key + "' 1>&2 >> " + foreign, true},
		{"f23", "powershell -Command \"" + key + "\" 2>&1 >> " + foreign, true},
		{"n01", "git status 2>&1", false},
		{"n20", "pwsh -NoProfile -wd " + project + ` -Command "git status 2>&1"`, false},
		{"n03", "dir 2>&1 >> out.txt", false},
		{"n04", "npm test", false},
	}
	rank := map[string]int{"": 0, "allow": 0, "alert": 1, "confirm": 1, "block": 2}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		cursor := gap0437Server(t, p, "cursor", "action")
		claude := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		for _, r := range rows {
			raw, _ := json.Marshal(map[string]any{"hook_event_name": "beforeShellExecution", "conversation_id": "c", "generation_id": "g",
				"command": r.command, "cwd": project, "workspace_roots": []string{project}})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/cursor/hook", strings.NewReader(string(raw)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("cursor", "", "beforeShellExecution", raw))
			if p.managed {
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			}
			w := httptest.NewRecorder()
			cursor.handleAgentHook("cursor").ServeHTTP(w, req)
			var out map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			action, _ := out["action"].(string)
			want := shapeParityHook(t, claude.handleAgentHook("claudecode"), shapeParityCall{name: "claudecode/PowerShell " + r.id, conn: "claudecode",
				event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", project, "PowerShell", map[string]any{"command": r.command})}, p.managed)
			switch {
			case r.attack && rank[action] < rank[want]:
				t.Errorf("%s %s: cursor %q weaker than Claude Code PowerShell %q (%s)", p.name, r.id, action, want, w.Body.String())
			case r.attack && action == "allow":
				t.Errorf("%s %s: cursor allow with Claude Code PowerShell %q", p.name, r.id, want)
			case !r.attack && action == "block":
				t.Errorf("%s %s: benign cursor row blocked (%s)", p.name, r.id, w.Body.String())
			}
		}
	})
}
