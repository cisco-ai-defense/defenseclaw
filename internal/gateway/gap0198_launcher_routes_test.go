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
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-0198 on the routes the string reading did not reach: a pwsh launcher's
// -WorkingDirectory is the folder its script writes in, so a relative write
// of the DefenseClaw config behind -wd <state folder> blocks in all five
// tiers on the Codex shell route as an argv (the launcher body reading had no
// body for -wd) and on Copilot's powershell tool (judged as shell, the launcher
// line read as POSIX lost the folder's backslashes), as the same move spelled
// Set-Location already did. The same launchers writing a project file,
// reading the config or running git stay allowed.
func TestGAP0198WorkingDirectoryOnTheArgvAndCopilotRoutes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows hook dialect readings and path resolution")
	}
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{state, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"), []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	const write = "Set-Content -Path config.yaml -Value m"
	dq := func(s string) string { return `"` + s + `"` }
	type row struct {
		name, route, cwd string
		command          any
		block            bool
	}
	rows := []row{
		{"argv -wd", "codex", project, []string{"pwsh", "-NoProfile", "-wd", state, "-Command", write}, true},
		{"argv -WorkingDirectory", "codex", project, []string{"pwsh.exe", "-NoProfile", "-WorkingDirectory", state, "-Command", write}, true},
		{"copilot -wd", "copilot", project, "pwsh -NoProfile -wd " + state + " -Command " + dq(write), true},
		{"copilot -WorkingDirectory", "copilot", project, "pwsh -NoProfile -WorkingDirectory " + state + " -Command " + dq(write), true},
		{"benign argv -wd write", "codex", home, []string{"pwsh", "-NoProfile", "-wd", project, "-Command", "Set-Content -Path notes.txt -Value m"}, false},
		{"benign argv -wd git", "codex", home, []string{"pwsh", "-NoProfile", "-wd", project, "-Command", "git status"}, false},
		{"benign argv -wd read", "codex", project, []string{"pwsh", "-NoProfile", "-wd", state, "-Command", "Get-Content config.yaml"}, false},
		{"benign copilot -wd write", "copilot", home, "pwsh -NoProfile -wd " + project + " -Command " + dq("Set-Content -Path notes.txt -Value m"), false},
		{"benign copilot -wd read", "copilot", project, "pwsh -NoProfile -wd " + state + " -Command " + dq("Get-Content config.yaml"), false},
		{"benign copilot -wd build", "copilot", home, "pwsh -NoProfile -wd " + project + " -Command " + dq("go build ./..."), false},
	}
	for _, p := range gap0437Packs {
		servers := map[string]*APIServer{}
		for _, r := range rows {
			if servers[r.route] == nil {
				servers[r.route] = gap0437Server(t, p, r.route, "action")
			}
			action := gap0198RoutePost(t, servers[r.route], r.route, r.cwd, r.command, home, p.managed)
			if blocked := action == "block"; blocked != r.block {
				t.Errorf("%s %s: action %q, want block=%v", p.name, r.name, action, r.block)
			}
		}
	}
}

// gap0198RoutePost posts one PreToolUse call to the connector's hook route:
// Codex's shell tool, or Copilot's powershell tool.
func gap0198RoutePost(t *testing.T, a *APIServer, route, cwd string, command any, home string, managed bool) string {
	t.Helper()
	event, body := "PreToolUse", map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0198", "cwd": cwd,
		"tool_name": "shell", "tool_use_id": "tu-gap0198", "tool_input": map[string]any{"command": command}}
	if route == "copilot" {
		event, body = "preToolUse", map[string]any{"sessionId": "gap0198", "timestamp": 1, "cwd": cwd,
			"eventName": "preToolUse", "toolName": "powershell", "toolArgs": map[string]any{"command": command}}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+route+"/hook", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(route, "", event, raw))
	if route == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	} else {
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	}
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	w := httptest.NewRecorder()
	a.handleAgentHook(route).ServeHTTP(w, req)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %d %q", route, w.Code, w.Body.String())
	}
	action, _ := out["action"].(string)
	return action
}

// The command of Copilot's powershell tool is judged alone as the PowerShell
// tool, whatever tool the call itself is judged as (shell on Windows), so its
// launcher reading is the PowerShell tool's (GAP-0198); other shell tools keep
// the call's tool.
func TestGAP0198CopilotPowerShellCommandIsJudgedAsPowerShell(t *testing.T) {
	args := json.RawMessage(`{"command":"pwsh -NoProfile -wd C:\\Users\\alice\\.defenseclaw -Command \"Set-Content -Path config.yaml -Value m\""}`)
	ctx := context.Background()
	if command, tool := sandboxShellCommand(ctx, "copilot", "preToolUse", "powershell", "shell", args); command == nil || tool != "powershell" {
		t.Fatalf("copilot powershell: command %s judged as %q, want powershell", command, tool)
	}
	if _, tool := sandboxShellCommand(ctx, "copilot", "preToolUse", "bash", "shell", args); tool != "shell" {
		t.Fatalf("copilot bash judged as %q, want the call's tool", tool)
	}
}
