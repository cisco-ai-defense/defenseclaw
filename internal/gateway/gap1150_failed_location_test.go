// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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

// gap1150Post sends command through the live hook route of route (the
// Claude Code PowerShell tool, the Codex shell in its spellings, the Copilot
// CLI powershell tool), with the evidence header the hook client makes of
// the same body, and returns the answer.
func gap1150Post(t *testing.T, a *APIServer, route, cwd, command, home string, managedPeer bool) map[string]any {
	t.Helper()
	connector := strings.SplitN(route, "-", 2)[0]
	hook := func(tool string, input any) map[string]any {
		return map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap1150", "cwd": cwd,
			"tool_name": tool, "tool_use_id": "tu-gap1150", "tool_input": map[string]any{"command": input}}
	}
	var body map[string]any
	switch route {
	case "claudecode":
		body = hook("PowerShell", command)
	case "codex":
		body = hook("Bash", command)
	case "codex-argv":
		body = hook("shell", []string{"powershell.exe", "-NoProfile", "-Command", command})
	case "codex-shell_command":
		body = hook("shell_command", command)
	case "codex-cmd":
		body = hook("shell", []string{"cmd.exe", "/c", command})
	case "copilot":
		body = map[string]any{"sessionId": "gap1150", "timestamp": 1, "cwd": cwd, "eventName": "preToolUse",
			"toolName": "powershell", "toolArgs": map[string]any{"command": command}}
	default:
		t.Fatalf("unknown route %s", route)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	event := "PreToolUse"
	if connector == "copilot" {
		event = "preToolUse"
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(connector, "", event, raw))
	switch connector {
	case "codex":
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	case "copilot":
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	}
	if managedPeer {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	w := httptest.NewRecorder()
	a.handleAgentHook(connector).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", route, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: answer %q: %v", route, w.Body.String(), err)
	}
	return out
}

// TestGAP1150FailedLocationChangeThenRelativeStateWriteFiveTiers pins
// rel-1-0-10:GAP-1150 (cert L72, the PowerShell and CMD side of GAP-0133).
// A Set-Location, cd, chdir, Push-Location or pushd that fails is not a
// terminating error, and a failed CMD cd does not stop the next command, so
// a relative write after it lands where the shell stood: after Set-Location
// <home> it is the DefenseClaw config. It was allowed with no finding in
// every pack. The write is the state write wherever the shell may be, in
// the five tiers, on the Claude Code PowerShell tool, the Codex shell (its
// string, argv and shell_command spellings, and cmd /c) and the Copilot CLI
// powershell tool; the same shapes on project files stay allowed.
//
// The gateway judges the Windows path on the host that holds it: the rows
// run on native Windows (the S7 WINDOWS-READER run), as a standard user.
func TestGAP1150FailedLocationChangeThenRelativeStateWriteFiveTiers(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a per-user gateway resolves the Windows path on its own host")
	}
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	missing := filepath.Join(filepath.VolumeName(root)+`\`, "nonexistent-gap1150")
	rel := `.defenseclaw\config.yaml`
	write := "type nul >> " + rel
	type row struct {
		id, cwd, command string
		block            bool
	}
	powerShell := []row{
		{"control-in-home", home, write, true},
		{"control-absolute", project, "cd " + missing + "; type nul >> " + filepath.Join(home, rel), true},
		// The cert form (L72): the call starts in a project folder.
		{"cert-form", project, "Set-Location " + home + "; cd " + missing + "; " + write, true},
		{"cert-form-in-home", home, "Set-Location " + home + "; cd " + missing + "; " + write, true},
		{"failed-cd-in-home", home, "cd " + missing + "; " + write, true},
		{"newlines", project, "Set-Location " + home + "\ncd " + missing + "\n" + write, true},
		{"silently-continue", project, "Set-Location " + home + "; Set-Location -Path " + missing + " -ErrorAction SilentlyContinue; " + write, true},
		{"push-location", project, "Set-Location " + home + "; Push-Location " + missing + "; " + write, true},
		{"sl", home, "sl " + missing + "; " + write, true},
		{"add-content", home, "cd " + missing + "; Add-Content -Path " + rel + " -Value x", true},
		{"set-content", home, "cd " + missing + "; Set-Content " + rel + " x", true},
		{"out-file", home, "cd " + missing + "; 'x' | Out-File " + rel, true},
		{"scriptblock-cd", project, "Set-Location " + home + "; & { cd " + missing + " }; " + write, true},
		{"or-list", project, "Set-Location " + home + "; cd " + missing + " || Write-Output x; " + write, true},
		{"and-list", project, "Set-Location " + home + " && cd " + missing + "; " + write, true},
		{"literal-path", project, "Set-Location -LiteralPath " + home + "; Set-Location -LiteralPath " + missing + "; " + write, true},
		{"chdir", project, "chdir " + home + "; chdir " + missing + "; " + write, true},
		{"add-content-from-project", project, "Set-Location " + home + "; cd " + missing + "; Add-Content -Path " + rel + " -Value x", true},
		{"cd-home", project, "cd " + home + "; cd " + missing + "; " + write, true},
		{"cd-home-only", project, "cd " + home + "; " + write, true},
		{"set-location-home-only", project, "Set-Location " + home + "; " + write, true},
		{"chdir-add-content", project, "chdir " + home + "; chdir " + missing + "; Add-Content -Path " + rel + " -Value x", true},
		// Benign twins: the same shapes on project files, and reads.
		{"benign-append", project, "cd " + missing + "; type nul >> notes.txt", false},
		{"benign-add-content", home, "cd " + missing + "; Add-Content -Path notes.txt -Value x", false},
		{"benign-project", project, "Set-Location " + project + "; cd " + missing + "; type nul >> notes.txt", false},
		{"benign-read", project, "Set-Location " + home + "; cd " + missing + "; Get-Content " + rel, false},
		{"benign-and", project, "Set-Location " + project + " && type nul >> notes.txt", false},
		{"benign-list", project, "cd " + home + "; cd " + missing + "; Get-ChildItem " + rel, false},
	}
	cmd := []row{
		{"cmd-control", home, write, true},
		{"cmd-cd-d", project, "cd /d " + home + " & cd /d " + missing + " & " + write, true},
		{"cmd-in-home", home, "cd /d " + missing + " & " + write, true},
		{"cmd-and", project, "cd /d " + home + " && cd /d " + missing + " & " + write, true},
		{"cmd-or", project, "cd /d " + home + " & cd /d " + missing + " || " + write, true},
		{"cmd-cd", project, "cd " + home + " & cd " + missing + " & " + write, true},
		{"cmd-pushd", project, "pushd " + home + " & pushd " + missing + " & " + write, true},
		{"cmd-benign", project, "cd /d " + missing + " & type nul >> notes.txt", false},
	}
	for _, p := range gap0437Packs {
		for _, route := range []string{"claudecode", "codex", "codex-argv", "codex-shell_command", "codex-cmd", "copilot"} {
			rows := powerShell
			if route == "codex-cmd" {
				rows = cmd
			}
			for _, r := range rows {
				if p.managed && route == "codex-argv" && r.id == "newlines" {
					// The managed-peer reading of the argv form with
					// newline-separated moves: rel-1-0-10:GAP-1156 (same
					// at rel).
					continue
				}
				// A gateway of its own for each call: gap1150Post sends one
				// tool use id, and a second call with it on one gateway is a
				// correlation collision (as in the GAP-1228 test).
				a := gap0437Server(t, p, strings.SplitN(route, "-", 2)[0], "action")
				out := gap1150Post(t, a, route, r.cwd, r.command, home, p.managed)
				raw, _ := json.Marshal(out)
				action, _ := out["action"].(string)
				// The rule id in any spelling: a Windows host's reader names it
				// TAMPER.DETECTOR_STATE_WRITE (canonicalTrustedRuleID folds both).
				state := strings.Contains(strings.ToLower(string(raw)), "tamper.detector_state_write")
				// A proven state write is a HIGH alert outside strict and
				// managed strict, a block there (GAP-0747 owner tiering 2026-11-15T15:20Z).
				want := gap1173Want("write", p.name)
				if gap1157CopilotUnresolvedBlock(p.managed, route, action, raw) {
					want = "block"
				}
				if r.block && (action != want || !state) {
					t.Errorf("%s %s %s: action %q, want %s by tamper.detector_state_write: %.400s", p.name, route, r.id, action, want, raw)
				}
				if !r.block && (action == "block" || state) {
					t.Errorf("%s %s %s: a benign twin was judged %q: %.400s", p.name, route, r.id, action, raw)
				}
			}
		}
	}
}

// gap1157CopilotUnresolvedBlock is a managed Copilot write on these rows that
// is also an unresolved write target (rel-1-0-10:GAP-1157, same at rel): a
// CRITICAL block by persistence.ssh_authorized_keys_command next to the state
// rule. Native Windows (cimapnat1, 2026-11-21) answers it so; the block is
// stronger than the GAP-0747 state tier, so it stands.
func gap1157CopilotUnresolvedBlock(managed bool, route, action string, raw []byte) bool {
	return managed && route == "copilot" && action == "block" &&
		strings.Contains(string(raw), "A write target could not be resolved")
}
