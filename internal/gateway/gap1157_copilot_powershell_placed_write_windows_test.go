// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1157CopilotPowerShellPlacedWriteAfterAMoveThatMayFail pins
// rel-1-0-10:GAP-1157 (DET111 ruling 2026-11-24, option B). The Copilot CLI
// powershell tool runs its call in PowerShell, but the Windows hook places
// `cd C:\x; type nul >> notes.txt` in no dialect (the PowerShell reading is
// partial), so the call is read POSIX, where cd C:\x is the folder C:x under
// the hook's folder. Windows rejects that name, the managed hook client
// answers the write after it empty, and the managed gateway blocked the
// project-file append as an unresolved key write in both managed tiers. The
// PowerShell reading places the write in the folder the move reaches and in
// the one a failed move leaves, both ordinary, so the append is allowed in
// every tier. The same command into the keys, the DefenseClaw state, a
// credential, a startup file, or a write it cannot place keeps the block
// in both managed tiers, and a native az keyvault read keeps its verdict
// (TST-15697). Every cell is logged as CELL lines for the red/green table.
func TestGAP1157CopilotPowerShellPlacedWriteAfterAMoveThatMayFail(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "project")
	folders := map[string]string{
		"home": home, "project": project, "ssh": filepath.Join(home, ".ssh"),
		"state": filepath.Join(home, ".defenseclaw"), "aws": filepath.Join(home, ".aws"),
		"profile": filepath.Join(home, "Documents", "WindowsPowerShell"),
	}
	for _, dir := range folders {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".aws", "credentials"), filepath.Join(project, "notes.txt"),
	} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	missing := filepath.Join(filepath.VolumeName(root)+`\`, "nonexistent-gap1157")
	move := "cd " + missing + "; "
	type row struct {
		id, folder, command string
		benign              bool
	}
	rows := []row{
		{"benign-append", "project", move + "type nul >> notes.txt", true},
		{"benign-after-set-location", "project", "Set-Location " + project + "; " + move + "type nul >> notes.txt", true},
		{"benign-home-file", "home", move + "type nul >> notes.txt", true},
		{"benign-add-content", "project", move + "Add-Content -Path notes.txt -Value x", true},
		{"keys", "home", move + `type nul >> .ssh\authorized_keys`, false},
		{"keys-in-folder", "ssh", move + "type nul >> authorized_keys", false},
		{"state", "home", move + `type nul >> .defenseclaw\config.yaml`, false},
		{"state-in-folder", "state", move + "type nul >> config.yaml", false},
		{"credential", "home", move + `type nul >> .aws\credentials`, false},
		{"credential-in-folder", "aws", move + "type nul >> credentials", false},
		{"startup-in-folder", "profile", move + "type nul >> Microsoft.PowerShell_profile.ps1", false},
		{"unplaced", "project", move + "type nul >> $env:DC_GAP1157_TARGET", false},
	}
	for _, p := range gap0437Packs {
		for _, r := range rows {
			a := gap0437Server(t, p, "copilot", "action")
			out := gap1150Post(t, a, "copilot", folders[r.folder], r.command, home, p.managed)
			raw, _ := json.Marshal(out)
			action, _ := out["action"].(string)
			unresolved := strings.Contains(string(raw), "A write target could not be resolved")
			t.Logf("CELL|%s|%s|%s|unresolved=%v", r.id, p.name, action, unresolved)
			switch {
			case r.benign && action != "allow":
				t.Errorf("%s %s: the project-file write was judged %q: %.400s", p.name, r.id, action, raw)
			case !r.benign && p.managed && action != "block":
				t.Errorf("%s %s: action %q, want the managed block: %.400s", p.name, r.id, action, raw)
			}
		}
		// A native program the PowerShell model leaves unread keeps the
		// POSIX reading that enforces it (TST-15697): never allowed.
		a := gap0437Server(t, p, "copilot", "action")
		out := gap1150Post(t, a, "copilot", project, "az keyvault secret show --vault-name v --name fixture", home, p.managed)
		raw, _ := json.Marshal(out)
		action, _ := out["action"].(string)
		t.Logf("CELL|az-keyvault|%s|%s", p.name, action)
		if action == "allow" {
			t.Errorf("%s az keyvault secret show: allowed: %.400s", p.name, raw)
		}
	}
}
