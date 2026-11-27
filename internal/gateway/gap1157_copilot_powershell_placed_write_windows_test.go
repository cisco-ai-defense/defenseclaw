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
// in both managed tiers. A native credential read is pinned separately by
// TestAgentHookTrustedActionToolSelectsWindowsHostShellGrammar (TST-15697).
// Every cell is logged as CELL lines for the red/green table.
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
	// want is the cell of each pack, in gap0437Packs order: default,
	// strict, permissive, managed, managed-strict. The attack cells are the
	// fix parent's (native red run, TST in the gap note): none moves.
	type row struct {
		id, folder, command string
		want                [5]string
	}
	allow := [5]string{"allow", "allow", "allow", "allow", "allow"}
	block := [5]string{"block", "block", "block", "block", "block"}
	stateTier := [5]string{"alert", "block", "alert", "block", "block"}
	// A Known write to an exact credential file gets the cell of its plain
	// spelling (type nul >> .aws\credentials) since T23d e7d2c5b031
	// (GAP-1478/1500/0662; GAP-0701 plain-form parity): block in all five
	// packs. The state, startup and hook-config rows keep the owner state
	// tier (GAP-0747, owner 2026-11-19). LEAD ruling 2026-11-25 (T23e f).
	credentialPlain := block
	rows := []row{
		{"benign-append", "project", move + "type nul >> notes.txt", allow},
		{"benign-after-set-location", "project", "Set-Location " + project + "; " + move + "type nul >> notes.txt", allow},
		{"benign-home-file", "home", move + "type nul >> notes.txt", allow},
		{"benign-add-content", "project", move + "Add-Content -Path notes.txt -Value x", allow},
		{"keys", "home", move + `type nul >> .ssh\authorized_keys`, block},
		{"keys-in-folder", "ssh", move + "type nul >> authorized_keys", block},
		{"state", "home", move + `type nul >> .defenseclaw\config.yaml`, stateTier},
		{"state-in-folder", "state", move + "type nul >> config.yaml", stateTier},
		{"credential", "home", move + `type nul >> .aws\credentials`, credentialPlain},
		{"credential-in-folder", "aws", move + "type nul >> credentials", credentialPlain},
		{"startup-in-folder", "profile", move + "type nul >> Microsoft.PowerShell_profile.ps1", stateTier},
		// A target no reading places is allowed at the parent as at 1.0.10;
		// the fix leaves it there.
		{"unplaced", "project", move + "type nul >> $env:DC_GAP1157_TARGET", allow},
	}
	for index, p := range gap0437Packs {
		for _, r := range rows {
			a := gap0437Server(t, p, "copilot", "action")
			out := gap1150Post(t, a, "copilot", folders[r.folder], r.command, home, p.managed)
			raw, _ := json.Marshal(out)
			action, _ := out["action"].(string)
			unresolved := strings.Contains(string(raw), "A write target could not be resolved")
			t.Logf("CELL|%s|%s|%s|unresolved=%v", r.id, p.name, action, unresolved)
			if action != r.want[index] {
				t.Errorf("%s %s: action %q, want %q: %.400s", p.name, r.id, action, r.want[index], raw)
			}
		}
	}
}
