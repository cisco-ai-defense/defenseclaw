// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gap1228Pad is n statements that each append to a file of the folder they
// run in, joined by separator.
func gap1228Pad(prefix, separator string, n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("type nul >> %s%d.txt", prefix, i)
	}
	return strings.Join(parts, separator)
}

// TestGAP1228PaddedWindowsCallAfterMovesThatMayFailKeepsItsReadingsFiveTiers
// pins rel-1-0-10:GAP-1228 (review round 1 of s7/cdcand, rows w-pad-ak-mid
// and w-pad-benign): a statement with a relative operand after folder moves
// that may fail is read in every folder it may run in (GAP-1150), and those
// readings used to count against the evaluation budget of the call, so a
// padded PowerShell or CMD call the base reads in full went to the
// whole-call limit: a key write in the middle went from block to the
// unknown tier, and the benign padded call from allow to alert (block in
// strict). The statements keep their budget; the call keeps the verdict it
// has on rel: the protected writes block by their rule, the benign call is
// allowed, on the Claude Code PowerShell tool, the Codex shell (and cmd /c)
// and the Copilot CLI powershell tool, in the five tiers.
//
// The gateway judges the Windows path on the host that holds it: the rows
// run on native Windows (the S7 WINDOWS-READER run), as a standard user.
func TestGAP1228PaddedWindowsCallAfterMovesThatMayFailKeepsItsReadingsFiveTiers(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a per-user gateway resolves the Windows path on its own host")
	}
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw"), filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	volume := filepath.VolumeName(root) + `\`
	psMoves, cmdMoves := "Set-Location "+home+"; ", "cd /d "+home+" & "
	for i := 1; i <= 7; i++ {
		psMoves += fmt.Sprintf("cd %snonexistent-g1228-%d; ", volume, i)
		cmdMoves += fmt.Sprintf("cd /d %snonexistent-g1228-%d & ", volume, i)
	}
	psPad := func(prefix string, n int) string { return gap1228Pad(prefix, "; ", n) }
	cmdPad := func(prefix string, n int) string { return gap1228Pad(prefix, " & ", n) }
	key := filepath.Join(home, ".ssh", "authorized_keys")
	type row struct {
		id, command string
		// rule is the evidence of the block; "" for a call that is allowed.
		rule string
	}
	powerShell := []row{
		{"key-mid", psMoves + psPad("a", 35) + "; Add-Content -Path " + key + " -Value k; " + psPad("b", 35), "ssh_authorized"},
		{"benign", psMoves + psPad("a", 70), ""},
	}
	cmd := []row{
		{"cmd-key-mid", cmdMoves + cmdPad("a", 35) + " & echo k >> " + key + " & " + cmdPad("b", 35), "ssh_authorized"},
		{"cmd-benign", cmdMoves + cmdPad("a", 70), ""},
	}
	for _, p := range gap0437Packs {
		for _, route := range []string{"claudecode", "codex", "codex-cmd", "copilot"} {
			rows := powerShell
			if route == "codex-cmd" {
				rows = cmd
			}
			for _, r := range rows {
				if p.managed && route == "copilot" && r.rule == "" {
					// A Copilot managed-peer append after a cd that may
					// fail is an unresolved write target:
					// rel-1-0-10:GAP-1157 (same at rel).
					continue
				}
				// A gateway of its own for each call: gap1150Post sends one
				// tool use id, and a second call with it on one gateway is a
				// correlation collision whose audit write may fail closed.
				a := gap0437Server(t, p, strings.SplitN(route, "-", 2)[0], "action")
				out := gap1150Post(t, a, route, project, r.command, home, p.managed)
				raw, _ := json.Marshal(out)
				action, _ := out["action"].(string)
				if r.rule != "" && (action != "block" || !strings.Contains(string(raw), r.rule)) {
					t.Errorf("%s %s %s: action %q, want block by %s: %.400s", p.name, route, r.id, action, r.rule, raw)
				}
				if r.rule == "" && action != "allow" {
					t.Errorf("%s %s %s: the benign padded call is %q, want allow: %.400s", p.name, route, r.id, action, raw)
				}
			}
		}
	}
}
