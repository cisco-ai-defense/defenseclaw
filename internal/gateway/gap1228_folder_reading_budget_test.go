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
// and the Copilot CLI powershell tool, in the five tiers. Past the reading
// cap a relative write of the DefenseClaw config after the moves (2 moves
// and 64 statements, 7 and 18) is read in the home again and blocks, as
// below the cap (rel-1-0-10:GAP-1281: it was allowed in all five tiers).
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
	psTwo, cmdTwo := psMoves, cmdMoves
	for i := 1; i <= 7; i++ {
		psMoves += fmt.Sprintf("cd %snonexistent-g1228-%d; ", volume, i)
		cmdMoves += fmt.Sprintf("cd /d %snonexistent-g1228-%d & ", volume, i)
		if i == 2 {
			psTwo, cmdTwo = psMoves, cmdMoves
		}
	}
	psPad := func(prefix string, n int) string { return gap1228Pad(prefix, "; ", n) }
	cmdPad := func(prefix string, n int) string { return gap1228Pad(prefix, " & ", n) }
	key := filepath.Join(home, ".ssh", "authorized_keys")
	const stateWrite = `type nul >> .defenseclaw\config.yaml`
	type row struct {
		id, command string
		// rule is the evidence of the block; "" for a call that is allowed
		// unless block is set (a block whatever its rule).
		rule  string
		block bool
	}
	powerShell := []row{
		{"key-mid", psMoves + psPad("a", 35) + "; Add-Content -Path " + key + " -Value k; " + psPad("b", 35), "ssh_authorized", true},
		{"benign", psMoves + psPad("a", 70), "", false},
		{"state-k2-n64", psTwo + psPad("p", 64) + "; " + stateWrite, "", true},
		{"state-k7-n18", psMoves + psPad("p", 18) + "; " + stateWrite, "", true},
	}
	cmd := []row{
		{"cmd-key-mid", cmdMoves + cmdPad("a", 35) + " & echo k >> " + key + " & " + cmdPad("b", 35), "ssh_authorized", true},
		{"cmd-benign", cmdMoves + cmdPad("a", 70), "", false},
		{"cmd-state-k2-n64", cmdTwo + cmdPad("p", 64) + " & " + stateWrite, "", true},
		{"cmd-state-k7-n18", cmdMoves + cmdPad("p", 18) + " & " + stateWrite, "", true},
	}
	for _, p := range gap0437Packs {
		for _, route := range []string{"claudecode", "codex", "codex-cmd", "copilot"} {
			rows := powerShell
			if route == "codex-cmd" {
				rows = cmd
			}
			for _, r := range rows {
				if p.managed && route == "copilot" && !r.block {
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
				if r.block && r.rule == "" {
					// The state write rows: a proven DefenseClaw state write is
					// a HIGH alert outside strict and managed strict, a block
					// there (GAP-0747 owner tiering 2026-11-15T15:20Z).
					want := gap1173Want("write", p.name)
					if gap1157CopilotUnresolvedBlock(p.managed, route, action, raw) {
						want = "block"
					}
					if action != want || !strings.Contains(string(raw), gap0747StateRule) {
						t.Errorf("%s %s %s: action %q, want %s by %s: %.400s", p.name, route, r.id, action, want, gap0747StateRule, raw)
					}
					continue
				}
				if r.block && (action != "block" || !strings.Contains(string(raw), r.rule)) {
					t.Errorf("%s %s %s: action %q, want block (evidence %q): %.400s", p.name, route, r.id, action, r.rule, raw)
				}
				if !r.block && action != "allow" {
					t.Errorf("%s %s %s: the benign padded call is %q, want allow: %.400s", p.name, route, r.id, action, raw)
				}
			}
		}
	}
}
