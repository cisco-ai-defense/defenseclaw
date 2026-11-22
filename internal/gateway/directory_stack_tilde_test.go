// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Bash expands the directory-stack tildes ~N, ~+N, ~-N, ~+ and ~- to the
// directories of the dirs list, PWD and OLDPWD. After pushd ~/.ssh; pushd
// /tmp the word ~1 is ~/.ssh, so grep -r . ~1 reads the private keys,
// while the reading saw a literal ~1 and allowed it (GAP-2480).
func TestDirectoryStackTildeKeyReadIsAKeyRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	home, cwd := r104ReviewHomeNoAlias(t)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	installDefaultProfileConnector(t, "claudecode")
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	for _, tc := range gap2480DirectoryStackRows {
		t.Run(tc.command, func(t *testing.T) {
			api := activeClaudeCodeTestAPI()
			api.scannerCfg.Guardrail.Mode = "action"
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "directory-stack-tilde", CWD: cwd,
				ToolName: "Bash", ToolInput: map[string]interface{}{"command": tc.command},
				Payload: map[string]interface{}{"tool_name": "Bash"},
			})
			if got := resp.Action == "block"; got != tc.block {
				t.Fatalf("action=%q findings=%v, want block=%t", resp.Action, resp.Findings, tc.block)
			}
		})
	}
}

// gap2480DirectoryStackRows are the directory-stack reads of GAP-2480: block
// is true for a read the dirs list, PWD or OLDPWD turns into a read of the
// active account's private keys.
var gap2480DirectoryStackRows = []struct {
	command string
	block   bool
}{
	{"pushd ~/.ssh; pushd /tmp && grep -r . ~/.ssh", true},
	{"pushd ~/.ssh; pushd /tmp && grep -r . ~1", true},
	{"pushd ~/.ssh; pushd /tmp && grep -r . ~+1", true},
	{"pushd ~/.ssh; pushd /tmp && grep -r . ~-1", true},
	{"pushd ~/.ssh; pushd /tmp && cat ~1/id_ed25519", true},
	{"pushd ~/.ssh >/dev/null; pushd /tmp >/dev/null; cat ~1/id_ed25519", true},
	{"pushd ~/.ssh && cat ~0/id_ed25519", true},
	{"cd ~/.ssh && cat ~+/id_ed25519", true},
	{"cd ~/.ssh; cd /tmp; cat ~-/id_ed25519", true},
	{"pushd /tmp; pushd /var && ls ~1", false},
	{"pushd src && ls ~1", false},
	{"pushd ~/.ssh; pushd /tmp && ls ~2", false},
	{"pushd /tmp && echo ~5", false},
	{"cd src && cat ~-/README.md", false},
	{"pushd /tmp && cat ~1/notes.txt", false},
}

// TestDirectoryStackTildeKeyReadInAnAccountHomeFiveTiers runs the GAP-2480
// rows with the active home where account homes sit (/home/<u>, /Users/<u>)
// in the five tiers, on the Claude Code hook and on /inspect/tool. Only a
// home placed by position lets the ~user resolver name another account's
// home, so the temp-folder home of TestDirectoryStackTildeKeyReadIsAKeyRead
// could not see ~1 taken as the home of an account named 1
// (rel-1-0-10:GAP-0887). A key read blocks CRITICAL PATH-SSH-KEY on both
// routes, as on rel; the other rows do not block.
func TestDirectoryStackTildeKeyReadInAnAccountHomeFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	for _, home := range []string{"/home/alice", "/Users/alice"} {
		t.Setenv("HOME", home)
		cwd := home + "/proj"
		for _, p := range gap0437Packs {
			check := func(route string, i int, block bool, out map[string]any) {
				t.Helper()
				where := fmt.Sprintf("%s %s %s row %d %q", home, p.name, route, i, gap2480DirectoryStackRows[i].command)
				if !block {
					if out["action"] == "block" {
						t.Errorf("%s: action %v severity %v rules %v, want no block", where, out["action"], out["severity"], out["rule_ids"])
					}
					return
				}
				if out["action"] != "block" || out["severity"] != "CRITICAL" {
					t.Errorf("%s: action %v severity %v rules %v, want block CRITICAL", where, out["action"], out["severity"], out["rule_ids"])
					return
				}
				if route != "hook" {
					return
				}
				rules, _ := out["rule_ids"].([]any)
				for _, rule := range rules {
					if rule == "PATH-SSH-KEY" {
						return
					}
				}
				t.Errorf("%s: rules %v, want PATH-SSH-KEY", where, out["rule_ids"])
			}
			hookServer := gap0437Server(t, p, "claudecode", "action")
			for i, row := range gap2480DirectoryStackRows {
				check("hook", i, row.block, gap0437Hook(t, hookServer, cwd, fmt.Sprintf("gap0887-%s-%d", p.name, i), row.command))
			}
			inspectServer := gap0437Server(t, p, "openclaw", "action")
			for i, row := range gap2480DirectoryStackRows {
				check("inspect", i, row.block, gap0437Inspect(t, inspectServer, cwd, row.command))
			}
		}
	}
}
