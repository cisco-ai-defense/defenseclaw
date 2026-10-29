// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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
	home, cwd := r104ReviewHome(t)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	installDefaultProfileConnector(t, "claudecode")
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	for _, tc := range []struct {
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
	} {
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
