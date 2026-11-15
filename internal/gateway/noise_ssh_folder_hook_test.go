// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The hook route gives the same answer as the dispatch for a copy of the
// user's own SSH folder content inside the home: an alert, no block, with and
// without a working directory; a copy to /tmp stays a block
// (rel-1-0-10:GAP-0018, the s2 backup-of-own-keys cluster).
func TestOwnSSHFolderCopyThroughTheHookRoute(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, dir := range []string{"backup/ssh_backup"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"id_rsa", "id_ed25519"} {
		if err := os.WriteFile(filepath.Join(home, ".ssh", name), []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	installDefaultProfileConnector(t, "claudecode")
	ctx := context.Background()
	replacer := strings.NewReplacer("{H}", home)
	for _, tc := range []struct {
		name, command, cwd string
		block              bool
	}{
		{"glob copy into a backup folder", `cp -r {H}/.ssh/* {H}/backup/ssh_backup/`, cwd, false},
		{"glob copy, no working directory", `cp -r {H}/.ssh/* {H}/backup/ssh_backup/`, "", false},
		{"folder copy into a backup folder", `cp -r {H}/.ssh {H}/backup/ssh_backup`, cwd, false},
		{"key file copy into a backup folder", `cp {H}/.ssh/id_rsa {H}/backup/id_rsa.bak`, cwd, false},
		{"glob copy to tmp", `cp -r {H}/.ssh/* /tmp/ssh_backup/`, cwd, true},
		{"glob copy into the key folder itself", `cp -r {H}/backup/* {H}/.ssh/`, cwd, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := activeClaudeCodeTestAPI()
			api.scannerCfg.Guardrail.Mode = "action"
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "own-ssh-copy", CWD: tc.cwd,
				ToolName: "Bash", ToolInput: map[string]interface{}{"command": replacer.Replace(tc.command)},
				Payload: map[string]interface{}{"tool_name": "Bash"},
			})
			if got := resp.Action == "block"; got != tc.block {
				t.Fatalf("action=%q findings=%v, want block=%t", resp.Action, resp.Findings, tc.block)
			}
		})
	}
}
