// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A command that only reads the keys file (checksum, listing, a state test,
// over ssh or inside a shell body) is not a key write: alone it is allowed,
// beside other work it alerts in a per-user default install, and a write of
// the file in the same command still blocks (rel-1-0-10:GAP-0018).
func TestGAP0018KeyReadersAreNotKeyWrites(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.WriteFile(filepath.Join(cwd, "keys.sum"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installDefaultProfileConnector(t, "claudecode")
	ctx := context.Background()
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"checksum to a report", `sha256sum ~/.ssh/authorized_keys > keys.sum`, false},
		{"checksum to a report then a listing", `sha256sum ~/.ssh/authorized_keys > keys.sum; ls -l keys.sum`, false},
		{"remote listing", `ssh -n -F ~/.ssh/config builder 'sudo ls -la ~/.ssh/authorized_keys 2>&1' | head -3`, false},
		{"state test", `test ! -e ~/.ssh/authorized_keys && echo absent`, false},
		{"listing printed by sed", `ls ~/.ssh | sed -n 1,5p`, false},
		{"login shell body", `sudo -iu builder bash -lc "sha256sum ~/.ssh/authorized_keys"`, false},
		{"state test or true", `test -e ~/.ssh/authorized_keys || true`, false},
		// A write in the same command, or any way to write, still blocks.
		{"checksum then keys write", `sha256sum ~/.ssh/authorized_keys; echo x >> ~/.ssh/authorized_keys`, true},
		{"remote write", `ssh -n builder 'echo x >> ~/.ssh/authorized_keys'`, true},
		{"remote command from a proxy option", `ssh -o ProxyCommand=true builder 'ls ~/.ssh/authorized_keys'`, true},
		{"sed edit", `sed -i s/a/b/ ~/.ssh/authorized_keys`, true},
		{"sed write command", `sed -n 'w ~/.ssh/authorized_keys' keys.sum`, true},
		{"shell body that writes", `bash -lc "echo x >> ~/.ssh/authorized_keys"`, true},
		{"directory change into the folder", `cd ~/.ssh && cp ~/project/a.txt scratch.txt`, true},
	} {
		for _, mode := range []string{"observe", "action"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				api := activeClaudeCodeTestAPI()
				api.scannerCfg.Guardrail.Mode = mode
				resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "gap0018-readers", CWD: cwd,
					ToolName: "Bash", ToolInput: map[string]interface{}{"command": tc.command},
					Payload: map[string]interface{}{"tool_name": "Bash"},
				})
				wantBlock := tc.block && mode == "action"
				if got := resp.Action == "block"; got != wantBlock {
					t.Fatalf("action=%q findings=%v home=%s, want block=%t", resp.Action, resp.Findings, home, wantBlock)
				}
			})
		}
	}
}
