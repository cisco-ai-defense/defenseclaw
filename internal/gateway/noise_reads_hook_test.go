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
// beside other work it alerts in the default pack, and a write of the file in
// the same command still blocks (rel-1-0-10:GAP-0018).
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
		{"remote listing", `ssh -n builder 'sudo ls -la ~/.ssh/authorized_keys'`, false},
		{"remote listing beside an echo", `echo before; ssh -n builder 'sudo ls -la ~/.ssh/authorized_keys'; echo after`, false},
		{"state test", `test ! -e ~/.ssh/authorized_keys && echo absent`, false},
		{"listing printed by sed", `ls ~/.ssh | sed -n 1,5p`, false},
		{"login shell body", `sudo -iu builder bash -lc "sha256sum ~/.ssh/authorized_keys"`, false},
		{"state test or true", `test -e ~/.ssh/authorized_keys || true`, false},
		// A list of prints of a source file whose NAME holds the key file name reads
		// no key file; the list is held as unproven, and only reads are in it.
		{"printed source files named for the keys", `sed -n '2090,2115p' internal/gateway/semantic_authorized_keys_proof.go && sed -n '1,230p' internal/hookpaths/applypatch.go`, false},
		// A source file called applypatch.go is a file, not an apply_patch call.
		{"printed source files, one named applypatch.go", `sed -n 1,5p internal/gateway/semantic_authorized_keys_proof.go && cat internal/hookpaths/applypatch.go`, false},
		// A glob that can reach the keys file by name is decided by identity: it blocks as
		// it always did (glob review round 4, rows B2 and B3).
		{"B2 dotglob glob reaching the keys file by name", `shopt -s dotglob; cat ~/*/authorized_keys`, true},
		{"B3 dotglob glob reaching a key file by a name prefix", `shopt -s dotglob; cat ~/*/auth*`, true},
		{"printed source file, then a key write", `sed -n '2090,2115p' internal/gateway/semantic_authorized_keys_proof.go && echo x >> ~/.ssh/authorized_keys`, true},
		// A statement with an output redirect is no plain read (owner ruling, GAP-2590):
		// the copy of the file's content into another file stays a block.
		{"checksum to a report", `sha256sum ~/.ssh/authorized_keys > keys.sum`, true},
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
