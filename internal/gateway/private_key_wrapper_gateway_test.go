// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestR104WrappedPrivateKeyGatewayVerdict(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(
		"identity:\n\tsudo ssh -i ~/.ssh/id_ed25519 host uptime\n"+
			"copy:\n\tsudo cp ~/.ssh/id_ed25519 copy.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installDefaultProfileConnector(t, "claudecode")
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"sudo SSH identity", `sudo ssh -i ~/.ssh/id_ed25519 host uptime`, false},
		{"env SSH identity", `env LC_ALL=C ssh -i ~/.ssh/id_ed25519 host uptime`, false},
		{"nested SSH identity", `sudo -n env LC_ALL=C ssh -i ~/.ssh/id_ed25519 host uptime`, false},
		{"Make SSH identity", `make identity`, false},
		{"sudo key read", `sudo cat ~/.ssh/id_ed25519`, true},
		{"env key read", `env LC_ALL=C base64 ~/.ssh/id_ed25519`, true},
		{"Make key copy", `make copy`, true},
	} {
		for _, mode := range []string{"observe", "action"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				api := activeClaudeCodeTestAPI()
				api.scannerCfg.Guardrail.Mode = mode
				resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "private-key-wrapper", CWD: cwd,
					ToolName: "Bash", ToolInput: map[string]interface{}{"command": tc.command},
					Payload: map[string]interface{}{"tool_name": "Bash"},
				})
				wantBlock := tc.block && mode == "action"
				if got := resp.Action == "block"; got != wantBlock {
					t.Fatalf("action=%q findings=%v, want block=%t", resp.Action, resp.Findings, wantBlock)
				}
			})
		}
	}
}
