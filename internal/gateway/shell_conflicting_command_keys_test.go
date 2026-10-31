// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"
)

// TestShellToolConflictingCommandKeysWithAnExtraKey pins rel-1-0-6:GAP-0132:
// a shell tool call whose cmd and command keys hold two different commands
// has no one command to verify, also when one more key the projection does
// not know comes with it. On every shell tool name it is blocked in action
// mode, as Bash and bash are; the same value under both keys is the one
// command it names (GAP-0696), judged by its own rules.
func TestShellToolConflictingCommandKeysWithAnExtraKey(t *testing.T) {
	installSandboxMarkerRules(t)
	const m = `"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"`
	for _, tool := range []string{"async_shell_command", "run_command", "terminal", "exec", "shell_command", "Shell", "Bash", "bash"} {
		for _, row := range []struct {
			name, args string
			block      bool
		}{
			{"command-marker+cmd-benign+zz", `{"command":` + m + `,"cmd":"true","zz":1}`, true},
			{"cmd-marker+command-benign+zz", `{"cmd":` + m + `,"command":"true","zz":1}`, true},
			{"both-marker+zz", `{"command":` + m + `,"cmd":` + m + `,"zz":1}`, true},
			{"command-benign+cmd-other+zz", `{"command":"ls","cmd":"date","zz":1}`, true},
			{"command-marker+cmd-benign", `{"command":` + m + `,"cmd":"true"}`, true},
			// Hard negatives: one command under both keys, with or without
			// an extra key, and one key with an extra key.
			{"benign-both-same+zz", `{"command":"ls -la","cmd":"ls -la","zz":1}`, false},
			{"benign-both-same", `{"command":"ls -la","cmd":"ls -la"}`, false},
			{"benign-command+zz", `{"command":"ls -la","zz":1}`, false},
		} {
			t.Run(tool+"/"+row.name, func(t *testing.T) {
				resp := ampShellToolHook(t, "action", tool, row.args)
				blocked := resp.Action == "block" && resp.RawAction == "block"
				if blocked != row.block {
					t.Fatalf("blocked = %t, want %t: action %q raw %q reason %q", blocked, row.block, resp.Action, resp.RawAction, resp.Reason)
				}
			})
		}
	}
	resp := ampShellToolHook(t, "observe", "async_shell_command", `{"command":"ls","cmd":"date","zz":1}`)
	if resp.Action == "block" {
		t.Fatalf("observe mode blocked: %+v", resp)
	}
}
