// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGAP0459FunctionDeclarationAndParameterRedirect(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	for _, row := range []struct {
		name, command string
		block         bool
	}{
		{"tab declaration", "function\techo { printf c >> \"$1\"; }; function\tlog { echo \"$1\"; }; log ~/.defenseclaw/config.yaml", true},
		{"plain parameter", `echo() { printf c >> $1; }; log() { echo "$1"; }; log ~/.defenseclaw/config.yaml`, true},
		{"tab ordinary", "function\techo { printf c >> \"$1\"; }; function\tlog { echo \"$1\"; }; log out.txt", false},
		{"plain ordinary", `echo() { printf c >> $1; }; log() { echo "$1"; }; log out.txt`, false},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, mode := range []string{"action", "observe"} {
				t.Run(connector+"/"+mode+"/"+row.name, func(t *testing.T) {
					api := instructionProtectionTestAPI(t, connector, mode, "HIGH")
					tool := "Bash"
					if connector == "codex" {
						tool = "exec_command"
					}
					got := gap0568ToolHookAction(t, api, connector, tool, home, cwd, row.command, true, true)
					if (got == guardrailActionBlock) != row.block {
						t.Errorf("blocked=%t, want %t", got == guardrailActionBlock, row.block)
					}
				})
			}
		}
	}
}
