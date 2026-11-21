// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"path/filepath"
	"testing"
)

// TestGAP0276ExportedFunctionCountsOnlyWhenCalled: the dead-value proofs
// (a variable rebound from a link name to a plain file before the write)
// stay proved under an exported bash function no call of the command runs,
// and are declined when a call runs one, when a call may run code the walk
// does not read, or when the export cannot be read (rel-1-0-10:GAP-0276).
func TestGAP0276ExportedFunctionCountsOnlyWhenCalled(t *testing.T) {
	root := t.TempDir()
	cwd, home := filepath.Join(root, "project"), filepath.Join(root, "home")
	for _, row := range []struct {
		name, variable, command string
		want                    bool
	}{
		{"none", "", `f=keylink; f=a.txt; echo m >> "$f"`, true},
		{"unrelated-redirect", "BASH_FUNC_module%%", `f=keylink; f=a.txt; echo m >> "$f"`, true},
		{"unrelated-install", "BASH_FUNC_module%%", `f=keylink; f=a.txt; install b.txt "$f"`, true},
		{"unrelated-rsync", "BASH_FUNC_ml%%", `f=keylink; f=a.txt; rsync b.txt "$f"`, true},
		{"unrelated-patched", "BASH_FUNC_module()", `f=keylink; f=a.txt; echo m >> "$f"`, true},
		{"called-echo", "BASH_FUNC_echo%%", `f=keylink; f=a.txt; echo m >> "$f"`, false},
		{"called-echo-patched", "BASH_FUNC_echo()", `f=keylink; f=a.txt; echo m >> "$f"`, false},
		{"called-install", "BASH_FUNC_install%%", `f=keylink; f=a.txt; install b.txt "$f"`, false},
		{"called-by-path", "BASH_FUNC_/usr/bin/rsync%%", `f=keylink; f=a.txt; rsync b.txt "$f"`, false},
		{"missing-program-handler", "BASH_FUNC_command_not_found_handle%%", `f=keylink; f=a.txt; echo m >> "$f"`, false},
		{"unreadable-export", "BASH_FUNC_module", `f=keylink; f=a.txt; echo m >> "$f"`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			clearShellStartupEnv(t)
			if row.variable != "" {
				t.Setenv(row.variable, "() {  :\n}")
			}
			if got := actionClientProvedSafeVariableTargets(row.command, cwd, home); got != row.want {
				t.Errorf("proof %t, want %t for %q with %s", got, row.want, row.command, row.variable)
			}
		})
	}
}
