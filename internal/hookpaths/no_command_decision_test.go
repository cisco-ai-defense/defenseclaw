// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

// GAP-0958: a tool call with no command text (Copilot task, Claude Code
// Task/Agent, any other delegation, file or MCP tool) has no shell action to
// decide. The Windows grammar used to return dynamic-command for it, so the
// gateway blocked every such call on Windows as an SSH persistence write.
// Protected writes still block; empty launchers carry an audit note.
func TestGAP0958NoCommandTextHasNoActionDecision(t *testing.T) {
	// The home is a real path: on macOS the temporary directory is under the
	// /var -> /private/var link, which the protected-file proof resolves.
	posixHome, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	posixCWD := filepath.Join(posixHome, "project")
	homes := []struct{ name, cwd, home string }{
		{"POSIX", posixCWD, posixHome},
		{"Windows drive", `C:\Users\alice\project`, `C:\Users\alice`},
		{"Windows forward slashes", `C:/Users/alice/project`, `C:/Users/alice`},
		{"Windows UNC profile", `\\fs\profiles\alice\project`, `\\fs\profiles\alice`},
	}
	for _, home := range homes {
		for _, command := range []string{"", " ", "\t", "\r\n", " \n "} {
			if got := ActionCommandDecision(command, home.cwd, home.home); got != "" {
				t.Errorf("%s: command %q decision = %q, want none", home.name, command, got)
			}
		}
	}
	for _, tc := range []struct {
		name, command, cwd, home string
		block                    bool
	}{
		{"POSIX protected write", `echo key >> ~/.ssh/authorized_keys`, posixCWD, posixHome, true},
		{"POSIX empty nested shell", `sh -c`, posixCWD, posixHome, false},
		{"PowerShell protected write", `Add-Content -Path "$env:USERPROFILE\.ssh\authorized_keys" -Value key`, `C:\Users\alice\project`, `C:\Users\alice`, true},
		{"cmd protected write", `echo key>>%USERPROFILE%\.ssh\authorized_keys`, `C:\Users\alice\project`, `C:\Users\alice`, true},
		{"cmd launcher without a child", `cmd /c`, `C:\Users\alice\project`, `C:\Users\alice`, false},
		{"cmd launcher with a blank child", `cmd /c ""`, `C:\Users\alice\project`, `C:\Users\alice`, false},
		{"pwsh launcher without a child", `pwsh -Command`, `C:\Users\alice\project`, `C:\Users\alice`, false},
		{"pwsh stdin", `pwsh -`, `C:\Users\alice\project`, `C:\Users\alice`, false},
		{"Windows backtick command in a write", "Set-Content -Path `$x -Value key", `C:\Users\alice\project`, `C:\Users\alice`, false},
	} {
		if got := ActionCommandDecision(tc.command, tc.cwd, tc.home) != ""; got != tc.block {
			t.Errorf("%s: %q block=%v, want %v", tc.name, tc.command, got, tc.block)
		}
		if !tc.block && ActionCommandAuditReason(tc.command, tc.cwd, tc.home) == "" {
			t.Errorf("%s: %q has no audit reason", tc.name, tc.command)
		}
	}
}
