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
// Protected writes and launchers with an empty child stay blocked.
func TestGAP0958NoCommandTextHasNoActionDecision(t *testing.T) {
	posixHome := t.TempDir()
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
	}{
		{"POSIX protected write", `echo key >> ~/.ssh/authorized_keys`, posixCWD, posixHome},
		{"POSIX empty nested shell", `sh -c`, posixCWD, posixHome},
		{"PowerShell protected write", `Add-Content -Path "$env:USERPROFILE\.ssh\authorized_keys" -Value key`, `C:\Users\alice\project`, `C:\Users\alice`},
		{"cmd protected write", `echo key>>%USERPROFILE%\.ssh\authorized_keys`, `C:\Users\alice\project`, `C:\Users\alice`},
		{"cmd launcher without a child", `cmd /c`, `C:\Users\alice\project`, `C:\Users\alice`},
		{"cmd launcher with a blank child", `cmd /c ""`, `C:\Users\alice\project`, `C:\Users\alice`},
		{"pwsh launcher without a child", `pwsh -Command`, `C:\Users\alice\project`, `C:\Users\alice`},
		{"pwsh stdin", `pwsh -`, `C:\Users\alice\project`, `C:\Users\alice`},
		{"Windows backtick command in a write", "Set-Content -Path `$x -Value key", `C:\Users\alice\project`, `C:\Users\alice`},
	} {
		if got := ActionCommandDecision(tc.command, tc.cwd, tc.home); got == "" {
			t.Errorf("%s: %q decision is empty, want a block", tc.name, tc.command)
		}
	}
}
