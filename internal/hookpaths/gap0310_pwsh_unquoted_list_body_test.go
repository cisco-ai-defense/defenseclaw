// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPowerShellUnquotedListBodyReadsAsTheQuotedBody is rel-1-0-6:GAP-0310
// (sweep 9, per-user Linux): pwsh -Command with an unquoted listing body
// (Get-ChildItem ~/.ssh, Test-Path ~/.ssh/authorized_keys, ls ~/.ssh) was
// blocked while the quoted body allowed. PowerShell joins every argument
// after -Command with a blank, so the split body is the same text; each
// row equals its quoted twin, and writer bodies keep blocking.
func TestPowerShellUnquotedListBodyReadsAsTheQuotedBody(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{project, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		"Get-ChildItem ~/.ssh",
		"Test-Path ~/.ssh/authorized_keys",
		"ls ~/.ssh",
		"Get-ChildItem $HOME/.ssh",
	} {
		for _, prefix := range []string{"pwsh -Command ", "pwsh -NoProfile -Command ", "pwsh -c ", "powershell -Command "} {
			unquoted := prefix + body
			quoted := prefix + "'" + body + "'"
			want := ActionCommandDecision(quoted, project, home)
			if got := ActionCommandDecision(unquoted, project, home); got != want || got != "" {
				t.Errorf("%q = %q, want %q (its quoted twin, allow)", unquoted, got, want)
			}
		}
	}
	for _, command := range []string{
		"pwsh -Command Add-Content ~/.ssh/authorized_keys k",
		"pwsh -Command Set-Content ~/.ssh/authorized_keys k",
		"pwsh -Command Get-ChildItem ~/.ssh; echo k >> ~/.ssh/authorized_keys",
		"pwsh -Command Get-ChildItem ~/.ssh '|' Out-File ~/.ssh/authorized_keys",
		"pwsh -Command Get-ChildItem 'x; Add-Content ~/.ssh/authorized_keys k'",
	} {
		if got := ActionCommandDecision(command, project, home); got != "protected-target" {
			t.Errorf("%q = %q, want protected-target", command, got)
		}
	}
}
