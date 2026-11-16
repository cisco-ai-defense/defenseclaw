// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestWindowsPlainRemovalOfAKeysLinkIsNotAKeysWrite is rel-1-0-4:GAP-2590
// on the Codex Windows route (sweep 7 oss-win and mgd-win): Codex has its
// shell calls read as PowerShell, and a plain removal of a project link to
// the keys file, or a read of it into a discard redirect, was denied while
// Claude Code allowed them. Remove-Item and rm remove the link entry, not
// the file it names; a discarded read writes nothing. Writes through the
// link and a removal of the keys file itself still block, and the echo * rows of rel-1-0-6:GAP-0211 allow
// at a real home.
func TestWindowsPlainRemovalOfAKeysLinkIsNotAKeysWrite(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	keyDir := filepath.Join(home, ".ssh")
	for _, dir := range []string{keyDir, cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(keyDir, "authorized_keys")
	if err := os.WriteFile(keys, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "keylink")); err != nil {
		t.Skipf("no symbolic link privilege: %v", err)
	}
	if err := os.Symlink(keyDir, filepath.Join(cwd, "dirlink")); err != nil {
		t.Skipf("no symbolic link privilege: %v", err)
	}
	dialects := []actionfacts.Dialect{actionfacts.DialectPowerShell, actionfacts.DialectPOSIX}
	// The Codex route (PowerShell hint) and Claude Code (posix hint, Git
	// Bash) forms of the sweep rows; Remove-Item and $null are PowerShell
	// only.
	for _, row := range []struct {
		command string
		dialect actionfacts.Dialect
	}{
		{"rm keylink", actionfacts.DialectPowerShell},
		{"rm keylink", actionfacts.DialectPOSIX},
		{"Remove-Item keylink", actionfacts.DialectPowerShell},
		{"Remove-Item -Force keylink", actionfacts.DialectPowerShell},
		{"Remove-Item -LiteralPath keylink", actionfacts.DialectPowerShell},
		{"uniq keylink > /dev/null", actionfacts.DialectPowerShell},
		{"uniq keylink > /dev/null", actionfacts.DialectPOSIX},
		{"uniq keylink 2> $null", actionfacts.DialectPowerShell},
	} {
		if got := ActionCommandDecisionWithDialectAndGlobFacts(row.command, cwd, home, row.dialect, nil); got != "" {
			t.Errorf("dialect %q %q = %q, want allow", row.dialect, row.command, got)
		}
	}
	for _, command := range []string{
		"Add-Content keylink x",
		"Set-Content -Path keylink -Value k",
		"echo k >> keylink",
		"rm ../.ssh/authorized_keys",
		"Remove-Item ../.ssh/authorized_keys",
	} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, nil); got != "protected-target" {
				t.Errorf("dialect %q %q = %q, want protected-target", dialect, command, got)
			}
		}
	}
	for _, command := range []string{"echo *", "echo * && echo done", "echo */", "Write-Output *"} {
		for _, dialect := range []actionfacts.Dialect{actionfacts.DialectPowerShell, ""} {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "" {
				t.Errorf("home dialect %q %q = %q, want allow", dialect, command, got)
			}
		}
	}
}
