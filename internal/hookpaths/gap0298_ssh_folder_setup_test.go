// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap0298Allowed make or tighten the user's own .ssh folder; gap0298Blocked
// are their twins that reach the keys file, or change the folder in a way
// the setup rule does not read.
var (
	gap0298Allowed = []string{
		"mkdir -p ~/.ssh",
		"mkdir ~/.ssh",
		"mkdir -pv ~/.ssh",
		"mkdir -m 700 -p ~/.ssh",
		"chmod 700 ~/.ssh",
		"chmod go-rwx ~/.ssh/",
		"mkdir -p ~/.ssh && chmod 700 ~/.ssh",
		"mkdir -p ~/.ssh && ls -la ~/.ssh",
	}
	gap0298Blocked = []string{
		"mkdir -p ~/.ssh && echo k >> ~/.ssh/authorized_keys",
		"mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys",
		"mkdir -p ~/.ssh && cp a.txt ~/.ssh/authorized_keys",
		"mkdir -p ~/.ssh/authorized_keys",
		"chmod 600 ~/.ssh/authorized_keys",
		"chmod -R 700 ~/.ssh",
		"chmod 777 ~/.ssh",
	}
)

// TestSSHFolderSetupIsNotAKeysWrite is rel-1-0-6:GAP-0298 (sweep 8,
// per-user Windows; the same verdict on Linux and macOS): mkdir -p ~/.ssh
// and chmod 700 ~/.ssh, the usual step before ssh-keygen, were blocked as
// an authorized-keys write. Making or tightening exactly the home's .ssh
// folder writes no keys file; a write to the keys file, a path under the
// folder, a recursive chmod or another mode keep their verdicts.
func TestSSHFolderSetupIsNotAKeysWrite(t *testing.T) {
	if runtime.GOOS != "windows" {
		root := t.TempDir()
		home := filepath.Join(root, "alice")
		project := filepath.Join(home, "project")
		if err := os.MkdirAll(project, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, command := range gap0298Allowed {
			if got := ActionCommandDecision(command, project, home); got != "" {
				t.Errorf("%q = %q, want allow", command, got)
			}
		}
		for _, command := range gap0298Blocked {
			if got := ActionCommandDecision(command, project, home); got != "protected-target" {
				t.Errorf("%q = %q, want protected-target", command, got)
			}
		}
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../.ssh", filepath.Join(project, "sshlink")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(project, "keylink")); err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"chmod 700 sshlink", "mkdir -p sshlink"} {
			if got := ActionCommandDecision(command, project, home); got != "" {
				t.Errorf("%q = %q, want allow", command, got)
			}
		}
		for _, command := range []string{"chmod 700 sshlink/authorized_keys", "chmod 700 keylink", "chmod -R 700 sshlink", "chmod 777 sshlink"} {
			if got := ActionCommandDecision(command, project, home); got != "protected-target" {
				t.Errorf("%q = %q, want protected-target", command, got)
			}
		}
	}
	const home, cwd = `C:\Users\b00`, `C:\Users\b00\proj`
	for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell, actionfacts.DialectPOSIX} {
		for _, command := range gap0298Allowed {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, nil); got != "" {
				t.Errorf("dialect %q %q = %q, want allow", dialect, command, got)
			}
		}
		for _, command := range gap0298Blocked {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, nil); got != "protected-target" {
				t.Errorf("dialect %q %q = %q, want protected-target", dialect, command, got)
			}
		}
	}
}
