// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"runtime"
	"testing"
)

// TestR106HiddenHomeNamesKeysFile (rel-1-0-6:GAP-0046): a gateway behind
// ProtectHome cannot resolve the user's home, so a word that names an
// authorized-keys file of it (a pwsh -Command body on Linux) matched
// nothing there while a per-user gateway, which resolves the word, found
// the keys file. The hidden-home reading now gives the visible-home answer
// for every row: the keys-file writes decide, ordinary writes, reads, a
// commit message and a comment that name the path do not.
func TestR106HiddenHomeNamesKeysFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 directory")
	}
	homes, home, project := r106KeysHome(t)
	for _, tc := range []struct {
		command string
		want    string
	}{
		{`pwsh -NoProfile -Command "Add-Content -Path ~/.ssh/authorized_keys -Value k"`, "protected-target"},
		{`pwsh -Command "Get-Content notes.txt | Out-File -Append ~/.ssh/authorized_keys"`, "protected-target"},
		{`pwsh -NoProfile -Command "Set-Content -Path ~/.ssh/authorized_keys2 -Value k"`, "protected-target"},
		{`pwsh -NoProfile -Command "Add-Content -Path notes.txt -Value k"`, ""},
		{`pwsh -NoProfile -Command "Get-ChildItem ."`, ""},
		{`git commit -m "document ~/.ssh/authorized_keys handling"`, ""},
		{`cat ~/.ssh/authorized_keys`, ""},
		{`echo done >> notes.txt # see ~/.ssh/authorized_keys`, ""},
		{`echo x >> ~/.ssh/known_hosts.bak`, ""},
	} {
		if err := os.Chmod(homes, 0o700); err != nil {
			t.Fatal(err)
		}
		visible := ActionCommandDecision(tc.command, project, home)
		if err := os.Chmod(homes, 0); err != nil {
			t.Fatal(err)
		}
		hidden := ActionCommandDecision(tc.command, project, home)
		if visible != tc.want || hidden != tc.want {
			t.Errorf("%q: visible home %q, hidden home %q, want %q", tc.command, visible, hidden, tc.want)
		}
	}
}
