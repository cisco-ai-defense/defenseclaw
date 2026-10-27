// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-1823: on a Windows home, a key read after a directory change was read
// relative to the request cwd, so `cd /c/Users/<me> && head -c 0
// .ssh/id_rsa` (Claude Code's Bash tool, Git Bash) was not a key read. The
// key-read proof follows cd, Set-Location and pushd in every drive spelling.
func TestActionWindowsKeyReadFollowsTheDirectoryChange(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, command := range []string{
		"cd /c/Users/u && head -c 0 .ssh/id_rsa",
		"cd /cygdrive/c/Users/u && cat .ssh/id_ed25519",
		"cd C:/Users/u && head -c 0 .ssh/id_rsa",
		"Set-Location ~; Get-Content .ssh\\id_ed25519",
		"cd .. && head -c 0 .ssh/id_rsa",
	} {
		if !ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
	for _, command := range []string{
		"cd /c/Users/u && head -c 0 .ssh/id_rsa.pub",
		"cd /c/Users/u/proj && head -c 0 .ssh/id_rsa",
	} {
		if ActionPrivateKeyRead(command, cwd, home) {
			t.Errorf("ActionPrivateKeyRead(%q) = true, want no key read", command)
		}
	}
}
