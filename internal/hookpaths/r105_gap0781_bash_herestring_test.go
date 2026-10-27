// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0781 (Windows leg, NP4 np4-owin): Codex on Windows runs apply_patch
// through Git Bash, & bash.exe -lc @'...'@, with the arg0 apply_patch.bat
// path or a PATH export. The here-string body was read as one glob pattern:
// it holds a / and the *** envelope markers, so it named a directory that
// does not exist, which counts as a possibly protected expansion on a
// Windows host, and a README.md patch was a protected target. Each line of
// the body is now its own candidate. The decisive run is native Windows
// (windows-native.yml); elsewhere the glob expansion is not reached.
func TestActionWindowsGitBashHereStringIsNotOneGlob(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Windows scanner expands a glob only on a Windows host")
	}
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "README.md"), []byte("plain notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	msys := filepath.ToSlash(home)
	if volume := filepath.VolumeName(home); len(volume) == 2 && volume[1] == ':' {
		msys = "/" + strings.ToLower(volume[:1]) + filepath.ToSlash(home[2:])
	}
	bash := "& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc @'\n"
	envelope := "*** Begin Patch\n*** Update File: README.md\n@@\n+np4-heredoc-line\n*** End Patch\nPATCH\ncat README.md\n'@"
	arg0 := msys + "/.codex/tmp/arg0/codex-arg0Utk7ea"
	for _, tc := range []struct {
		name, command, want string
	}{
		{"arg0 apply_patch.bat", bash + arg0 + "/apply_patch.bat <<'PATCH'\n" + envelope, ""},
		{"PowerShell and bash PATH export", "$env:PATH += ';" + home + "\\.codex\\tmp\\arg0\\codex-arg0Utk7ea'; " +
			bash + "export PATH=\"$PATH:" + arg0 + "\"\napply_patch <<'PATCH'\n" + envelope, ""},
		{"PATH export then apply_patch.bat", bash + "export PATH=\"$PATH:" + arg0 + "\"\napply_patch.bat <<'PATCH'\n" + envelope, ""},
		{"bare apply_patch", bash + "apply_patch <<'PATCH'\n" + envelope, ""},
		{"listing with a glob and a path", bash + "ls /c/tmp/*.md\ncat README.md\n'@", ""},
		{"key glob in the script", bash + "cp k.pub ~/.ssh/authorized_k*\n'@", "protected-target"},
		{"key path in the script", bash + "printf x >> " + msys + "/.ssh/authorized_keys\n'@", "protected-target"},
		{"key directive in the envelope", bash + "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: " + msys +
			"/.ssh/authorized_keys\n@@\n+k\n*** End Patch\nPATCH\n'@", "protected-target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, proj, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}
