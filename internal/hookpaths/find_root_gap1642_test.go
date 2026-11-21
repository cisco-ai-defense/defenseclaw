// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGAP1642FindRootReachesRegistrationFiles (rel-1-0-10:GAP-1642): a find
// that deletes from the file system root reaches a registration file under
// the home as a find from the home does; a root that already ends in a
// separator was tested as // (C:\\ on Windows), which starts no path. Git
// Bash's /c, /c/ and /cygdrive/c start at that drive's root.
func TestGAP1642FindRootReachesRegistrationFiles(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	root := "/"
	if runtime.GOOS == "windows" {
		root = filepath.VolumeName(home) + "/"
	}
	names := []string{settings}
	for command, want := range map[string]bool{
		"find " + home + " -type f -delete":             true,
		"find " + root + " -type f -delete":             true,
		"find " + root + " -type f -exec rm {} +":       true,
		"find " + root + " -name '*.tmp' -delete":       false,
		"find " + root + " -maxdepth 1 -type f -delete": false,
		"find " + root + " -name settings.json":         false,
	} {
		if got := len(RegistrationWriteReached(command, cwd, home, names)) == 1; got != want {
			t.Errorf("%s: reached %t, want %t", command, got, want)
		}
	}
	for written, want := range map[string]string{
		"/c": "c:/", "/c/": "c:/", "/C/": "C:/", "/cygdrive/c": "c:/", "/c/Users": "c:/Users", "/tmp": "/tmp", "C:/": "C:/",
	} {
		if got := findGitBashDriveRoot(written); got != want {
			t.Errorf("findGitBashDriveRoot(%q) = %q, want %q", written, got, want)
		}
	}
}
