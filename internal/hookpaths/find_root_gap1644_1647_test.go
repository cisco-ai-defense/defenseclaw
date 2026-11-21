// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGAP1644GAP1647FindRootReachesProtectedFiles: a find from the file
// system root reaches the protected files below the home that the same find
// from the home reaches. Two more find readers tested each file against the
// root plus a separator, which for / (C:/ on Windows) is // (C:\\) and starts
// no path, as registrationFindReach did before GAP-1642: the authorized-keys
// delete reader of the client decision (rel-1-0-10:GAP-1644, find / -name
// authorized_keys -delete) and the files a find hands its editing child
// (rel-1-0-10:GAP-1647, find / -name settings.json -exec sed -i ... {} +).
func TestGAP1644GAP1647FindRootReachesProtectedFiles(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	settings := filepath.Join(home, ".claude", "settings.json")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{settings, keys} {
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
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
		"find " + home + " -name settings.json -exec sed -i s/a/b/ {} +":  true,
		"find " + root + " -name settings.json -exec sed -i s/a/b/ {} +":  true,
		"find " + root + " -name settings.json -exec truncate -s0 {} +":   true,
		"find " + root + " -name 'settings.*' -exec sed -i s/a/b/ {} ';'": true,
		"find " + root + " -name notes.txt -exec sed -i s/a/b/ {} +":      false,
		"find " + root + " -name settings.json -exec cat {} +":            false,
	} {
		if got := len(RegistrationWriteReached(command, cwd, home, names)) == 1; got != want {
			t.Errorf("GAP-1647 %s: reached %t, want %t", command, got, want)
		}
	}
	// The client decision reads POSIX homes only (a Windows home takes the
	// PowerShell and Windows readers).
	if runtime.GOOS == "windows" {
		return
	}
	for command, want := range map[string]bool{
		"find " + home + " -name authorized_keys -delete": true,
		"find / -name authorized_keys -delete":            true,
		"find / -name 'authorized_key*' -delete":          true,
		"find / -name '*.tmp' -delete":                    false,
		"find / -name authorized_keys":                    false,
	} {
		if got := actionConcreteProtectedWrite(command, cwd, home); got != want {
			t.Errorf("GAP-1644 %s: protected write %t, want %t", command, got, want)
		}
	}
}

// TestGAP1650FolderRootReachesRegisteredFiles: an rsync --delete destination
// and an archive extraction folder that is the file system root (C:/ on
// Windows) reach the registered files below the home that the same call into
// the home reaches. registrationRsyncReach and
// registrationArchivePossibleReachAs tested each file against the folder plus
// a separator, // (C:\\) for the root, which starts no path, the find root
// bug of GAP-1642/1644/1647 (rel-1-0-10:GAP-1650).
func TestGAP1650FolderRootReachesRegisteredFiles(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	settingsDir := filepath.Join(home, ".claude")
	settings := filepath.Join(settingsDir, "settings.json")
	if err := os.MkdirAll(settingsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(cwd, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := "/"
	if runtime.GOOS == "windows" {
		root = filepath.VolumeName(home) + "/"
	}
	names := []string{settingsDir, settings}
	for command, want := range map[string]bool{
		"rsync -a --delete empty/ " + home + "/": true,
		"rsync -a --delete empty/ " + root:       true,
		"rsync -a empty/ " + root:                false,
		"rsync -a --delete empty/ " + cwd + "/":  false,
	} {
		if got := len(RegistrationWriteReached(command, cwd, home, names)) > 0; got != want {
			t.Errorf("GAP-1650 rsync %s: reached %t, want %t", command, got, want)
		}
	}
	// Members the words do not tell (a pattern) may be any file below the
	// folder; a member names the files it holds. A whole-archive extraction
	// into a folder that is not registered is no reach here at any folder
	// (TestRegistrationArchivePossibleReachUsesRegisteredFolder).
	for command, want := range map[string]bool{
		"tar -xf x.tar -C " + home + " '*.json'":       true,
		"tar -xf x.tar -C " + root + " '*.json'":       true,
		"tar -xf x.tar -C " + root + " .":              true,
		"tar -xf x.tar -C " + root + " opt/readme.txt": false,
		"tar -xf x.tar -C " + cwd + " '*.json'":        false,
		"tar -xf x.tar -C " + root:                     false,
	} {
		if got := RegistrationArchivePossibleReach(command, cwd, home, names) != ""; got != want {
			t.Errorf("GAP-1650 archive %s: reached %t, want %t", command, got, want)
		}
	}
}
