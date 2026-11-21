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
