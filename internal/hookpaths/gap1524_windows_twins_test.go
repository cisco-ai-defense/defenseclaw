// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10:GAP-1524: TestBoundCallReachesProtectedLink skips on native
// Windows (POSIX links; accepted by design, DET111 2026-11-24). This is its
// Windows twin. A second name of the keys file is made with a
// hard link, which a standard Windows account may create (a symbolic link
// needs a privilege the Limited token lacks).

func gap1524WindowsKeysHome(t *testing.T) (home, cwd, keys string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys = filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "plain.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(cwd, "output")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home, cwd, keys
}

// Class: a word of a call past a reading bound that is a second name of a
// protected file (POSIX twin TestBoundCallReachesProtectedLink).
func TestGAP1524WindowsBoundCallReachesProtectedLink(t *testing.T) {
	home, cwd, _ := gap1524WindowsKeysHome(t)
	for _, row := range []struct {
		command string
		want    bool
	}{
		{`echo x > output`, true},
		{`echo x > .\output`, true},
		{`Set-Content -Path output -Value x`, true},
		{`Add-Content -Path .\output -Value x`, true},
		{`$p = "out"; $p += "put"; Set-Content -Path $p -Value x`, true},
		{`echo x > "%USERPROFILE%\project\output"`, true},
		{`echo x > plain.txt`, false},
		{`Set-Content -Path plain.txt -Value x`, false},
		{`echo x > missing.txt`, false},
	} {
		if got := BoundCallReachesProtectedLink(row.command, cwd, home); got != row.want {
			t.Errorf("BoundCallReachesProtectedLink(%q) = %v, want %v", row.command, got, row.want)
		}
	}
}
