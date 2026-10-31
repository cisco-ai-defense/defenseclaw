// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"golang.org/x/sys/windows"
)

// A Windows profile holds legacy junctions (Application Data, Cookies ...)
// that deny listing to everyone, and NTUSER.DAT, which Windows holds open. The user Git Bash expands nothing in them,
// so at the home folder head -n 1 */* names no protected file when the
// process runs as the home user; a process of another user keeps the
// folder as unproved (rel-1-0-6:GAP-0211).
func TestWindowsProfileUnlistableFolderAtHome(t *testing.T) {
	home := t.TempDir()
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), filepath.Join(home, "Documents"), filepath.Join(home, "Cookies")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keys, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// NTUSER.DAT is a file Windows holds open with no sharing.
	locked, err := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Join(home, "NTUSER.DAT")),
		windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(locked) })
	// Everyone (S-1-1-0) may not list Cookies, as in a real profile.
	if out, err := exec.Command("icacls", filepath.Join(home, "Cookies"), "/deny", "*S-1-1-0:(RD)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("icacls", filepath.Join(home, "Cookies"), "/remove:d", "*S-1-1-0").Run() })
	// An elevated process with the backup privilege lists it anyway: then
	// the row of another user proves nothing and is not judged.
	denied := true
	if directory, err := pathOpen(filepath.Join(home, "Cookies")); err == nil {
		_, readErr := directory.Readdirnames(1)
		_ = directory.Close()
		denied = readErr != nil && !errors.Is(readErr, io.EOF)
	}
	saved := actionProcessProfileDirectory
	t.Cleanup(func() { actionProcessProfileDirectory = saved })
	for _, row := range []struct {
		command, want string
		owner         bool
	}{
		{"head -n 1 */*; echo done", "", true},
		{"echo */*; echo done", "", true},
		{"head -n 1 */*; echo done", "protected-target", false},
		{"cp a.txt .ssh/authorized_keys", "protected-target", true},
		{"cp a.txt .*/authorized_keys", "protected-target", true},
	} {
		if !row.owner && !denied {
			t.Logf("this process lists a folder that denies listing: %q as another user not judged", row.command)
			continue
		}
		actionProcessProfileDirectory = func() (string, error) {
			if row.owner {
				return home, nil
			}
			return filepath.Join(filepath.Dir(home), "other"), nil
		}
		if got := ActionCommandDecisionWithDialectAndGlobFacts(row.command, home, home, actionfacts.DialectPOSIX, nil); got != row.want {
			t.Errorf("owner=%v %q: decision %q, want %q", row.owner, row.command, got, row.want)
		}
	}
}
