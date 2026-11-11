// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package actionfacts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// rel-1-0-6:GAP-0734: the 8.3 name of a published managed settings file, or
// of the folder it sits in, is the same file. The names come from this
// volume (the test makes the files and reads them with GetShortPathName),
// because only the volume says whether it makes short names and which ones:
// every alias that exists must read as the protected file, and the alias of
// another file in the same vendor folder must not. The test skips, naming
// why, where the volume has no short name for the files.
func TestWindowsManagedAgentSettingsPathShortNamesOfTheVolume(t *testing.T) {
	protected := []string{
		`C:\ProgramData\Cursor\defenseclaw-hook.ps1`,
		`C:\ProgramData\Cursor\hooks.json`,
		`C:\ProgramData\opencode\opencode.jsonc`,
	}
	// Made after the protected files, so that its short name is the next one
	// of the same stem (DEFENS~2.PS1 beside DEFENS~1.PS1).
	ordinary := `C:\ProgramData\Cursor\defenseclaw-hook-notes.ps1`
	var aliases, notes []string
	for _, file := range protected {
		if err := createWindowsShortNameFixture(t, file); err != nil {
			notes = append(notes, "cannot make "+file+": "+err.Error())
			continue
		}
		dir, leaf := filepath.Dir(file), filepath.Base(file)
		short := windowsShortPath(t, file)
		if strings.EqualFold(short, file) {
			notes = append(notes, "the volume makes no 8.3 name for "+file)
			continue
		}
		aliases = append(aliases, short, dir+`\`+filepath.Base(short), windowsShortPath(t, dir)+`\`+leaf)
	}
	if len(aliases) == 0 {
		t.Skipf("no 8.3 name of a managed settings file exists on this volume: %s", strings.Join(notes, "; "))
	}
	for _, alias := range aliases {
		if !WindowsManagedAgentSettingsPath(alias) {
			t.Errorf("WindowsManagedAgentSettingsPath(%q) = false, want true (8.3 name of a managed settings file)", alias)
		}
	}
	if err := createWindowsShortNameFixture(t, ordinary); err != nil {
		t.Logf("benign twin not made: %v", err)
		return
	}
	if short := windowsShortPath(t, ordinary); !strings.EqualFold(short, ordinary) {
		if WindowsManagedAgentSettingsPath(short) {
			t.Errorf("WindowsManagedAgentSettingsPath(%q) = true, want false (8.3 name of another file in the vendor folder)", short)
		}
	}
}

// createWindowsShortNameFixture makes file and the folders above it that are
// not there, and removes at the end of the test what it made. A file that is
// already there is left as it is. It returns the error where the files cannot
// be made (no administrator), so the caller can go on with the others.
func createWindowsShortNameFixture(t *testing.T, file string) error {
	t.Helper()
	var missing []string
	for dir := filepath.Dir(file); ; {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		missing = append([]string{dir}, missing...)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	for _, dir := range missing {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return err
		}
		t.Cleanup(func() { _ = os.Remove(dir) })
	}
	handle, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_ = handle.Close()
	t.Cleanup(func() { _ = os.Remove(file) })
	return nil
}

// windowsShortPath is the path with every part that has an 8.3 name in that
// name, as the volume gives it.
func windowsShortPath(t *testing.T, path string) string {
	t.Helper()
	from, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("path %q: %v", path, err)
	}
	buffer := make([]uint16, windows.MAX_PATH)
	for range 2 {
		n, err := windows.GetShortPathName(from, &buffer[0], uint32(len(buffer)))
		if err != nil || n == 0 {
			t.Fatalf("GetShortPathName(%q): %d, %v", path, n, err)
		}
		if int(n) <= len(buffer) {
			return windows.UTF16ToString(buffer[:n])
		}
		buffer = make([]uint16, n)
	}
	t.Fatalf("GetShortPathName(%q) did not settle", path)
	return ""
}
