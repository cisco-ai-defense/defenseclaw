// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// windowsManagedSettingsShortNames makes the managed agent settings files on
// this volume (only those that are not there; the test removes what it
// made), reads their real 8.3 names with GetShortPathName, and returns every
// alias that exists, whole and with the long file name. A volume can name one
// path and not another (short names can be stripped per folder), so each file
// is judged on its own: a file with no alias adds none and the others still
// count. The test skips only when no alias exists at all, because then there
// is no second name to protect.
func windowsManagedSettingsShortNames(t *testing.T) []string {
	t.Helper()
	files := []string{
		`C:\Program Files\ClaudeCode\managed-settings.json`,
		`C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json`,
		`C:\ProgramData\OpenAI\Codex\requirements.toml`,
	}
	var aliases, notes []string
	for _, file := range files {
		if err := createWindowsFixtureFile(t, file); err != nil {
			notes = append(notes, "cannot make "+file+" for the short-name fixture: "+err.Error())
			continue
		}
		if short := windowsShortPathOf(t, file); !strings.EqualFold(short, file) {
			aliases = append(aliases, short)
		} else {
			notes = append(notes, "the volume generates no 8.3 short name for "+file)
		}
		dir, leaf := filepath.Dir(file), filepath.Base(file)
		if shortDir := windowsShortPathOf(t, dir); !strings.EqualFold(shortDir, dir) {
			aliases = append(aliases, shortDir+`\`+leaf)
		}
	}
	if len(aliases) == 0 {
		t.Skipf("no 8.3 alias of a managed settings file exists on this volume: %s", strings.Join(notes, "; "))
	}
	return aliases
}

// windowsOrdinaryVendorFileShortName makes an ordinary file in the vendor
// folder of the managed Claude Code settings and returns its 8.3 name as the
// volume gives it, or "" (with a note in the test log) where the volume gives
// it none or the file cannot be made. The name is that of another file, not
// of a managed settings file.
func windowsOrdinaryVendorFileShortName(t *testing.T) string {
	t.Helper()
	file := `C:\Program Files\ClaudeCode\operations-notes.txt`
	if err := createWindowsFixtureFile(t, file); err != nil {
		t.Logf("ordinary vendor-folder file not made: %v", err)
		return ""
	}
	short := windowsShortPathOf(t, file)
	if strings.EqualFold(short, file) {
		t.Logf("the volume generates no 8.3 short name for %s", file)
		return ""
	}
	return short
}

// createWindowsFixtureFile makes file and the folders above it that are not
// there, and removes at the end of the test what it made. A file that is
// already there is left as it is. It returns the error where the files cannot
// be made (no administrator), so the caller can go on with the other files.
func createWindowsFixtureFile(t *testing.T, file string) error {
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

// windowsShortPathOf is the path with every part that has an 8.3 name in that
// name, as the file system gives it.
func windowsShortPathOf(t *testing.T, path string) string {
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
