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
// made), reads their real 8.3 names with GetShortPathName, and returns them
// whole and with the long file name. The alias exists only where the volume
// makes short names: with none the test skips, because there is no second
// name to protect.
func windowsManagedSettingsShortNames(t *testing.T) []string {
	t.Helper()
	files := []string{
		`C:\Program Files\ClaudeCode\managed-settings.json`,
		`C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json`,
		`C:\ProgramData\OpenAI\Codex\requirements.toml`,
	}
	var aliases []string
	for _, file := range files {
		createWindowsFixtureFile(t, file)
		short := windowsShortPathOf(t, file)
		if strings.EqualFold(short, file) {
			t.Skipf("the volume generates no 8.3 short name for %s, so the alias does not exist", file)
		}
		aliases = append(aliases, short)
		dir, leaf := filepath.Dir(file), filepath.Base(file)
		if shortDir := windowsShortPathOf(t, dir); !strings.EqualFold(shortDir, dir) {
			aliases = append(aliases, shortDir+`\`+leaf)
		}
	}
	return aliases
}

// createWindowsFixtureFile makes file and the folders above it that are not
// there, and removes at the end of the test what it made. A file that is
// already there is left as it is. Where the files cannot be made (no
// administrator) the test skips.
func createWindowsFixtureFile(t *testing.T, file string) {
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
			t.Skipf("cannot make %s for the short-name fixture: %v", dir, err)
		}
		t.Cleanup(func() { _ = os.Remove(dir) })
	}
	handle, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return
	}
	if err != nil {
		t.Skipf("cannot make %s for the short-name fixture: %v", file, err)
	}
	_ = handle.Close()
	t.Cleanup(func() { _ = os.Remove(file) })
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
