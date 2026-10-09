// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enforce

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0913: a managed gateway cannot inspect the guardian-protected folders
// above a Copilot or OpenCode skill, so the ancestry check accepts a folder
// that resolves to itself. A folder reached through a junction never does.
func TestExistingPathIsLinkFreeRefusesAJunctionAbove(t *testing.T) {
	root := longTestPath(t, t.TempDir())
	skills := filepath.Join(root, "real", "skills")
	if err := os.MkdirAll(skills, 0o700); err != nil {
		t.Fatal(err)
	}
	if !existingPathIsLinkFree(skills) {
		t.Fatalf("plain folder %s was refused", skills)
	}
	link := filepath.Join(root, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, filepath.Join(root, "real")).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if existingPathIsLinkFree(link) || existingPathIsLinkFree(filepath.Join(link, "skills")) {
		t.Fatal("a junction, or a folder below one, passed")
	}
	if err := validateExistingAncestors(filepath.Join(link, "skills")); err == nil {
		t.Fatal("the ancestry check accepted a folder below a junction")
	}
}

func longTestPath(t *testing.T, path string) string {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(name, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("long path of %s: %v", path, err)
	}
	return windows.UTF16ToString(buf[:n])
}
