// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeImagePathStripsNamespacePrefixes(t *testing.T) {
	t.Setenv("CMIDBROKER_IMAGEPATH_TEST_ROOT", `C:\Program Files`)
	for input, want := range map[string]string{
		`\??\C:\Program Files\x.exe`:                         `C:\Program Files\x.exe`,
		`\\?\C:\Program Files\x.exe`:                         `C:\Program Files\x.exe`,
		`%CMIDBROKER_IMAGEPATH_TEST_ROOT%\x.exe`:             `C:\Program Files\x.exe`,
		`C:\Program Files\x.exe`:                             `C:\Program Files\x.exe`,
		`\??\%CMIDBROKER_IMAGEPATH_TEST_ROOT%\Cisco\bin.exe`: `C:\Program Files\Cisco\bin.exe`,
	} {
		if got := normalizeImagePath(input); got != want {
			t.Fatalf("normalizeImagePath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSameExecutablePathComparesFileIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broker.exe")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !sameExecutablePath(`\\?\`+path, path) {
		t.Fatal("prefixed spelling of the same file did not match")
	}
	// A hard link is a second name for the same file: the spelling differs,
	// so only the volume and file-index comparison can match it.
	link := filepath.Join(dir, "broker-link.exe")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if !sameExecutablePath(link, path) {
		t.Fatal("hard link to the same file did not match by file identity")
	}
	other := filepath.Join(dir, "other.exe")
	if err := os.WriteFile(other, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sameExecutablePath(other, path) {
		t.Fatal("different files matched")
	}
}
