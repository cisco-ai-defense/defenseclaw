//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forceACLOpen makes the ACL check name every path whose slash-separated
// string ends in one of suffixes, as a file system ACL entry for another
// account would (macOS keeps the mode bits unchanged when one is added).
func forceACLOpen(t *testing.T, suffixes ...string) {
	t.Helper()
	old := openCodePathACLOpen
	openCodePathACLOpen = func(path string) bool {
		for _, suffix := range suffixes {
			if strings.HasSuffix(filepath.ToSlash(path), suffix) {
				return true
			}
		}
		return false
	}
	t.Cleanup(func() { openCodePathACLOpen = old })
}

func writeACLTestService(t *testing.T, home string, port string) string {
	t.Helper()
	path := OpenCodeServiceConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"port":`+port+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// An account-owned 0600 file that another account can write through an ACL
// entry names no port, whatever its mode bits say (REVIEW-6 MF1): the account
// gets a fresh port and the setter replaces the file with a private copy.
func TestReadOpenCodeServicePortDoesNotImportAFileWithAWriteACL(t *testing.T) {
	home := t.TempDir()
	writeACLTestService(t, home, "25001")
	forceACLOpen(t, "/opencode/service.json")
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 0 {
		t.Fatalf("a file with a write ACL was imported: port=%d err=%v", port, err)
	}
	result, err := SetOpenCodeServicePort(home, 25001)
	if err != nil || result.Port != 25001 || !result.Changed {
		t.Fatalf("a matching file with a write ACL was accepted as it stands: %+v %v", result, err)
	}
}

// The ACL on the file a final link leads to decides the same way.
func TestReadOpenCodeServicePortDoesNotImportALinkedFileWithAWriteACL(t *testing.T) {
	home := t.TempDir()
	path := OpenCodeServiceConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "linked-service.json")
	if err := os.WriteFile(target, []byte(`{"port":25002}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("service link unavailable: %v", err)
	}
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25002 {
		t.Fatalf("an ordinary linked file was not imported: port=%d err=%v", port, err)
	}
	forceACLOpen(t, "/linked-service.json")
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 0 {
		t.Fatalf("a linked file with a write ACL was imported: port=%d err=%v", port, err)
	}
}

// A folder on the path that another account can write by ACL is refused by the
// read and by the setter, sticky bit or not.
func TestOpenCodeServicePortRefusesAFolderWithAWriteACL(t *testing.T) {
	for _, mode := range []os.FileMode{0o700, 0o700 | os.ModeSticky} {
		home := t.TempDir()
		path := writeACLTestService(t, home, "25001")
		dir := filepath.Dir(path)
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		forceACLOpen(t, "/.config/opencode")
		if port, err := ReadOpenCodeServicePortAsUser(home); err == nil || port != 0 {
			t.Fatalf("mode %v: a folder with a write ACL was read: port=%d err=%v", mode, port, err)
		}
		if _, err := SetOpenCodeServicePort(home, 25001); err == nil {
			t.Fatalf("mode %v: a folder with a write ACL was accepted by the setter", mode)
		}
	}
}

// Benign twin: with no ACL entry the same layouts import and match.
func TestOpenCodeServicePortKeepsAnACLFreeFile(t *testing.T) {
	home := t.TempDir()
	writeACLTestService(t, home, "25001")
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25001 {
		t.Fatalf("port=%d err=%v", port, err)
	}
	result, err := SetOpenCodeServicePort(home, 25001)
	if err != nil || result.Changed || result.Port != 25001 {
		t.Fatalf("an ACL-free matching file was rewritten: %+v %v", result, err)
	}
}
