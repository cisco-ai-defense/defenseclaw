//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func addNativeACL(t *testing.T, path, entry string) {
	t.Helper()
	if output, err := exec.Command("/bin/chmod", "+a", entry, path).CombinedOutput(); err != nil {
		t.Fatalf("add macOS ACL: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}

// Benign twin of the write-ACL refusals, on the real ACL reader: an
// account-owned folder with an entry for root adds no authority, so the port
// is imported and a matching port is left alone (REVIEW-7 MF1).
func TestOpenCodeServicePortKeepsAFolderWithARootACLEntry(t *testing.T) {
	home := t.TempDir()
	path := writeACLTestService(t, home, "25001")
	addNativeACL(t, filepath.Dir(path), "user:root allow add_file,delete_child")
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25001 {
		t.Fatalf("a folder with a root entry was refused: port=%d err=%v", port, err)
	}
	result, err := SetOpenCodeServicePort(home, 25001)
	if err != nil || result.Changed || result.Port != 25001 {
		t.Fatalf("a folder with a root entry was refused by the setter: %+v %v", result, err)
	}
}

// An entry for everyone on the same folder is still refused.
func TestOpenCodeServicePortRefusesAFolderWithAnEveryoneACLEntry(t *testing.T) {
	home := t.TempDir()
	path := writeACLTestService(t, home, "25001")
	addNativeACL(t, filepath.Dir(path), "everyone allow add_file,delete_child")
	if port, err := ReadOpenCodeServicePortAsUser(home); err == nil || port != 0 {
		t.Fatalf("a folder with an everyone entry was read: port=%d err=%v", port, err)
	}
	if _, err := SetOpenCodeServicePort(home, 25001); err == nil {
		t.Fatal("a folder with an everyone entry was accepted by the setter")
	}
}

// On macOS an ACL entry grants another account write access without changing
// the mode bits (REVIEW-6 MF1). The real file ACL, not the mode, must keep the
// file from naming a port, and the setter must replace the writable file
// (restored: GAP-0053 round 9 MF2).
func TestReadOpenCodeServicePortDoesNotImportAFileWithARealWriteACL(t *testing.T) {
	home := t.TempDir()
	path := writeACLTestService(t, home, "25001")
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25001 {
		t.Fatalf("an ACL-free file was not imported: port=%d err=%v", port, err)
	}
	addNativeACL(t, path, "everyone allow write,append")
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the ACL changed the mode bits: %v %v", info, err)
	}
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 0 {
		t.Fatalf("a file with a write ACL was imported: port=%d err=%v", port, err)
	}
	if result, err := SetOpenCodeServicePort(home, 25001); err != nil || !result.Changed {
		t.Fatalf("a matching file with a write ACL was accepted as it stands: %+v %v", result, err)
	}
}

// Benign twin on the same real reader: an entry for root on the file adds no
// authority, so the port is imported and a matching file is left alone.
func TestOpenCodeServicePortKeepsAFileWithARootACLEntry(t *testing.T) {
	home := t.TempDir()
	path := writeACLTestService(t, home, "25001")
	addNativeACL(t, path, "user:root allow write,append")
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25001 {
		t.Fatalf("a file with a root entry was not imported: port=%d err=%v", port, err)
	}
	result, err := SetOpenCodeServicePort(home, 25001)
	if err != nil || result.Changed || result.Port != 25001 {
		t.Fatalf("a file with a root entry was rewritten: %+v %v", result, err)
	}
}
