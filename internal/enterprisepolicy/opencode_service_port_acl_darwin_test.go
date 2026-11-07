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

// On macOS an ACL entry grants another account write access without changing
// the mode bits (REVIEW-6 MF1). The real ACL, not the mode, must keep the file
// from naming a port.
func TestReadOpenCodeServicePortDoesNotImportAFileWithARealWriteACL(t *testing.T) {
	home := t.TempDir()
	path := writeACLTestService(t, home, "25001")
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25001 {
		t.Fatalf("an ACL-free file was not imported: port=%d err=%v", port, err)
	}
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow write,append", path).CombinedOutput(); err != nil {
		t.Skipf("cannot add an ACL entry: %v %s", err, out)
	}
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

func TestOpenCodeServicePortRefusesAFolderWithARealWriteACL(t *testing.T) {
	home := t.TempDir()
	path := writeACLTestService(t, home, "25001")
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow add_file,add_subdirectory,delete_child", filepath.Dir(path)).CombinedOutput(); err != nil {
		t.Skipf("cannot add an ACL entry: %v %s", err, out)
	}
	if port, err := ReadOpenCodeServicePortAsUser(home); err == nil || port != 0 {
		t.Fatalf("a folder with a write ACL was read: port=%d err=%v", port, err)
	}
}
