//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
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
