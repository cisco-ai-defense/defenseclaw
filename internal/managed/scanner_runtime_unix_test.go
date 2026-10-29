// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1527: the gateway runs the scanner runtime only when every entry of
// its tree is a root-owned plain file or folder no other account can write.
func TestGAP1527ScannerRuntimeCodeTreeTrust(t *testing.T) {
	root := filepath.Join(t.TempDir(), "scanner-runtime")
	if err := os.MkdirAll(filepath.Join(root, "python", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "python", "lib", "m.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime")
	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("a root-owned tree was refused: %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "not root") {
		// The temporary folders above are not root's either; either refusal
		// names the owner.
		if err == nil || !strings.Contains(err.Error(), "uid") {
			t.Fatalf("a tree owned by uid %d was trusted: %v", os.Geteuid(), err)
		}
	}
	if os.Geteuid() != 0 {
		return
	}
	module := filepath.Join(root, "python", "lib", "m.py")
	if err := os.Chmod(module, 0o664); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime"); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("a group-writable module was trusted: %v", err)
	}
	_ = os.Chmod(module, 0o644)
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "python", "lib", "link.py")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime"); err == nil || !strings.Contains(err.Error(), "symlinks") {
		t.Fatalf("a link in the tree was trusted: %v", err)
	}
}

func TestGAP1527NoScannerRuntimeOnAHostWithoutThePackage(t *testing.T) {
	if _, err := os.Lstat("/opt/defenseclaw/scanner-runtime"); err == nil {
		t.Skip("this host has a managed scanner runtime")
	}
	if _, _, err := InstalledUnixScannerRuntime(); err != ErrNoScannerRuntime {
		t.Fatalf("InstalledUnixScannerRuntime = %v, want ErrNoScannerRuntime", err)
	}
}
