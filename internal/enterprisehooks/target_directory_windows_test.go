//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureWindowsTargetOwnedDirectoryTreePinsOwnerAndProtectedDACL(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(home, target, true); err != nil {
		t.Fatal(err)
	}
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	if err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		return ensureWindowsTargetOwnedDirectoryTree(home, hookDir, target)
	}); err != nil {
		t.Fatalf("create target-owned directory tree: %v", err)
	}
	for _, path := range []string{filepath.Dir(hookDir), hookDir} {
		if err := validateWindowsUserPathElement(path, target, true, true, true); err != nil {
			t.Fatalf("validate explicit target ownership on %s: %v", path, err)
		}
	}
}

func TestEnsureWindowsTargetOwnedDirectoryTreeRejectsPreexistingNoncanonicalDirectory(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(home, target, true); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	// A normal directory create inherits the parent ACL and, for an elevated
	// administrator token, may also select BUILTIN\Administrators as owner.
	// Neither shape is an acceptable managed-runtime preimage.
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	before := windowsTestSecurityDescriptorString(t, dataDir)
	err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		return ensureWindowsTargetOwnedDirectoryTree(
			home,
			filepath.Join(dataDir, "hooks"),
			target,
		)
	})
	if err == nil {
		t.Fatal("noncanonical pre-existing directory was adopted")
	}
	after := windowsTestSecurityDescriptorString(t, dataDir)
	if after != before {
		t.Fatalf("rejected directory security descriptor changed:\nbefore=%s\nafter=%s", before, after)
	}
	if _, statErr := os.Lstat(filepath.Join(dataDir, "hooks")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected directory gained a managed child: %v", statErr)
	}
}
