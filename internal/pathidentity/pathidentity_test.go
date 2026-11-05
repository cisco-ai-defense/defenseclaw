// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pathidentity

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSameUsesFilesystemIdentity(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	alias := filepath.Join(dir, "alias")
	if err := os.WriteFile(original, []byte("same bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, alias); err != nil {
		t.Skipf("hard links are unavailable: %v", err)
	}
	if !Same(original, alias) {
		t.Fatal("hard-link aliases must compare as the same object")
	}
}

func TestSameRejectsDifferentFilesWithEqualContents(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, "left")
	right := filepath.Join(dir, "right")
	for _, path := range []string{left, right} {
		if err := os.WriteFile(path, []byte("same bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if Same(left, right) {
		t.Fatal("different filesystem objects must not compare as identical")
	}
}

func TestSameAllowsIdenticalMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "future.exe")
	if !Same(missing, missing) {
		t.Fatal("the same missing path must compare as identical")
	}
}

func TestSameFailsClosedOnAsymmetricExistence(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if Same(existing, filepath.Join(dir, "missing")) {
		t.Fatal("an existing path must not match a missing path")
	}
}

// The gateway a privileged helper runs for this home lives under an
// administrator's private folder: this account cannot stat it, so the
// recorded path and the live process's path can only be compared by spelling.
func TestSameAcceptsEqualPathsThisAccountCannotInspect(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a folder this account cannot open")
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(private, "gateway")
	if err := os.WriteFile(gateway, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })
	if _, err := os.Stat(gateway); err == nil {
		t.Skip("this account can inspect the private folder")
	}
	if !Same(gateway, gateway) {
		t.Fatal("the same path this account cannot inspect must compare as identical")
	}
	if Same(gateway, filepath.Join(private, "other")) {
		t.Fatal("different paths this account cannot inspect must not compare as identical")
	}
	if Same(gateway, filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("an uninspectable path must not match a missing one")
	}
}
