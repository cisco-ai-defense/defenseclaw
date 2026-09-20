// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pathidentity

import (
	"os"
	"path/filepath"
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
