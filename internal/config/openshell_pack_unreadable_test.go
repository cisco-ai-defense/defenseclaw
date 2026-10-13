// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0521: a required pack inside the managed tree that this account cannot
// reach is unreadable, not outside the tree.
func TestManagedPackUnreadableIsNotOutside(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every mode")
	}
	root := filepath.Join(t.TempDir(), "sandbox")
	closed := filepath.Join(root, "strict")
	if err := os.MkdirAll(closed, 0o755); err != nil {
		t.Fatal(err)
	}
	pack := filepath.Join(closed, "pack.yaml")
	if err := os.WriteFile(pack, []byte("name: strict\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o755) })
	if managedPackInside(root, pack) {
		t.Fatal("an unreadable pack resolves inside")
	}
	if !managedPackUnreadable(root, pack) {
		t.Error("an unreadable pack inside the tree is not reported unreadable")
	}
	if managedPackUnreadable(root, filepath.Join(filepath.Dir(root), "elsewhere", "pack.yaml")) {
		t.Error("a pack outside the tree is reported unreadable")
	}
}
