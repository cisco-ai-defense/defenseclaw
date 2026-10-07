// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ideplugins

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVisualStudioMissingHiveDoesNotCreateFiles(t *testing.T) {
	dir := t.TempDir()
	if _, ok := readVisualStudioEnabled(dir, "17.0_test"); ok {
		t.Fatal("missing hive was read")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("scan created files beside missing hive: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(dir, "privateregistry.bin")); !os.IsNotExist(err) {
		t.Fatalf("hive unexpectedly exists: %v", err)
	}
}
