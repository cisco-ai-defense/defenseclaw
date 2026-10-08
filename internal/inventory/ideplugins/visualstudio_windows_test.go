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
	if _, ok := readVisualStudioEnabled(newScanner("windows", Limits{}), dir, "17.0_test"); ok {
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

func TestVisualStudioHiveRespectsScanByteBudget(t *testing.T) {
	home := t.TempDir()
	instance := filepath.Join(home, "AppData", "Local", "Microsoft", "VisualStudio", "17.0_test")
	if err := os.MkdirAll(filepath.Join(instance, "Extensions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(instance, "privateregistry.bin"), []byte("invalid hive"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, install := range Scan(home, "windows", Limits{MaxBytes: 1}) {
		if install.Family == FamilyVisualStudio {
			if !install.Partial {
				t.Fatal("hive copy bypassed scan byte budget")
			}
			return
		}
	}
	t.Fatal("Visual Studio instance was not found")
}
