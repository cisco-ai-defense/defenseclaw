//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedLinuxPythonIgnoresPATHHijack(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	if err := os.WriteFile(filepath.Join(dir, "python3"), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	python, err := CheckManagedLinuxPython()
	if os.Getenv("DCLAW_TEST_MANAGED_PYTHON") == "1" && err != nil {
		t.Fatalf("host-managed Python admission failed: %v", err)
	}
	if err == nil && !strings.HasPrefix(python, "/usr/bin/python3") {
		t.Fatalf("managed resolver selected %q", python)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("PATH-controlled interpreter executed: %v", statErr)
	}
}

func TestManagedLinuxPythonRejectsWritablePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "python3")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateLinuxOwnedPath(path, false, false); err == nil {
		t.Fatal("accepted interpreter under a writable temporary directory")
	}
}
