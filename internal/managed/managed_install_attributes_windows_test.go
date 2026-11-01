//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// ReadOnly, Hidden or System on a managed file is cleared by the guardian's
// layout repair; other attributes are kept.
func TestClearManagedFileRestrictiveAttributes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		t.Fatal(err)
	}
	set := uint32(windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_HIDDEN |
		windows.FILE_ATTRIBUTE_SYSTEM | windows.FILE_ATTRIBUTE_ARCHIVE)
	if err := windows.SetFileAttributes(pointer, set); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.SetFileAttributes(pointer, windows.FILE_ATTRIBUTE_NORMAL) })
	clearManagedFileRestrictiveAttributes(path)
	got, err := windows.GetFileAttributes(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if got&managedFileRestrictiveAttributes != 0 {
		t.Fatalf("attributes = 0x%x, restrictive bits still set", got)
	}
	if got&windows.FILE_ATTRIBUTE_ARCHIVE == 0 {
		t.Fatalf("attributes = 0x%x, archive bit was dropped", got)
	}
}
