// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// WIN-R1-06: Setup refuses a full disk before it stages anything.
func TestRequireFreeSpaceRefusesBeforeStaging(t *testing.T) {
	dir := t.TempDir()
	saved := freeDiskBytes
	t.Cleanup(func() { freeDiskBytes = saved })
	freeDiskBytes = func(string) (uint64, bool, error) { return 100 << 20, true, nil }
	err := requireFreeSpace(dir+"/not-yet/staging", 400<<20, "stage the install")
	if err == nil || !strings.Contains(err.Error(), "100 MB free and about 656 MB is needed") {
		t.Fatalf("a full disk was not refused with the sizes: %v", err)
	}
	freeDiskBytes = func(string) (uint64, bool, error) { return 2 << 30, true, nil }
	if err := requireFreeSpace(dir, 400<<20, "stage the install"); err != nil {
		t.Fatalf("enough space was refused: %v", err)
	}
}
