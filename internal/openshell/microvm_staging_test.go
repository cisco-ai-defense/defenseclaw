// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStagingDisksAreNamedAfterInterruptedFirstStart(t *testing.T) {
	images := t.TempDir()
	staged := filepath.Join(images, PreparedDiskPrefix+"sha256-abc.staging-1")
	if err := os.Mkdir(staged, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "rootfs.ext4"), []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-11 * time.Minute)
	if err := os.Chtimes(staged, old, old); err != nil {
		t.Fatal(err)
	}
	if n, size := stagingDisks(images); n != 1 || size == 0 {
		t.Fatalf("staging disks = %d, %d", n, size)
	}
	if n, _ := preparedDisks(images); n != 0 {
		t.Fatalf("staging counted as prepared: %d", n)
	}
}
