// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity/pinnedtest"
)

// rel-1-0-6:GAP-0300: the rollback snapshot of a managed hook file keeps the
// bytes of the file it checked; one swapped in at the check/use instant is
// refused, so a rollback can never write the swapped bytes back.
func TestSnapshotWindowsRuntimeFilesRefusesAHookFileSwappedAfterTheCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks", "claude-code-hook.ps1")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	replacement := writeSwapPair(t, path, []byte("# checked hook\n"), []byte("# swapped hook\n"))

	snapshots, err := snapshotWindowsRuntimeFiles([]string{path})
	if err != nil || len(snapshots) != 1 || string(snapshots[0].data) != "# checked hook\n" {
		t.Fatalf("unswapped snapshot = %+v, %v", snapshots, err)
	}
	swaps := pinnedtest.SwapAfterCheck(t, path, replacement)
	snapshots, err = snapshotWindowsRuntimeFiles([]string{path})
	if swaps.Load() != 1 {
		t.Fatalf("swaps = %d, want 1", swaps.Load())
	}
	if err == nil || !strings.Contains(err.Error(), "changed identity before open") {
		t.Fatalf("swapped snapshot = %+v, %v; want refused as changed identity before open", snapshots, err)
	}
}
