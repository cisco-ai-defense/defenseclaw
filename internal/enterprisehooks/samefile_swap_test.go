// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity/pinnedtest"
)

// rel-1-0-6:GAP-0300: a file another file replaces after the reader checked
// it and before it opens the path is refused, not read. The pinned stat is
// the seam: pinnedtest renames the replacement over the checked path at the
// exact check/use instant, so no timing is involved. With os.Lstat the file
// identity was read on Windows only at the comparison, from the swapped
// file, and the swapped bytes came back.

func writeSwapPair(t *testing.T, path string, checked, swapped []byte) string {
	t.Helper()
	if err := os.WriteFile(path, checked, 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(filepath.Dir(path), "replacement")
	if err := os.WriteFile(replacement, swapped, 0o600); err != nil {
		t.Fatal(err)
	}
	return replacement
}

func TestReadGuardianRestoreRecordRefusesARecordSwappedAfterTheCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), GuardianRestoresFile)
	checked := `{"version":1,"targets":[{"uid":1001,"user":"checked","connector":"codex","restored_at":"2026-10-13T20:00:00Z"}]}`
	swapped := `{"version":1,"targets":[{"uid":1002,"user":"swapped","connector":"codex","restored_at":"2026-10-13T20:00:00Z"}]}`
	replacement := writeSwapPair(t, path, []byte(checked), []byte(swapped))

	if record, err := ReadGuardianRestoreRecord(path); err != nil || len(record.Targets) != 1 || record.Targets[0].User != "checked" {
		t.Fatalf("unswapped read = %+v, %v", record, err)
	}
	swaps := pinnedtest.SwapAfterCheck(t, path, replacement)
	record, err := ReadGuardianRestoreRecord(path)
	if swaps.Load() != 1 {
		t.Fatalf("swaps = %d, want 1", swaps.Load())
	}
	if err == nil || !strings.Contains(err.Error(), "changed identity before open") {
		t.Fatalf("swapped record = %+v, %v; want refused as changed identity before open", record, err)
	}
}

func TestLoadManifestRefusesAManifestSwappedAfterTheCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	checked := "version: 1\ntargets:\n  - user: checked\n    connector: codex\n    enabled: false\n"
	swapped := "version: 1\ntargets:\n  - user: swapped\n    connector: codex\n    enabled: false\n"
	replacement := writeSwapPair(t, path, []byte(checked), []byte(swapped))

	if manifest, _, err := LoadManifestWithSHA256(path); err != nil || len(manifest.Targets) != 1 || manifest.Targets[0].User != "checked" {
		t.Fatalf("unswapped load = %+v, %v", manifest, err)
	}
	swaps := pinnedtest.SwapAfterCheck(t, path, replacement)
	manifest, digest, err := LoadManifestWithSHA256(path)
	if swaps.Load() != 1 {
		t.Fatalf("swaps = %d, want 1", swaps.Load())
	}
	if err == nil || !strings.Contains(err.Error(), "changed identity before open") {
		t.Fatalf("swapped manifest = %+v (digest %q), %v; want refused as changed identity before open", manifest, digest, err)
	}
}
