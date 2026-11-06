// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// assertPeerFileIdentityBound checks that a plugin snapshot keeps its allowed
// baseline for an unchanged peer target and drops it once a different
// directory, with the same manifest, takes the target path.
func assertPeerFileIdentityBound(t *testing.T, plugin, target string, manifest []byte) {
	t.Helper()
	before, err := snapshotTarget(plugin, true)
	if err != nil {
		t.Fatal(err)
	}
	baseline := &audit.SnapshotRow{
		ContentHash: before.ContentHash, ScanID: "scan-1", ScannerFingerprint: "scanner-1",
	}
	again, err := snapshotTarget(plugin, true)
	if err != nil {
		t.Fatal(err)
	}
	if rescan, reason := shouldRescan(baseline, again, "scanner-1", true); rescan {
		t.Fatalf("unchanged peer target rescanned: %s", reason)
	}
	original, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target, target+"-retired"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "package.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	replaced, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(original, replaced) {
		t.Fatal("the peer target was not replaced")
	}
	after, err := snapshotTarget(plugin, true)
	if err != nil {
		t.Fatal(err)
	}
	if rescan, reason := shouldRescan(baseline, after, "scanner-1", true); !rescan {
		t.Fatalf("a different peer target kept the allowed baseline: %s", reason)
	}
}
