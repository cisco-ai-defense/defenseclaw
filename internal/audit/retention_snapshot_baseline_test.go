// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"
)

// TestRetentionKeepsScanASnapshotBaselineReferences: retention deleted the
// scan_results row a target_snapshots baseline pointed at, so every later
// rescan of that target logged "get scan raw json: sql: no rows" and
// reported no new-finding or severity-escalation drift (rel-1-0-10:GAP-1177).
// The baseline scan stays while a snapshot references it; an old scan no
// snapshot references is still deleted, and so is a baseline scan once its
// snapshot is replaced.
func TestRetentionKeepsScanASnapshotBaselineReferences(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	old := now.Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano)
	for _, id := range []string{"gap1177-baseline", "gap1177-unreferenced", "gap1177-replaced"} {
		if _, err := store.db.Exec(`INSERT INTO scan_results
			(id, scanner, target, timestamp, raw_json) VALUES (?, 'skill-scanner', '/skills/a', ?, '{}')`,
			id, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetTargetSnapshot("skill", "/skills/a", "h1", "{}", "{}", "[]", "gap1177-baseline", "fp"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot("skill", "/skills/b", "h2", "{}", "{}", "[]", "gap1177-replaced", "fp"); err != nil {
		t.Fatal(err)
	}
	// The rescan replaced /skills/b's baseline with a newer scan.
	if err := store.SetTargetSnapshot("skill", "/skills/b", "h3", "{}", "{}", "[]", "gap1177-current", "fp"); err != nil {
		t.Fatal(err)
	}

	result, err := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{}).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := countRetentionLike(t, store.db, "scan_results", "gap1177-baseline"); got != 1 {
		t.Fatalf("retention deleted the scan a snapshot baseline references (rows=%d, deleted=%#v)", got, result.RowsDeleted)
	}
	if raw, err := store.GetScanRawJSON("gap1177-baseline"); err != nil || raw != "{}" {
		t.Fatalf("baseline scan raw json = %q, %v", raw, err)
	}
	if got := countRetentionLike(t, store.db, "scan_results", "gap1177-unreferenced"); got != 0 {
		t.Fatalf("an old scan no snapshot references was kept (rows=%d)", got)
	}
	if got := countRetentionLike(t, store.db, "scan_results", "gap1177-replaced"); got != 0 {
		t.Fatalf("a replaced baseline scan was kept (rows=%d)", got)
	}
	if result.RowsDeleted[RetentionScanResults] != 2 {
		t.Fatalf("scan_results deletes=%d want 2", result.RowsDeleted[RetentionScanResults])
	}
}
