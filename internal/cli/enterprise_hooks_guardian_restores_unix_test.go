// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0499: the standalone Linux and macOS guardian dates, by uid, the
// targets its pass put back (the pass's repair record names them by account
// and connector); a repair record left by an earlier pass is not this
// pass's restore.
func TestEnterpriseHookStandaloneUnixRestoresDateThePassRepairs(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	dataDir := t.TempDir()
	rows := []enterpriseHookReconcileRow{
		{User: "alice", UID: 1001, Connector: "hermes", OK: true},
		{User: "alice", UID: 1001, Connector: "codex", OK: true},
		{User: "bob", UID: 1002, Connector: "hermes", OK: true},
	}
	writeRepairs := func(at time.Time, users ...string) {
		t.Helper()
		type repair struct {
			User      string `json:"user"`
			Connector string `json:"connector"`
		}
		var repaired []repair
		for _, user := range users {
			repaired = append(repaired, repair{User: user, Connector: "hermes"})
		}
		data, err := json.Marshal(struct {
			UpdatedAt string   `json:"updated_at"`
			Repaired  []repair `json:"repaired"`
		}{at.UTC().Format(time.RFC3339Nano), repaired})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, hookGuardianRepairsFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	since := time.Now().Add(-time.Second)
	repairedAt := since.Add(500 * time.Millisecond)
	writeRepairs(repairedAt, "alice")
	if err := recordEnterpriseHookStandaloneUnixRestores(io.Discard, dataDir, since, enterpriseHookReconcileRun{Rows: rows, Repairs: 1}); err != nil {
		t.Fatal(err)
	}
	restores := guardianRestoresForTest(t, dataDir)
	if len(restores) != 1 || !restores[enterpriseHookGuardianRestoreUIDKey(1001, "hermes")].Equal(repairedAt.UTC()) {
		t.Fatalf("restores = %v, want hermes of uid 1001 at %s", restores, repairedAt)
	}
	record := readGuardianRestoreRecordForTest(t, dataDir)
	if len(record.Targets) != 1 || record.Targets[0].User != "alice" || record.Targets[0].SID != "" {
		t.Fatalf("record = %+v, want alice by uid", record.Targets)
	}

	// The next pass repaired bob but could not rewrite the repair record:
	// the earlier record is not taken for this pass.
	later := time.Now().Add(time.Second)
	if err := recordEnterpriseHookStandaloneUnixRestores(io.Discard, dataDir, later, enterpriseHookReconcileRun{Rows: rows, Repairs: 1}); err != nil {
		t.Fatal(err)
	}
	if restores := guardianRestoresForTest(t, dataDir); len(restores) != 1 {
		t.Fatalf("restores after a pass without its own repair record = %v, want only alice's", restores)
	}

	// A directory outage: alice's identity lookup is pending, then fails, so
	// her rows of these passes carry no uid. She is still enrolled and her
	// Hermes session may still run: her entry stays (verify r1 F3).
	for _, outage := range []enterpriseHookReconcileRow{
		{Pending: true},
		{Error: "enterprise hooks: resolve alice: directory unavailable"},
	} {
		passRows := []enterpriseHookReconcileRow{outage, outage, rows[2]}
		passRows[0].User, passRows[0].Connector = "alice", "hermes"
		passRows[1].User, passRows[1].Connector = "alice", "codex"
		if err := recordEnterpriseHookStandaloneUnixRestores(io.Discard, dataDir, later, enterpriseHookReconcileRun{Rows: passRows}); err != nil {
			t.Fatal(err)
		}
		restores := guardianRestoresForTest(t, dataDir)
		if len(restores) != 1 || !restores[enterpriseHookGuardianRestoreUIDKey(1001, "hermes")].Equal(repairedAt.UTC()) {
			t.Fatalf("restores after a pass with alice's rows %+v = %v, want hermes of uid 1001 at %s", passRows[:2], restores, repairedAt)
		}
	}

	// alice left the manifest: her entry is dropped by a pass without repairs.
	if err := recordEnterpriseHookStandaloneUnixRestores(io.Discard, dataDir, later, enterpriseHookReconcileRun{Rows: rows[2:]}); err != nil {
		t.Fatal(err)
	}
	if restores := guardianRestoresForTest(t, dataDir); len(restores) != 0 {
		t.Fatalf("restores after alice left = %v, want none", restores)
	}

	// alice's name now maps to another uid (the reconcile revokes her
	// earlier protection): the old uid's entry is not kept by her name.
	again := time.Now().Add(-time.Second)
	writeRepairs(again.Add(500*time.Millisecond), "alice")
	if err := recordEnterpriseHookStandaloneUnixRestores(io.Discard, dataDir, again, enterpriseHookReconcileRun{Rows: rows, Repairs: 1}); err != nil {
		t.Fatal(err)
	}
	if restores := guardianRestoresForTest(t, dataDir); len(restores) != 1 {
		t.Fatalf("restores after alice's second repair = %v, want hermes of uid 1001", restores)
	}
	reassigned := enterpriseHookReconcileRow{User: "alice", Connector: "hermes", Error: "enterprise hooks: alice now has another uid", RevokeProtection: true}
	if err := recordEnterpriseHookStandaloneUnixRestores(io.Discard, dataDir, later, enterpriseHookReconcileRun{Rows: append([]enterpriseHookReconcileRow{reassigned}, rows[2:]...)}); err != nil {
		t.Fatal(err)
	}
	if restores := guardianRestoresForTest(t, dataDir); len(restores) != 0 {
		t.Fatalf("restores after alice's uid was reassigned = %v, want none", restores)
	}
}
