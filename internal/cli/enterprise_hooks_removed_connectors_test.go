// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubRemovedConnectorsRecord(t *testing.T) string {
	t.Helper()
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	previous := enterpriseHookAuthorizationOwnershipSetter
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	t.Cleanup(func() { enterpriseHookAuthorizationOwnershipSetter = previous })
	scope := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	return filepath.Join(scope, "runtime")
}

// The record is written, read back and removed when it is empty; a record
// that cannot be read is replaced by what the rows still show.
func TestEnterpriseHookRemovedConnectorsRecordLifecycle(t *testing.T) {
	dataDir := stubRemovedConnectorsRecord(t)
	now := time.Date(2026, 11, 8, 18, 0, 0, 0, time.UTC)
	if entries, err := loadEnterpriseHookRemovedConnectors(dataDir); err != nil || entries != nil {
		t.Fatalf("missing record = %v, %v", entries, err)
	}
	machine := func(name string) bool { return name == "cursor" || name == "codex" || name == "claudecode" }
	notPublished := func(string) bool { return false }
	rows := []enterpriseHookReconcileRow{
		{SID: "S-1-5-21-1-2-3-1001", User: "alice", Connector: "Cursor", Pending: true},
		{SID: "S-1-5-21-1-2-3-1001", User: "alice", Connector: "codex", OK: true},
	}
	if err := recordEnterpriseHookRemovedConnectors(dataDir, rows, enterprisehooks.Manifest{}, notPublished, machine, now); err != nil {
		t.Fatal(err)
	}
	entries, err := loadEnterpriseHookRemovedConnectors(dataDir)
	if err != nil || len(entries) != 2 || entries[0].Connector != "codex" || entries[1].Connector != "cursor" || entries[1].User != "alice" {
		t.Fatalf("entries = %+v, %v; want codex and cursor of alice", entries, err)
	}
	// A second pass with the same rows keeps the first removal time.
	if err := recordEnterpriseHookRemovedConnectors(dataDir, rows, enterprisehooks.Manifest{}, notPublished, machine, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if again, _ := loadEnterpriseHookRemovedConnectors(dataDir); again[1].RemovedAt != entries[1].RemovedAt {
		t.Fatalf("the removal time moved: %+v", again)
	}
	path := managed.RemovedConnectorsPath(dataDir)
	if err := os.WriteFile(path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordEnterpriseHookRemovedConnectors(dataDir, rows, enterprisehooks.Manifest{}, notPublished, machine, now); err != nil {
		t.Fatalf("a damaged record stopped the rebuild: %v", err)
	}
	if entries, err = loadEnterpriseHookRemovedConnectors(dataDir); err != nil || len(entries) != 2 {
		t.Fatalf("rebuilt record = %+v, %v", entries, err)
	}
	if err := saveEnterpriseHookRemovedConnectors(dataDir, nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("an empty record stays: %v", err)
	}
}

// Only a machine-scope connector the config no longer publishes and the
// manifest no longer admits is recorded; a connector the config still
// publishes, an admitted target, a per-user connector, a deleted account's
// row and a row without an account are not.
func TestPlanEnterpriseHookRemovedConnectorsOnlyRecordsARosterRemoval(t *testing.T) {
	now := time.Date(2026, 11, 8, 18, 0, 0, 0, time.UTC)
	const alice, bob = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	machine := func(name string) bool { return name == "cursor" || name == "codex" }
	published := func(name string) bool { return name == "codex" }
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{Connector: "cursor", SID: bob}}}
	rows := []enterpriseHookReconcileRow{
		{SID: alice, Connector: "cursor", OK: true},                               // recorded
		{SID: alice, Connector: "codex", OK: true},                                // config still publishes it
		{SID: bob, Connector: "cursor", Pending: true},                            // the manifest still admits it
		{SID: alice, Connector: "copilot", OK: true},                              // per-user connector
		{SID: bob, Connector: "cursor", Removed: true},                            // deleted account
		{Connector: "cursor", OK: true},                                           // no account
		{SID: alice, Result: &enterprisehooks.InstallResult{Connector: "cursor"}}, // connector from the result, already seen
	}
	planned, changed := planEnterpriseHookRemovedConnectors(nil, rows, manifest, published, machine, now)
	if !changed || len(planned) != 1 || planned[0].Connector != "cursor" || planned[0].SID != alice {
		t.Fatalf("planned = %+v changed=%t, want only cursor of alice", planned, changed)
	}
	if again, changed := planEnterpriseHookRemovedConnectors(planned, rows, manifest, published, machine, now); changed || len(again) != 1 {
		t.Fatalf("a second plan changed the record: %+v", again)
	}
}

// An entry ages out when the connector is on the roster again for the
// account (manifest or config) or the account is gone; time alone never ends it.
func TestEnterpriseHookRemovedConnectorsAgeOut(t *testing.T) {
	dataDir := stubRemovedConnectorsRecord(t)
	now := time.Date(2026, 11, 8, 18, 0, 0, 0, time.UTC)
	long := now.Add(-400 * 24 * time.Hour)
	const alice, bob, carol = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1003"
	var seed []managed.RemovedConnector
	for _, entry := range []managed.RemovedConnector{
		{Connector: "cursor", SID: alice}, {Connector: "codex", SID: alice},
		{Connector: "cursor", SID: bob}, {Connector: "claudecode", SID: carol},
	} {
		seed = append(seed, managed.RemovedConnector{Connector: entry.Connector, SID: entry.SID, RemovedAt: long.Format(time.RFC3339Nano)})
	}
	if err := saveEnterpriseHookRemovedConnectors(dataDir, seed, long); err != nil {
		t.Fatal(err)
	}
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{Connector: "codex", SID: alice}}}
	published := func(name string) bool { return name == "claudecode" }
	gone := func(sid string) bool { return sid == bob }
	if err := pruneEnterpriseHookRemovedConnectors(dataDir, manifest, published, gone, now); err != nil {
		t.Fatal(err)
	}
	entries, err := loadEnterpriseHookRemovedConnectors(dataDir)
	if err != nil || len(entries) != 1 || entries[0].Connector != "cursor" || entries[0].SID != alice {
		t.Fatalf("after the prune: %+v, %v; want only cursor of alice (old as it is)", entries, err)
	}
	if err := pruneEnterpriseHookRemovedConnectors(dataDir, enterprisehooks.Manifest{}, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	if entries, _ = loadEnterpriseHookRemovedConnectors(dataDir); len(entries) != 1 {
		t.Fatalf("a prune with nothing to drop changed the record: %+v", entries)
	}
}
