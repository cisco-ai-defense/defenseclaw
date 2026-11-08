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

// The record is written, refreshed, read back and removed when it is empty;
// a record that cannot be read does not stop a new entry.
func TestEnterpriseHookRemovedConnectorsRecordLifecycle(t *testing.T) {
	dataDir := stubRemovedConnectorsRecord(t)
	now := time.Date(2026, 11, 8, 18, 0, 0, 0, time.UTC)
	if entries, err := loadEnterpriseHookRemovedConnectors(dataDir); err != nil || entries != nil {
		t.Fatalf("missing record = %v, %v", entries, err)
	}
	first := managed.RemovedConnector{Connector: "Cursor", SID: "S-1-5-21-1-2-3-1001", User: "alice"}
	if err := recordEnterpriseHookRemovedConnector(dataDir, first, now); err != nil {
		t.Fatal(err)
	}
	if err := recordEnterpriseHookRemovedConnector(dataDir, first, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := recordEnterpriseHookRemovedConnector(dataDir, managed.RemovedConnector{Connector: "codex", SID: "S-1-5-21-1-2-3-1001"}, now); err != nil {
		t.Fatal(err)
	}
	entries, err := loadEnterpriseHookRemovedConnectors(dataDir)
	if err != nil || len(entries) != 2 || entries[0].Connector != "codex" || entries[1].Connector != "cursor" {
		t.Fatalf("entries = %+v, %v; want codex and cursor once each", entries, err)
	}
	if entries[1].RemovedAt != now.Add(time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("the refreshed entry kept its old time: %+v", entries[1])
	}
	path := managed.RemovedConnectorsPath(dataDir)
	if err := os.WriteFile(path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordEnterpriseHookRemovedConnector(dataDir, first, now); err != nil {
		t.Fatalf("a damaged record stopped a new entry: %v", err)
	}
	if entries, err = loadEnterpriseHookRemovedConnectors(dataDir); err != nil || len(entries) != 1 {
		t.Fatalf("replaced record = %+v, %v", entries, err)
	}
	if err := saveEnterpriseHookRemovedConnectors(dataDir, nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("an empty record stays: %v", err)
	}
}

// An entry ages out when the connector is on the roster again for the
// account (manifest or config) or the account is gone; time alone never ends it.
func TestEnterpriseHookRemovedConnectorsAgeOut(t *testing.T) {
	dataDir := stubRemovedConnectorsRecord(t)
	now := time.Date(2026, 11, 8, 18, 0, 0, 0, time.UTC)
	long := now.Add(-400 * 24 * time.Hour)
	const alice, bob, carol = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1003"
	for _, entry := range []managed.RemovedConnector{
		{Connector: "cursor", SID: alice}, {Connector: "codex", SID: alice},
		{Connector: "cursor", SID: bob}, {Connector: "claudecode", SID: carol},
	} {
		if err := recordEnterpriseHookRemovedConnector(dataDir, entry, long); err != nil {
			t.Fatal(err)
		}
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
