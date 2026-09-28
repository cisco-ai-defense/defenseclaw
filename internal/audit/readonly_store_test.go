// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func readOnlyTestDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	writer, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := writer.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := writer.LogEvent(Event{Action: "scan", Target: "/tmp/skill", Severity: "INFO", Details: "connector=codex"}); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

// An administrator's review of the managed gateway's store reads it
// without migrating it, changing it or writing to it.
func TestOpenReadOnlyStoreQueriesWithoutWriting(t *testing.T) {
	path := readOnlyTestDatabase(t)
	before := fileDigest(t, path)

	store, err := OpenReadOnlyStore(path)
	if err != nil {
		t.Fatalf("OpenReadOnlyStore: %v", err)
	}
	if _, _, err := store.QueryFindingStatesWithCount(context.Background(), FindingStateQuery{Limit: 10}); err != nil {
		t.Fatalf("QueryFindingStatesWithCount: %v", err)
	}
	if version, err := store.SchemaVersion(); err != nil || version == 0 {
		t.Fatalf("SchemaVersion = %d, %v", version, err)
	}
	if err := store.LogEvent(Event{Action: "scan", Target: "/tmp/other", Severity: "INFO"}); err == nil {
		t.Fatal("a read-only store accepted a write")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if after := fileDigest(t, path); after != before {
		t.Fatal("reading the store read-only changed the database file")
	}

	db, err := OpenReadOnlyDB(path)
	if err != nil {
		t.Fatalf("OpenReadOnlyDB: %v", err)
	}
	defer db.Close()
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&rows); err != nil || rows == 0 {
		t.Fatalf("audit_events rows = %d, %v", rows, err)
	}
	if _, err := db.Exec(`DELETE FROM audit_events`); err == nil {
		t.Fatal("a read-only connection accepted a delete")
	}
}

// A missing database is an error, never a new file.
func TestOpenReadOnlyDBDoesNotCreateAMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	if db, err := OpenReadOnlyDB(path); err == nil {
		_ = db.Close()
		t.Fatal("OpenReadOnlyDB opened a missing database")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("OpenReadOnlyDB created %s: %v", path, err)
	}
}

// A file that is not an initialized audit database is refused.
func TestOpenReadOnlyStoreRefusesAnUninitializedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenReadOnlyStore(path); err == nil {
		_ = store.Close()
		t.Fatal("OpenReadOnlyStore accepted an empty file")
	}
}
