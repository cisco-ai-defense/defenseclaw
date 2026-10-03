// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPendingMigrations(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.db")
	if n, err := PendingMigrations(missing); err != nil || n != 0 {
		t.Fatalf("missing store: got %d, %v; want 0, nil", n, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("PendingMigrations created the store: %v", err)
	}

	path := filepath.Join(dir, "audit.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := PendingMigrations(path); err != nil || n != len(migrations) {
		t.Fatalf("empty store: got %d, %v; want %d", n, err, len(migrations))
	}

	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if n, err := PendingMigrations(path); err != nil || n != 0 {
		t.Fatalf("current store: got %d, %v; want 0", n, err)
	}
	// A 0.x store stopped before the pre-1.0 history purge (GAP-1909).
	if _, err := store.db.Exec(`DELETE FROM schema_version WHERE version > 32`); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if n, err := PendingMigrations(path); err != nil || n != len(migrations)-32 {
		t.Fatalf("0.x store: got %d, %v; want %d", n, err, len(migrations)-32)
	}
}
