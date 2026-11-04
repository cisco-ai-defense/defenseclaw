// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

func TestR109PerfWALReadPoolIsReadOnly(t *testing.T) {
	store, _ := newCorrelationTestStore(t)
	if store.readDB == nil {
		t.Fatal("read-only WAL pool is unavailable")
	}
	if _, err := store.readDB.ExecContext(t.Context(), `CREATE TABLE r109_read_pool_probe (id INTEGER)`); err == nil {
		t.Fatal("read-only WAL pool accepted a write")
	}
}

func TestR109PerfWALSecureClientUsesOriginalConnection(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"), WithSecureClientSchema())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if store.readDB != nil || store.queryPool() != store.db {
		t.Fatal("Secure Client audit connection changed")
	}
}

func TestR109PerfWALVerdictReadSeesCommittedWrite(t *testing.T) {
	store, _ := newCorrelationTestStore(t)
	if err := store.SetActionForConnector("tool", "example", "codex", "", ActionState{Install: "block"}, "reviewed"); err != nil {
		t.Fatal(err)
	}
	entry, err := store.GetActionForConnector("tool", "example", "codex")
	if err != nil || entry == nil || entry.Actions.Install != "block" {
		t.Fatalf("committed verdict = %+v, %v", entry, err)
	}
	if err := store.SetActionForConnector("tool", "example", "codex", "", ActionState{Install: "allow"}, "reviewed"); err != nil {
		t.Fatal(err)
	}
	entry, err = store.GetActionForConnector("tool", "example", "codex")
	if err != nil || entry == nil || entry.Actions.Install != "allow" {
		t.Fatalf("updated verdict = %+v, %v", entry, err)
	}
}
