// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestR109PerfWALReadPoolReleasesSidecarsOnStoreClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if store.readDB == nil {
		_ = store.Close()
		t.Fatal("read-only WAL pool is unavailable")
	}
	if store.readDB.Stats().Idle == 0 {
		_ = store.Close()
		t.Fatal("read-only WAL pool has no reusable connection")
	}
	if err := store.LogEvent(Event{Action: "allow", Target: "ordinary"}); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + "-wal"); !os.IsNotExist(err) {
		t.Fatalf("WAL remains after the last store close: %v", err)
	}
}

func TestR109PerfWALReadPoolCloseKeepsCommittedAllow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.SetActionForConnector("tool", "ordinary", "codex", "", ActionState{Install: "allow"}, "reviewed"); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Init(); err != nil {
		t.Fatal(err)
	}
	entry, err := reopened.GetActionForConnector("tool", "ordinary", "codex")
	if err != nil || entry == nil || entry.Actions.Install != "allow" {
		t.Fatalf("committed allow after reopen = %+v, %v", entry, err)
	}
}

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
