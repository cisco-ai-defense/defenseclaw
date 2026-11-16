// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// migratedAuditTemplate is one audit database that Store.Init migrated once
// for the whole test process. Most gateway tests build an audit store of
// their own (testStoreAndLogger), and the migrations of a fresh database
// were most of the cost of such a test: under -race a fresh Store.Init took
// about 0.3 s on dc-build-2 (TestHostShellCallsInTheirOwnWorkdirAreJudged
// spent 25.5 s of its 70 s in Store.Init), so the race shards of CI spent
// minutes migrating identical empty databases (rel-1-0-6:GAP-0252).
var migratedAuditTemplate struct {
	once sync.Once
	dir  string
	err  error
}

// migratedAuditFiles are the files of a closed audit database; a WAL that a
// close did not fold back in is copied with it.
var migratedAuditFiles = []string{"audit.db", "audit.db-wal"}

// newMigratedTestAuditStore opens an audit store at path from a copy of the
// migrated template; its Init still runs every readiness check of a store
// opened on an existing database. The caller owns path's directory.
func newMigratedTestAuditStore(t testing.TB, path string) *audit.Store {
	t.Helper()
	migratedAuditTemplate.once.Do(func() {
		migratedAuditTemplate.dir, migratedAuditTemplate.err = os.MkdirTemp("", "gateway-audit-template-")
		if migratedAuditTemplate.err != nil {
			return
		}
		store, err := audit.NewStore(filepath.Join(migratedAuditTemplate.dir, "audit.db"))
		if err == nil {
			err = errors.Join(store.Init(), store.Close())
		}
		migratedAuditTemplate.err = err
	})
	if err := migratedAuditTemplate.err; err != nil {
		t.Fatalf("migrate the template audit database: %v", err)
	}
	for _, name := range migratedAuditFiles {
		body, err := os.ReadFile(filepath.Join(migratedAuditTemplate.dir, name))
		if errors.Is(err, fs.ErrNotExist) && name != "audit.db" {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		target := path + name[len("audit.db"):]
		if err := os.WriteFile(target, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	return store
}

// removeMigratedAuditTemplate deletes the template after the last test.
func removeMigratedAuditTemplate() {
	if migratedAuditTemplate.dir != "" {
		_ = os.RemoveAll(migratedAuditTemplate.dir)
	}
}

// A store opened from the migrated template has the schema of a store that
// Store.Init migrated from nothing, and no rows of another store: copies are
// independent.
func TestMigratedTestAuditStoreMatchesAFreshlyMigratedStore(t *testing.T) {
	freshPath := filepath.Join(t.TempDir(), "audit.db")
	fresh, err := audit.NewStore(freshPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Init(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(t.TempDir(), "audit.db")
	first := newMigratedTestAuditStore(t, firstPath)
	secondPath := filepath.Join(t.TempDir(), "audit.db")
	newMigratedTestAuditStore(t, secondPath)
	if err := first.LogEvent(audit.Event{Action: "template-copy-probe", Target: "first", Severity: "INFO"}); err != nil {
		t.Fatal(err)
	}
	schema := func(path string) ([][2]string, int) {
		t.Helper()
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		rows, err := database.Query(`SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var objects [][2]string
		for rows.Next() {
			var object [2]string
			if err := rows.Scan(&object[0], &object[1]); err != nil {
				t.Fatal(err)
			}
			objects = append(objects, object)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		var probes int
		if err := database.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&probes); err != nil {
			t.Fatal(err)
		}
		return objects, probes
	}
	want, _ := schema(freshPath)
	if len(want) == 0 {
		t.Fatal("a freshly migrated store has no schema")
	}
	for _, path := range []string{firstPath, secondPath} {
		if got, _ := schema(path); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: schema differs from a freshly migrated store:\n got %d objects\nwant %d objects", path, len(got), len(want))
		}
	}
	if _, probes := schema(firstPath); probes == 0 {
		t.Fatal("the probe row is not in the copy it was written to")
	}
	if _, probes := schema(secondPath); probes != 0 {
		t.Errorf("a row written to one copy is in another copy (%d rows)", probes)
	}
}
