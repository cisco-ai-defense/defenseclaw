// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// schemaOf lists what the store at path holds: every table, index and trigger
// with its SQL, and the schema versions applied.
func schemaOf(t *testing.T, path string) (objects, versions []string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	read := func(query string) []string {
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var a, b, c sql.NullString
			if err := rows.Scan(&a, &b, &c); err != nil {
				t.Fatal(err)
			}
			out = append(out, a.String+"|"+b.String+"|"+c.String)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	return read("SELECT type, name, sql FROM sqlite_master ORDER BY type, name"),
		read("SELECT version, \"\", \"\" FROM schema_version ORDER BY version")
}

// The fixtures start from a database migrated once, to spare each test the
// migration list under -race. That is the same database as a fresh one only
// while it holds the same schema and versions after the caller Init.
func TestSeededAuditDatabaseHoldsTheSchemaOfAFreshlyMigratedOne(t *testing.T) {
	fresh := filepath.Join(t.TempDir(), "fresh.db")
	store, err := audit.NewStore(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	seeded := filepath.Join(t.TempDir(), "seeded.db")
	seedMigratedAuditDB(t, seeded)
	store, err = audit.NewStore(seeded)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	wantObjects, wantVersions := schemaOf(t, fresh)
	gotObjects, gotVersions := schemaOf(t, seeded)
	if len(wantVersions) == 0 || len(wantObjects) == 0 {
		t.Fatalf("a freshly migrated store holds %d objects and %d versions", len(wantObjects), len(wantVersions))
	}
	if !reflect.DeepEqual(gotObjects, wantObjects) {
		t.Fatalf("seeded store schema differs from a freshly migrated one:\n got %d objects\nwant %d objects", len(gotObjects), len(wantObjects))
	}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Fatalf("seeded store versions = %v, want %v", gotVersions, wantVersions)
	}
}
