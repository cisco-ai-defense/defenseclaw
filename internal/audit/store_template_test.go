package audit

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// GAP-0964: every fresh test store replayed all migrations (89 ms plain, 3.1 s
// under -race, because each ALTER re-parses the whole schema), and the package
// opens ~800 of them. The test binary migrates once per schema layout into a
// template file; auditStoreSeed copies its bytes into each new empty store file
// before SQLite opens it, so Init finds the schema current and skips the replay.
// The production open path is unchanged (the hook is nil outside this binary).
// Tests that must see the real migration path ask for a path with
// realMigrationPath. TestStoreTemplateMatchesFreshMigration proves the template
// is byte-identical in schema to a fresh migration. Re-check after any change
// to the migration list (sub0664 changes migration code: GAP-0945/0946).

type storeTemplate struct {
	once sync.Once
	data []byte
	err  error
}

var (
	storeTemplates   [2]storeTemplate // index 0: standard layout, 1: Secure Client layout
	noSeedPaths      sync.Map         // paths that keep the real migration path
	storeTemplateDir string
)

func init() { auditStoreSeed = seedStoreFromTemplate }

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "audit-store-template-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit tests: template dir:", err)
		os.Exit(1)
	}
	storeTemplateDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// realMigrationPath marks path as one whose first Init replays every migration.
func realMigrationPath(path string) string {
	noSeedPaths.Store(path, true)
	return path
}

func buildStoreTemplate(secureClient bool) ([]byte, error) {
	name := "standard.db"
	var opts []StoreOption
	if secureClient {
		name, opts = "secure-client.db", []StoreOption{WithSecureClientSchema()}
	}
	path := filepath.Join(storeTemplateDir, name)
	realMigrationPath(path)
	store, err := NewStore(path, opts...)
	if err != nil {
		return nil, err
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		return nil, err
	}
	// Close checkpoints the WAL; a template must be one self-contained file.
	if err := store.Close(); err != nil {
		return nil, err
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Stat(sidecar); err == nil {
			return nil, fmt.Errorf("template left %s behind", filepath.Base(sidecar))
		}
	}
	return os.ReadFile(path)
}

func seedStoreFromTemplate(path string, secureClient bool) {
	if _, skip := noSeedPaths.Load(path); skip {
		return
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		return
	}
	idx := 0
	if secureClient {
		idx = 1
	}
	tpl := &storeTemplates[idx]
	tpl.once.Do(func() { tpl.data, tpl.err = buildStoreTemplate(secureClient) })
	if tpl.err != nil {
		// A broken template must fail loudly, not fall back to slow stores.
		panic(fmt.Sprintf("audit tests: store template: %v", tpl.err))
	}
	if err := os.WriteFile(path, tpl.data, 0o600); err != nil {
		panic(fmt.Sprintf("audit tests: seed %s: %v", path, err))
	}
}

type schemaRow struct{ Type, Name, TblName, SQL string }

func readSchema(t *testing.T, path string) ([]schemaRow, int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatalf("read sqlite_master: %v", err)
	}
	defer rows.Close()
	var out []schemaRow
	for rows.Next() {
		var r schemaRow
		if err := rows.Scan(&r.Type, &r.Name, &r.TblName, &r.SQL); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	return out, version
}

// The template must be a pure cache of the real migration: the same
// sqlite_master rows (type, name, tbl_name, sql) and PRAGMA user_version as a
// store that replayed every migration, for both schema layouts.
func TestStoreTemplateMatchesFreshMigration(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []StoreOption
	}{
		{"standard", nil},
		{"secure_client", []StoreOption{WithSecureClientSchema()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fresh := realMigrationPath(filepath.Join(t.TempDir(), "fresh.db"))
			store, err := NewStore(fresh, tc.opts...)
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
			seededStore, err := NewStore(seeded, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(seeded)
			if err != nil || info.Size() == 0 {
				t.Fatalf("seeded store file was not populated from the template: %v", err)
			}
			if err := seededStore.Init(); err != nil {
				t.Fatal(err)
			}
			if err := seededStore.Close(); err != nil {
				t.Fatal(err)
			}

			wantRows, wantVersion := readSchema(t, fresh)
			gotRows, gotVersion := readSchema(t, seeded)
			if len(wantRows) < 100 {
				t.Fatalf("fresh migration produced only %d schema rows; the comparison is not meaningful", len(wantRows))
			}
			if gotVersion != wantVersion {
				t.Fatalf("user_version = %d, fresh migration has %d", gotVersion, wantVersion)
			}
			if !reflect.DeepEqual(gotRows, wantRows) {
				t.Fatalf("seeded sqlite_master differs from a fresh migration (%d vs %d rows)", len(gotRows), len(wantRows))
			}
		})
	}
}

// The real migration path stays covered: a store at a realMigrationPath replays
// every migration on first Init.
func TestRealMigrationPathStillReplaysEveryMigration(t *testing.T) {
	path := realMigrationPath(filepath.Join(t.TempDir(), "real.db"))
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var applied int
	var progress bytes.Buffer
	store.SetMigrationProgress(&progress)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != len(migrations) {
		t.Fatalf("schema_version rows = %d, want %d", applied, len(migrations))
	}
	if got := strings.Count(progress.String(), "applying migration"); got != len(migrations) {
		t.Fatalf("replayed %d migrations, want %d", got, len(migrations))
	}
}
