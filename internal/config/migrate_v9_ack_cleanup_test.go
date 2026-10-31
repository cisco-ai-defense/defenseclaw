// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const v9AckTestRow = `INSERT INTO actions VALUES ('1', 'skill', 'restored-skill', '', '{"install":"block"}', 'operator', 'now', '')`

// v9AckTestHome is a config_version 8 data home with one operator skill block
// row in audit.db.
func v9AckTestHome(t *testing.T) (MigrateV9Input, *sql.DB) {
	t.Helper()
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath, auditDB := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "audit.db")
	if err := os.WriteFile(configPath, []byte("config_version: 8\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", auditDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE actions (id TEXT PRIMARY KEY, target_type TEXT, target_name TEXT, source_path TEXT, actions_json TEXT, reason TEXT, updated_at TEXT, connector TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(v9AckTestRow); err != nil {
		t.Fatal(err)
	}
	return MigrateV9Input{ConfigPath: configPath, AuditDBPath: auditDB}, db
}

func v9AckTestRowsLeft(t *testing.T, db *sql.DB) int {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM actions WHERE id = '1'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// The commit clears the moved rows before the pre-9 Rego refresh, so a
// refresh that fails leaves a pending record whose rows are already gone.
// `config migrate --ack` then must not note that they may still be in
// audit.db; it does when one is still there (GAP-1552).
func TestAcknowledgeMigrationV9NotesOnlyRowsLeftInAuditDB(t *testing.T) {
	const note = "may still be in audit.db"
	for _, rowLeft := range []bool{false, true} {
		t.Run(fmt.Sprintf("row-left=%v", rowLeft), func(t *testing.T) {
			in, db := v9AckTestHome(t)
			ctx := context.Background()
			if _, err := MigrateV9(ctx, in); err != nil {
				t.Fatal(err)
			}
			if left := v9AckTestRowsLeft(t, db); left != 0 {
				t.Fatalf("the commit left %d moved rows", left)
			}
			if rowLeft {
				// What a cleanup that did not finish leaves.
				if _, err := db.Exec(v9AckTestRow); err != nil {
					t.Fatal(err)
				}
			}
			record, ok := readMigrationRecord(in.ConfigPath)
			if !ok || record.ActionsRowsMoved != 1 || record.AuditCleanup == nil || len(record.AuditCleanup.Rows) != 1 {
				t.Fatalf("migrated row record: %+v", record)
			}
			// What a pre-9 Rego refresh that failed after the commit leaves.
			record.Pending = true
			if err := writeMigrationRecord(MigrationRecordPath(in.ConfigPath), record); err != nil {
				t.Fatal(err)
			}
			if err := AcknowledgeMigrationV9(ctx, in); err != nil {
				t.Fatal(err)
			}
			record, _ = readMigrationRecord(in.ConfigPath)
			noted := slices.ContainsFunc(record.Notes, func(line string) bool { return strings.Contains(line, note) })
			if record.Pending || !record.Acknowledged || noted != rowLeft {
				t.Fatalf("--ack with row left %v: pending %v, acknowledged %v, notes %q", rowLeft, record.Pending,
					record.Acknowledged, record.Notes)
			}
		})
	}
}
