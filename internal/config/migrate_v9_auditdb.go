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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	// The audit store's driver; every binary that links this package links
	// it already.
	_ "modernc.org/sqlite"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Automatic scan reasons have fixed formats. Operator reasons are arbitrary
// text, so match the watcher's complete stem and its known suffix separators.
// Scanner and quarantine failure reasons carry an arbitrary error after their
// distinctive prefixes; these are also automatic journal rows.
var v9AutomaticReasonPattern = lazyregexp.New(`^(?:post-scan: |post-install scan: |scan: )[0-9]+ findings, max=[A-Z]+$`)
var v9WatchReasonPattern = lazyregexp.New(`^auto-block: watch detected [A-Z]+ findings(?: \(scanner=[^)]+\))?(?:$|: |; )`)

func v9AutomaticInstallReason(reason string) bool {
	reason = strings.TrimSpace(reason)
	return reason == "scan clean or within policy" ||
		v9AutomaticReasonPattern.MatchString(reason) ||
		v9WatchReasonPattern.MatchString(reason) ||
		strings.HasPrefix(reason, "scanner failure (fail-closed): ") ||
		strings.HasPrefix(reason, "quarantine failed: ") ||
		strings.HasPrefix(reason, "link removed: ")
}

// auditDBDSN is the file: URI of the audit database. The path goes through
// url.URL, so a '#', '?' or '%' in a directory name (all legal in a user
// profile) stays part of the path instead of ending it.
func auditDBDSN(path, query string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed // a Windows drive path: file:///C:/...
	}
	return (&url.URL{Scheme: "file", Path: slashed, RawQuery: query}).String()
}

// openV9AuditDB opens the audit database with query. A 0.8.x store whose
// schema SQLite refuses (the orphan quarantine_records index that 0.8.x
// concurrent writers leave, "malformed database schema
// (sqlite_autoindex_quarantine_records_1) - orphan index", GAP-1576) is opened
// again with writable_schema on: its actions table is intact, so the
// block/allow rows still move, and the gateway rebuilds the store at its first
// start (audit.rebuildAuditDB). A 0.8.10 store that a rollback started is
// damaged this way within minutes, and refusing it stopped the next upgrade.
// Any other damage still fails the statements that read it, and a store
// whose actions table is among the entries SQLite skipped is refused with
// the original error rather than read as one without rows.
func openV9AuditDB(path, query string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", auditDBDSN(path, query))
	if err != nil {
		return nil, err
	}
	var entries int
	probeErr := db.QueryRow(`SELECT count(*) FROM sqlite_schema`).Scan(&entries)
	if probeErr == nil || !v9AuditDBDamaged(probeErr) {
		return db, nil
	}
	_ = db.Close()
	if db, err = sql.Open("sqlite", auditDBDSN(path, query+"&_pragma=writable_schema(1)")); err != nil {
		return nil, err
	}
	// writable_schema skips the schema entries SQLite cannot parse, so the
	// listing alone cannot tell an intact actions table from a lost or
	// malformed one: exactly one must be listed and a read of it must
	// succeed. Otherwise readV9ActionRowsDB would read "no such table" as a
	// store without operator rows and the migration would drop them.
	var listed, rows int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'actions'`).Scan(&listed); err != nil ||
		listed != 1 || db.QueryRow(`SELECT count(*) FROM actions`).Scan(&rows) != nil {
		_ = db.Close()
		return nil, probeErr
	}
	return db, nil
}

// readV9ActionRows returns the operator block/allow rows of the actions
// table: install=block or allow, excluding scan verdicts
// (v9AutomaticInstallReasons), which stay as the journal.
func readV9ActionRows(path string) ([]v9ActionRow, error) {
	db, err := openV9AuditDB(path, "mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return readV9ActionRowsDB(db)
}

func readV9ActionRowsDB(db *sql.DB) ([]v9ActionRow, error) {
	query := `SELECT id, target_type, target_name, COALESCE(source_path, ''), actions_json, COALESCE(reason, ''), connector FROM actions ORDER BY id`
	rows, err := db.Query(query)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		rows, err = db.Query(`SELECT id, target_type, target_name, COALESCE(source_path, ''), actions_json, COALESCE(reason, ''), '' FROM actions ORDER BY id`)
	}
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []v9ActionRow
	for rows.Next() {
		var row v9ActionRow
		var state string
		if err := rows.Scan(&row.id, &row.targetType, &row.targetName, &row.sourcePath, &state, &row.reason, &row.connector); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(state), &row.state) != nil {
			continue
		}
		install := row.state["install"]
		if install != "block" && install != "allow" {
			continue
		}
		if v9AutomaticInstallReason(row.reason) {
			continue
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// lockV9ActionRows holds a write reservation across the final row check,
// config commit, and cleanup. A changed snapshot requires a fresh plan.
func lockV9ActionRows(ctx context.Context, path string, snapshot []v9ActionRow) (*sql.DB, error) {
	db, err := openV9AuditDB(path, "_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = db.Close()
		return nil, err
	}
	current, err := readV9ActionRowsDB(db)
	if err != nil || !slices.EqualFunc(snapshot, current, func(a, b v9ActionRow) bool {
		return a.id == b.id && a.targetType == b.targetType &&
			a.targetName == b.targetName && a.sourcePath == b.sourcePath &&
			a.reason == b.reason && a.connector == b.connector &&
			maps.Equal(a.state, b.state)
	}) {
		_, _ = db.Exec("ROLLBACK")
		_ = db.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("audit.db operator rows changed while migration ran; run it again")
	}
	return db, nil
}

// v9ActionRowFingerprint covers every field used to select and clear a row.
func v9ActionRowFingerprint(row v9ActionRow) string {
	raw, _ := json.Marshal([]any{row.id, row.targetType, row.targetName,
		row.sourcePath, row.reason, row.connector, row.state})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// resumeV9ActionCleanup checks the pending row snapshots under a write
// reservation. Already-cleared rows can be absent after an interrupted retry.
func resumeV9ActionCleanup(ctx context.Context, cleanup MigrationAuditCleanup) error {
	if cleanup.Path == "" {
		return fmt.Errorf("audit cleanup path is empty")
	}
	if _, err := os.Stat(cleanup.Path); err != nil {
		return err
	}
	db, err := openV9AuditDB(cleanup.Path, "_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() { _, _ = db.Exec("ROLLBACK") }()
	current, err := readV9ActionRowsDB(db)
	if err != nil {
		return err
	}
	byID := make(map[string]v9ActionRow, len(current))
	for _, row := range current {
		byID[row.id] = row
	}
	var moved []v9ActionRow
	for _, planned := range cleanup.Rows {
		row, present := byID[planned.ID]
		if !present {
			continue
		}
		if v9ActionRowFingerprint(row) != planned.Fingerprint {
			return fmt.Errorf("audit.db operator row %s changed after config commit; manual review is required", planned.ID)
		}
		moved = append(moved, row)
	}
	if err := clearV9ActionRowsDB(db, moved); err != nil {
		return err
	}
	_, err = db.Exec("COMMIT")
	return err
}

// clearV9ActionRowsDB removes the install field of moved rows inside the
// caller's write transaction.
func clearV9ActionRowsDB(db *sql.DB, moved []v9ActionRow) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, row := range moved {
		state := map[string]string{}
		for k, v := range row.state {
			if k != "install" && v != "" {
				state[k] = v
			}
		}
		if len(state) == 0 {
			if _, err := db.Exec(`DELETE FROM actions WHERE id = ?`, row.id); err != nil {
				return fmt.Errorf("delete actions row %s: %w", row.id, err)
			}
			continue
		}
		encoded, _ := json.Marshal(state)
		if _, err := db.Exec(`UPDATE actions SET actions_json = ?, updated_at = ? WHERE id = ?`, string(encoded), now, row.id); err != nil {
			return fmt.Errorf("update actions row %s: %w", row.id, err)
		}
	}
	return nil
}
