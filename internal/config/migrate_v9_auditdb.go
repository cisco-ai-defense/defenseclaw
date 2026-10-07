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
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	// The audit store's driver; every binary that links this package links
	// it already.
	_ "modernc.org/sqlite"
)

// v9AutomaticInstallReasons start the reason of an install block or allow
// that a scan verdict wrote up to 1.0: the gateway watcher ("auto-block:")
// and the CLI scan, install and mcp set paths (which also recorded
// scan-clean allows). Such a row is the enforcement journal, not operator
// intent, and stays in the table.
var v9AutomaticInstallReasons = []string{
	"auto-block", "post-scan:", "post-install scan:", "scan:", "scan clean or within policy",
}

func v9AutomaticInstallReason(reason string) bool {
	reason = strings.TrimSpace(reason)
	for _, prefix := range v9AutomaticInstallReasons {
		if strings.HasPrefix(reason, prefix) {
			return true
		}
	}
	return false
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

// readV9ActionRows returns the operator block/allow rows of the actions
// table: install=block or allow, excluding scan verdicts
// (v9AutomaticInstallReasons), which stay as the journal.
func readV9ActionRows(path string) ([]v9ActionRow, error) {
	db, err := sql.Open("sqlite", auditDBDSN(path, "mode=ro&_pragma=busy_timeout(5000)"))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	query := `SELECT id, target_type, target_name, COALESCE(source_path, ''), actions_json, COALESCE(reason, ''), connector FROM actions`
	rows, err := db.Query(query)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		rows, err = db.Query(`SELECT id, target_type, target_name, COALESCE(source_path, ''), actions_json, COALESCE(reason, ''), '' FROM actions`)
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

// clearV9ActionRows removes the install field of the moved rows in one
// transaction, deleting rows left with no state. It runs after the config
// commit, so the rows are never lost.
func clearV9ActionRows(path string, moved []v9ActionRow) error {
	db, err := sql.Open("sqlite", auditDBDSN(path, "_pragma=busy_timeout(5000)"))
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, row := range moved {
		state := map[string]string{}
		for k, v := range row.state {
			if k != "install" && v != "" {
				state[k] = v
			}
		}
		if len(state) == 0 {
			if _, err := tx.Exec(`DELETE FROM actions WHERE id = ?`, row.id); err != nil {
				return fmt.Errorf("delete actions row %s: %w", row.id, err)
			}
			continue
		}
		encoded, _ := json.Marshal(state)
		if _, err := tx.Exec(`UPDATE actions SET actions_json = ?, updated_at = ? WHERE id = ?`, string(encoded), now, row.id); err != nil {
			return fmt.Errorf("update actions row %s: %w", row.id, err)
		}
	}
	return tx.Commit()
}
