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

package policy

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/sqliteperms"

	_ "modernc.org/sqlite" // pure Go SQLite driver
)

// SQLitePolicyStore implements PolicyStore backed by a SQLite database.
// Uses modernc.org/sqlite — a pure Go implementation with no CGO dependency.
type SQLitePolicyStore struct {
	db *sql.DB
}

// NewSQLitePolicyStore opens (or creates) a SQLite database at the given path
// and initializes the policies table.
func NewSQLitePolicyStore(dbPath string) (*SQLitePolicyStore, error) {
	if err := sqliteperms.Prepare(dbPath); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}
	if _, err := db.Exec("PRAGMA secure_delete = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable secure_delete: %w", err)
	}

	if err := createPoliciesTable(db); err != nil {
		db.Close()
		return nil, err
	}

	if err := createMetadataTable(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := createEmergencyTable(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := sqliteperms.Secure(dbPath); err != nil {
		db.Close()
		return nil, err
	}

	return &SQLitePolicyStore{db: db}, nil
}

func createPoliciesTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS policies (
			tenant_id   INTEGER NOT NULL,
			fleet_id    INTEGER NOT NULL,
			version     INTEGER NOT NULL,
			profile     TEXT    NOT NULL DEFAULT 'standard',
			policy_bin  BLOB   NOT NULL,
			signature   TEXT   NOT NULL DEFAULT '',
			created_at  TEXT   NOT NULL,
			distributed INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (tenant_id, fleet_id, version)
		)
	`)
	if err != nil {
		return fmt.Errorf("create policies table: %w", err)
	}

	// Index for efficient latest-version lookups
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_policies_tenant_fleet_version
		ON policies (tenant_id, fleet_id, version DESC)
	`)
	if err != nil {
		return fmt.Errorf("create index: %w", err)
	}

	return nil
}

func createMetadataTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS metadata (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create metadata table: %w", err)
	}
	return nil
}

func createEmergencyTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS emergency_history (
			tenant_id INTEGER NOT NULL,
			fleet_id INTEGER NOT NULL,
			sequence  INTEGER NOT NULL,
			message   BLOB NOT NULL,
			PRIMARY KEY (tenant_id, fleet_id, sequence)
		)
	`)
	if err != nil {
		return fmt.Errorf("create emergency history table: %w", err)
	}
	return nil
}

func (s *SQLitePolicyStore) GetEmergencySeq() (uint32, error) {
	var valStr string
	err := s.db.QueryRow(`SELECT value FROM metadata WHERE key = 'emergency_seq'`).Scan(&valStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("get emergency_seq: %w", err)
	}
	val, err := parseUint32(valStr)
	if err != nil {
		return 0, fmt.Errorf("parse emergency_seq %q: %w", valStr, err)
	}
	return val, nil
}

func (s *SQLitePolicyStore) SetEmergencySeq(seq uint32) error {
	_, err := s.db.Exec(`
		INSERT INTO metadata (key, value) VALUES ('emergency_seq', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, fmt.Sprintf("%d", seq))
	if err != nil {
		return fmt.Errorf("set emergency_seq: %w", err)
	}
	return nil
}

// SaveEmergency persists both the anti-replay counter and replayable command
// in one transaction before the MQTT publish. A power loss cannot leave the
// counter advanced while silently dropping the last command.
func (s *SQLitePolicyStore) SaveEmergency(tenantID, fleetID uint64, seq uint32, signedMessage []byte) error {
	if len(signedMessage) != EmergencyMsgSize {
		return fmt.Errorf("emergency message must be %d bytes, got %d", EmergencyMsgSize, len(signedMessage))
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin emergency transaction: %w", err)
	}
	defer tx.Rollback()
	var previous uint32
	err = tx.QueryRow(`SELECT CAST(value AS INTEGER) FROM metadata WHERE key = 'emergency_seq'`).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read emergency sequence: %w", err)
	}
	if seq <= previous {
		return fmt.Errorf("emergency sequence %d is not newer than %d", seq, previous)
	}
	var fleetPrevious uint32
	err = tx.QueryRow(`SELECT sequence FROM emergency_history WHERE tenant_id=? AND fleet_id=? ORDER BY sequence DESC LIMIT 1`, tenantID, fleetID).Scan(&fleetPrevious)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("read fleet emergency predecessor: %w", err)
	}
	if err := validateEmergencyChain(seq, fleetPrevious, signedMessage); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		INSERT INTO metadata (key, value) VALUES ('emergency_seq', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, fmt.Sprintf("%d", seq)); err != nil {
		return fmt.Errorf("persist emergency sequence: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO emergency_history (tenant_id, fleet_id, sequence, message)
		VALUES (?, ?, ?, ?)
	`, tenantID, fleetID, seq, signedMessage); err != nil {
		return fmt.Errorf("persist emergency replay: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit emergency transaction: %w", err)
	}
	return nil
}

func (s *SQLitePolicyStore) GetLastEmergency(tenantID, fleetID uint64) (*EmergencyRecord, error) {
	var rec EmergencyRecord
	err := s.db.QueryRow(`
		SELECT sequence, message FROM emergency_history
		WHERE tenant_id = ? AND fleet_id = ?
		ORDER BY sequence DESC LIMIT 1
	`, tenantID, fleetID).Scan(&rec.Sequence, &rec.Message)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read emergency replay for tenant=%d fleet=%d: %w", tenantID, fleetID, err)
	}
	if len(rec.Message) != EmergencyMsgSize {
		return nil, fmt.Errorf("invalid persisted emergency command length %d", len(rec.Message))
	}
	return &rec, nil
}

func (s *SQLitePolicyStore) GetEmergenciesAfter(tenantID, fleetID uint64, afterSeq uint32, limit int) ([]EmergencyRecord, error) {
	if limit < 1 || limit > 32 {
		return nil, fmt.Errorf("emergency replay page limit must be 1..32")
	}
	rows, err := s.db.Query(`SELECT sequence, message FROM emergency_history
		WHERE tenant_id=? AND fleet_id=? AND sequence>? ORDER BY sequence ASC LIMIT ?`, tenantID, fleetID, afterSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("read emergency history: %w", err)
	}
	defer rows.Close()
	page := make([]EmergencyRecord, 0, limit)
	previous := afterSeq
	for rows.Next() {
		var rec EmergencyRecord
		if err := rows.Scan(&rec.Sequence, &rec.Message); err != nil {
			return nil, err
		}
		if err := validateEmergencyChain(rec.Sequence, previous, rec.Message); err != nil {
			return nil, err
		}
		page = append(page, rec)
		previous = rec.Sequence
	}
	return page, rows.Err()
}

func parseUint32(s string) (uint32, error) {
	var v uint32
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}

func (s *SQLitePolicyStore) SavePolicy(tenantID, fleetID uint64, version uint32, policyBin []byte, signature []byte, profile string) error {
	sigHex := hex.EncodeToString(signature)
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := s.db.Exec(`
		INSERT INTO policies (tenant_id, fleet_id, version, profile, policy_bin, signature, created_at, distributed)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)
	`, tenantID, fleetID, version, profile, policyBin, sigHex, now)
	if err != nil {
		return fmt.Errorf("save policy version %d for tenant=%d fleet=%d: %w", version, tenantID, fleetID, err)
	}
	return nil
}

func (s *SQLitePolicyStore) GetLatestPolicy(tenantID, fleetID uint64) (*PolicyRecord, error) {
	row := s.db.QueryRow(`
		SELECT tenant_id, fleet_id, version, profile, policy_bin, signature, created_at, distributed
		FROM policies
		WHERE tenant_id = ? AND fleet_id = ?
		ORDER BY version DESC
		LIMIT 1
	`, tenantID, fleetID)

	rec, err := scanPolicyRow(row)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *SQLitePolicyStore) GetPolicy(tenantID, fleetID uint64, version uint32) (*PolicyRecord, error) {
	row := s.db.QueryRow(`
		SELECT tenant_id, fleet_id, version, profile, policy_bin, signature, created_at, distributed
		FROM policies
		WHERE tenant_id = ? AND fleet_id = ? AND version = ?
	`, tenantID, fleetID, version)

	rec, err := scanPolicyRow(row)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *SQLitePolicyStore) ListVersions(tenantID, fleetID uint64) ([]PolicyRecord, error) {
	rows, err := s.db.Query(`
		SELECT tenant_id, fleet_id, version, profile, '', '', created_at, distributed
		FROM policies
		WHERE tenant_id = ? AND fleet_id = ?
		ORDER BY version DESC LIMIT 1000
	`, tenantID, fleetID)
	if err != nil {
		return nil, fmt.Errorf("list policy versions: %w", err)
	}
	defer rows.Close()

	var records []PolicyRecord
	for rows.Next() {
		rec, err := scanPolicyRows(rows)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			records = append(records, *rec)
		}
	}
	return records, rows.Err()
}

func (s *SQLitePolicyStore) MarkDistributed(tenantID, fleetID uint64, version uint32) error {
	res, err := s.db.Exec(`
		UPDATE policies SET distributed = 1
		WHERE tenant_id = ? AND fleet_id = ? AND version = ?
	`, tenantID, fleetID, version)
	if err != nil {
		return fmt.Errorf("mark distributed: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("policy version %d not found for tenant=%d fleet=%d", version, tenantID, fleetID)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SQLitePolicyStore) Close() error {
	return s.db.Close()
}

// policyScanner is an interface satisfied by both *sql.Row and *sql.Rows.
type policyScanner interface {
	Scan(dest ...any) error
}

func scanPolicyFromScanner(sc policyScanner) (*PolicyRecord, error) {
	var (
		rec       PolicyRecord
		sigHex    string
		createdAt string
		distInt   int
	)

	err := sc.Scan(
		&rec.TenantID, &rec.FleetID, &rec.Version, &rec.Profile,
		&rec.PolicyBin, &sigHex, &createdAt, &distInt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan policy: %w", err)
	}

	rec.Distributed = distInt != 0

	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		rec.CreatedAt = t
	}
	if sigHex != "" {
		if sigBytes, err := hex.DecodeString(sigHex); err == nil {
			rec.Signature = sigBytes
		}
	}

	return &rec, nil
}

func scanPolicyRow(row *sql.Row) (*PolicyRecord, error) {
	return scanPolicyFromScanner(row)
}

func scanPolicyRows(rows *sql.Rows) (*PolicyRecord, error) {
	return scanPolicyFromScanner(rows)
}
