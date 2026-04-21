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

package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Actor     string    `json:"actor"`
	Details   string    `json:"details"`
	Severity  string    `json:"severity"`
	RunID     string    `json:"run_id,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
}

// ActionState tracks enforcement state across three independent dimensions.
type ActionState struct {
	File    string `json:"file,omitempty"`    // "quarantine" or "" (none)
	Runtime string `json:"runtime,omitempty"` // "disable" or "" (enable)
	Install string `json:"install,omitempty"` // "block", "allow", or "" (none)
}

func (a ActionState) IsEmpty() bool {
	return a.File == "" && a.Runtime == "" && a.Install == ""
}

func (a ActionState) Summary() string {
	var parts []string
	if a.Install == "block" {
		parts = append(parts, "blocked")
	}
	if a.Install == "allow" {
		parts = append(parts, "allowed")
	}
	if a.File == "quarantine" {
		parts = append(parts, "quarantined")
	}
	if a.Runtime == "disable" {
		parts = append(parts, "disabled")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// ActionEntry is the unified record for all enforcement actions on a target.
type ActionEntry struct {
	ID         string      `json:"id"`
	TargetType string      `json:"target_type"`
	TargetName string      `json:"target_name"`
	SourcePath string      `json:"source_path,omitempty"`
	Actions    ActionState `json:"actions"`
	Reason     string      `json:"reason"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

type Store struct {
	db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("audit: open db %s: %w", dbPath, err)
	}

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("audit: %s: %w", pragma, err)
		}
	}

	return &Store{db: db}, nil
}

// ---------------------------------------------------------------------------
// Schema migration framework
// ---------------------------------------------------------------------------

// dbExecer is satisfied by both *sql.DB and *sql.Tx so migrations can run
// inside a transaction.
type dbExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// migration is a single versioned schema change. Migrations are applied
// sequentially from the current schema_version to len(migrations).
type migration struct {
	description string
	apply       func(ex dbExecer) error
}

// migrations is the ordered list of schema changes. Append new entries at the
// end; never reorder or remove existing entries.
var migrations = []migration{
	{
		description: "initial schema: audit_events, scan_results, findings, actions, egress, snapshots",
		apply: func(ex dbExecer) error {
			_, err := ex.Exec(`
			CREATE TABLE IF NOT EXISTS audit_events (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				action TEXT NOT NULL,
				target TEXT,
				actor TEXT NOT NULL DEFAULT 'defenseclaw',
				details TEXT,
				severity TEXT,
				run_id TEXT,
				trace_id TEXT
			);
			CREATE TABLE IF NOT EXISTS scan_results (
				id TEXT PRIMARY KEY,
				scanner TEXT NOT NULL,
				target TEXT NOT NULL,
				timestamp DATETIME NOT NULL,
				duration_ms INTEGER,
				finding_count INTEGER,
				max_severity TEXT,
				raw_json TEXT,
				run_id TEXT
			);
			CREATE TABLE IF NOT EXISTS findings (
				id TEXT PRIMARY KEY,
				scan_id TEXT NOT NULL,
				severity TEXT NOT NULL,
				title TEXT NOT NULL,
				description TEXT,
				location TEXT,
				remediation TEXT,
				scanner TEXT NOT NULL,
				tags TEXT,
				FOREIGN KEY (scan_id) REFERENCES scan_results(id)
			);
			CREATE TABLE IF NOT EXISTS actions (
				id TEXT PRIMARY KEY,
				target_type TEXT NOT NULL,
				target_name TEXT NOT NULL,
				source_path TEXT,
				actions_json TEXT NOT NULL DEFAULT '{}',
				reason TEXT,
				updated_at DATETIME NOT NULL
			);
			CREATE TABLE IF NOT EXISTS network_egress_events (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				session_id TEXT,
				hostname TEXT NOT NULL,
				url TEXT,
				http_method TEXT,
				protocol TEXT,
				policy_outcome TEXT NOT NULL,
				decision_code TEXT,
				blocked INTEGER NOT NULL DEFAULT 0,
				severity TEXT NOT NULL DEFAULT 'INFO',
				details TEXT
			);
			CREATE TABLE IF NOT EXISTS target_snapshots (
				id TEXT PRIMARY KEY,
				target_type TEXT NOT NULL,
				target_path TEXT NOT NULL,
				content_hash TEXT NOT NULL,
				dependency_hashes TEXT,
				config_hashes TEXT,
				network_endpoints TEXT,
				scan_id TEXT,
				captured_at DATETIME NOT NULL,
				UNIQUE(target_type, target_path)
			);
			CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
			CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
			CREATE INDEX IF NOT EXISTS idx_scan_scanner ON scan_results(scanner);
			CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity);
			CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id);
			CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_type_name ON actions(target_type, target_name);
			CREATE INDEX IF NOT EXISTS idx_egress_timestamp ON network_egress_events(timestamp);
			CREATE INDEX IF NOT EXISTS idx_egress_hostname ON network_egress_events(hostname);
			CREATE INDEX IF NOT EXISTS idx_egress_blocked ON network_egress_events(blocked);
			CREATE INDEX IF NOT EXISTS idx_egress_session ON network_egress_events(session_id);
			CREATE INDEX IF NOT EXISTS idx_snapshots_target ON target_snapshots(target_type, target_path);
			`)
			return err
		},
	},
	{
		description: "add run_id columns and indexes; migrate old block/allow lists",
		apply: func(ex dbExecer) error {
			for _, spec := range []struct {
				table, column, stmt string
			}{
				{"audit_events", "run_id", `ALTER TABLE audit_events ADD COLUMN run_id TEXT`},
				{"scan_results", "run_id", `ALTER TABLE scan_results ADD COLUMN run_id TEXT`},
			} {
				exists, err := hasColumnDB(ex, spec.table, spec.column)
				if err != nil {
					return err
				}
				if !exists {
					if _, err := ex.Exec(spec.stmt); err != nil {
						return fmt.Errorf("alter %s.%s: %w", spec.table, spec.column, err)
					}
				}
			}
			for _, idx := range []string{
				`CREATE INDEX IF NOT EXISTS idx_audit_run_id ON audit_events(run_id)`,
				`CREATE INDEX IF NOT EXISTS idx_scan_run_id ON scan_results(run_id)`,
			} {
				if _, err := ex.Exec(idx); err != nil {
					return fmt.Errorf("create run_id index: %w", err)
				}
			}
			var blockCount, allowCount int
			_ = ex.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='block_list'`).Scan(&blockCount)
			_ = ex.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='allow_list'`).Scan(&allowCount)
			if blockCount > 0 {
				if _, err := ex.Exec(`INSERT OR REPLACE INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
					SELECT id, target_type, target_name, NULL, '{"install":"block"}', reason, created_at FROM block_list`); err != nil {
					return fmt.Errorf("migrate block_list: %w", err)
				}
			}
			if allowCount > 0 {
				if _, err := ex.Exec(`INSERT OR REPLACE INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
					SELECT id, target_type, target_name, NULL, '{"install":"allow"}', reason, created_at FROM allow_list`); err != nil {
					return fmt.Errorf("migrate allow_list: %w", err)
				}
			}
			_, _ = ex.Exec(`DROP TABLE IF EXISTS block_list`)
			_, _ = ex.Exec(`DROP TABLE IF EXISTS allow_list`)
			return nil
		},
	},
	{
		// Phase 2.3 of the observability refactor: when
		// guardrail.retain_judge_bodies is on, the sidecar mirrors
		// every LLM-judge response body to this table so operators
		// can later reconstruct why the judge returned a given
		// verdict (parse failures, model drift, prompt regressions).
		//
		// The table is separate from audit_events because (a)
		// bodies can be kilobytes, (b) it makes per-sink retention
		// policies trivial (drop the whole table without touching
		// verdict history), and (c) schema drift is cheaper when
		// bodies and verdicts live on different migration tracks.
		description: "add judge_responses table for retained LLM-judge bodies",
		apply: func(ex dbExecer) error {
			_, err := ex.Exec(`
			CREATE TABLE IF NOT EXISTS judge_responses (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				kind TEXT NOT NULL,
				direction TEXT,
				model TEXT,
				action TEXT,
				severity TEXT,
				latency_ms INTEGER,
				parse_error TEXT,
				raw_response TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_judge_timestamp ON judge_responses(timestamp);
			CREATE INDEX IF NOT EXISTS idx_judge_kind ON judge_responses(kind);
			CREATE INDEX IF NOT EXISTS idx_judge_severity ON judge_responses(severity);
			`)
			return err
		},
	},
	{
		description: "add trace_id column to audit_events",
		apply: func(ex dbExecer) error {
			exists, err := hasColumnDB(ex, "audit_events", "trace_id")
			if err != nil {
				return err
			}
			if exists {
				return nil
			}
			if _, err := ex.Exec(`ALTER TABLE audit_events ADD COLUMN trace_id TEXT`); err != nil {
				return fmt.Errorf("alter audit_events.trace_id: %w", err)
			}
			return nil
		},
	},
}

func (s *Store) Init() error {
	// Ensure the schema_version tracking table exists.
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL
	)`); err != nil {
		return fmt.Errorf("audit: create schema_version table: %w", err)
	}

	current := 0
	row := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`)
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("audit: read schema version: %w", err)
	}

	for i := current; i < len(migrations); i++ {
		m := migrations[i]
		ver := i + 1
		fmt.Fprintf(os.Stderr, "[audit] applying migration %d: %s\n", ver, m.description)
		if err := s.applyMigration(ver, m); err != nil {
			return err
		}
	}

	return nil
}

// applyMigration runs a single migration inside a transaction so that both the
// DDL and the schema_version bump are atomic. On failure the transaction is
// rolled back and the version remains unchanged, making retries safe.
func (s *Store) applyMigration(ver int, m migration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("audit: begin migration %d: %w", ver, err)
	}
	defer tx.Rollback() //nolint:errcheck

	if err := m.apply(tx); err != nil {
		return fmt.Errorf("audit: migration %d (%s): %w", ver, m.description, err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`,
		ver, time.Now().UTC()); err != nil {
		return fmt.Errorf("audit: record migration %d: %w", ver, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit migration %d: %w", ver, err)
	}
	return nil
}

// SchemaVersion returns the current schema version number.
func (s *Store) SchemaVersion() (int, error) {
	var v int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v)
	return v, err
}

// hasColumnDB checks if a table has a specific column. Accepts dbExecer so it
// works inside transactions too.
func hasColumnDB(ex dbExecer, table, column string) (bool, error) {
	if !knownTables[table] {
		return false, fmt.Errorf("audit: hasColumn called with unknown table %q", table)
	}
	rows, err := ex.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("audit: pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name       string
			colType    string
			notNull    int
			defaultV   sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// knownTables is the set of tables hasColumn is allowed to inspect.
var knownTables = map[string]bool{
	"audit_events":          true,
	"scan_results":          true,
	"actions":               true,
	"target_snapshots":      true,
	"network_egress_events": true,
	"judge_responses":       true,
	"schema_version":        true,
}

func (s *Store) hasColumn(table, column string) (bool, error) {
	if !knownTables[table] {
		return false, fmt.Errorf("audit: hasColumn called with unknown table %q", table)
	}
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("audit: pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			colType    string
			notNull    int
			defaultV   sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &primaryKey); err != nil {
			return false, fmt.Errorf("audit: scan pragma table_info(%s): %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// --- Audit Events ---

func (s *Store) LogEvent(e Event) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Actor == "" {
		e.Actor = "defenseclaw"
	}
	if e.RunID == "" {
		e.RunID = currentRunID()
	}

	ts := e.Timestamp.Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`INSERT INTO audit_events (id, timestamp, action, target, actor, details, severity, run_id, trace_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, ts, e.Action, e.Target, e.Actor, e.Details, e.Severity, nullStr(e.RunID), nullStr(e.TraceID),
	)
	if err != nil {
		return fmt.Errorf("audit: log event: %w", err)
	}
	return nil
}

// JudgeResponse is the persisted shape of a single LLM-judge call
// (prompt-injection or PII detector). Rows are only written when
// guardrail.retain_judge_bodies is true — without that flag the sink
// pipeline receives a redacted placeholder and SQLite stores
// nothing, which is the safer default for PII.
type JudgeResponse struct {
	ID         string
	Timestamp  time.Time
	Kind       string
	Direction  string
	Model      string
	Action     string
	Severity   string
	LatencyMs  int64
	ParseError string
	Raw        string
}

// MaxJudgeRawBytes is the upper bound on the raw_response body
// stored in SQLite. Judge models occasionally echo entire
// conversation histories (we've seen >1MB); without a cap, a
// runaway response can bloat the audit DB by gigabytes and
// degrade query performance. 64KiB keeps every realistic
// detection trace intact while preventing pathological blowup.
const MaxJudgeRawBytes = 64 * 1024

// InsertJudgeResponse persists a single judge body. The caller is
// expected to supply a non-empty Raw; an empty body is treated as a
// no-op so the "retain off" path does not waste a row per request.
//
// Large raw_response payloads are truncated to MaxJudgeRawBytes with
// a terminal "…[truncated N bytes]" marker preserved so operators
// can see exactly how much was clipped. Truncation is UTF-8 safe —
// we rewind to the last codepoint boundary before appending the
// marker so downstream JSON decoders don't trip on partial runes.
func (s *Store) InsertJudgeResponse(e JudgeResponse) error {
	if e.Raw == "" {
		return nil
	}
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	raw := truncateJudgeRaw(e.Raw, MaxJudgeRawBytes)
	_, err := s.db.Exec(
		`INSERT INTO judge_responses
			(id, timestamp, kind, direction, model, action, severity, latency_ms, parse_error, raw_response)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID,
		e.Timestamp.Format(time.RFC3339Nano),
		e.Kind,
		nullStr(e.Direction),
		nullStr(e.Model),
		nullStr(e.Action),
		nullStr(e.Severity),
		e.LatencyMs,
		nullStr(e.ParseError),
		raw,
	)
	if err != nil {
		return fmt.Errorf("audit: insert judge response: %w", err)
	}
	return nil
}

// truncateJudgeRaw clips raw at maxBytes codepoint-safely and
// appends a marker so operators can see how much was dropped.
// Exported via test-internal access; kept lowercase to discourage
// callers outside the audit store.
func truncateJudgeRaw(raw string, maxBytes int) string {
	if maxBytes <= 0 || len(raw) <= maxBytes {
		return raw
	}
	// Walk back to the start of the last complete UTF-8 rune so
	// we do not slice inside a multi-byte codepoint.
	cut := maxBytes
	for cut > 0 && raw[cut]&0xC0 == 0x80 {
		cut--
	}
	dropped := len(raw) - cut
	return raw[:cut] + fmt.Sprintf("…[truncated %d bytes]", dropped)
}

// ListJudgeResponses returns the most recent N persisted judge bodies,
// newest first. Intended for operator review via the CLI / TUI once
// retention is turned on during an incident.
func (s *Store) ListJudgeResponses(limit int) ([]JudgeResponse, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`
		SELECT id, timestamp, kind, COALESCE(direction,''), COALESCE(model,''),
			COALESCE(action,''), COALESCE(severity,''), COALESCE(latency_ms,0),
			COALESCE(parse_error,''), raw_response
		FROM judge_responses ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list judge responses: %w", err)
	}
	defer rows.Close()

	out := make([]JudgeResponse, 0, limit)
	for rows.Next() {
		var r JudgeResponse
		var ts string
		if err := rows.Scan(&r.ID, &ts, &r.Kind, &r.Direction, &r.Model,
			&r.Action, &r.Severity, &r.LatencyMs, &r.ParseError, &r.Raw); err != nil {
			return nil, fmt.Errorf("audit: scan judge response: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			r.Timestamp = t
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate judge responses: %w", err)
	}
	return out, nil
}

func (s *Store) InsertScanResult(id, scannerName, target string, ts time.Time, durationMs int64, findingCount int, maxSeverity, rawJSON string) error {
	runID := currentRunID()
	_, err := s.db.Exec(
		`INSERT INTO scan_results (id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json, run_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, scannerName, target, ts, durationMs, findingCount, maxSeverity, rawJSON, nullStr(runID),
	)
	if err != nil {
		return fmt.Errorf("audit: insert scan result: %w", err)
	}
	return nil
}

func (s *Store) InsertFinding(id, scanID, severity, title, description, location, remediation, scannerName, tags string) error {
	_, err := s.db.Exec(
		`INSERT INTO findings (id, scan_id, severity, title, description, location, remediation, scanner, tags)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, scanID, severity, title, description, location, remediation, scannerName, tags,
	)
	if err != nil {
		return fmt.Errorf("audit: insert finding: %w", err)
	}
	return nil
}

func (s *Store) ListEvents(limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.Query(
		`SELECT id, timestamp, action, target, actor, details, severity, run_id, trace_id
		 FROM audit_events ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var target, details, severity, runID, traceID sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &target, &e.Actor, &details, &severity, &runID, &traceID); err != nil {
			return nil, fmt.Errorf("audit: scan row: %w", err)
		}
		e.Target = target.String
		e.Details = details.String
		e.Severity = severity.String
		e.RunID = runID.String
		e.TraceID = traceID.String
		events = append(events, e)
	}
	return events, rows.Err()
}

// --- Actions ---

// SetAction upserts the full action state for a target.
func (s *Store) SetAction(targetType, targetName, sourcePath string, state ActionState, reason string) error {
	actionsJSON, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("audit: marshal actions: %w", err)
	}
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err = s.db.Exec(
		`INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(target_type, target_name) DO UPDATE SET
		   actions_json = excluded.actions_json,
		   reason = excluded.reason,
		   updated_at = excluded.updated_at,
		   source_path = COALESCE(excluded.source_path, source_path)`,
		id, targetType, targetName, nullStr(sourcePath), string(actionsJSON), reason, now,
	)
	if err != nil {
		return fmt.Errorf("audit: set action: %w", err)
	}
	return nil
}

// SetActionField updates a single action dimension without touching others.
func (s *Store) SetActionField(targetType, targetName, field, value, reason string) error {
	if err := validateActionFieldAndValue(field, value); err != nil {
		return err
	}
	id := uuid.New().String()
	now := time.Now().UTC()
	path := "$." + field
	initJSON := "{}"
	switch field {
	case "install":
		initJSON = fmt.Sprintf(`{"install":"%s"}`, value)
	case "file":
		initJSON = fmt.Sprintf(`{"file":"%s"}`, value)
	case "runtime":
		initJSON = fmt.Sprintf(`{"runtime":"%s"}`, value)
	}
	query :=
		`INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
		 VALUES (?, ?, ?, NULL, ?, ?, ?)
		 ON CONFLICT(target_type, target_name) DO UPDATE SET
		   actions_json = json_set(actions_json, ?, ?),
		   reason = excluded.reason,
		   updated_at = excluded.updated_at`
	_, err := s.db.Exec(query, id, targetType, targetName, initJSON, reason, now, path, value)
	if err != nil {
		return fmt.Errorf("audit: set action field %s: %w", field, err)
	}
	return nil
}

// SetSourcePath updates just the source_path for an existing action row.
func (s *Store) SetSourcePath(targetType, targetName, path string) error {
	_, err := s.db.Exec(
		`UPDATE actions SET source_path = ? WHERE target_type = ? AND target_name = ?`,
		path, targetType, targetName,
	)
	if err != nil {
		return fmt.Errorf("audit: set source path: %w", err)
	}
	return nil
}

// ClearActionField removes a single dimension from the actions JSON.
// Deletes the row if all dimensions are empty afterward.
func (s *Store) ClearActionField(targetType, targetName, field string) error {
	if err := validateActionFieldAndValue(field, ""); err != nil {
		return err
	}
	path := "$." + field
	_, err := s.db.Exec(
		`UPDATE actions SET actions_json = json_remove(actions_json, ?), updated_at = ?
		 WHERE target_type = ? AND target_name = ?`,
		path, time.Now().UTC(), targetType, targetName,
	)
	if err != nil {
		return fmt.Errorf("audit: clear action field %s: %w", field, err)
	}
	// Clean up rows with no active actions
	_, _ = s.db.Exec(
		`DELETE FROM actions WHERE target_type = ? AND target_name = ? AND actions_json IN ('{}', 'null', '')`,
		targetType, targetName,
	)
	return nil
}

// RemoveAction deletes the entire action row for a target.
func (s *Store) RemoveAction(targetType, targetName string) error {
	_, err := s.db.Exec(
		`DELETE FROM actions WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	)
	if err != nil {
		return fmt.Errorf("audit: remove action: %w", err)
	}
	return nil
}

// GetAction returns the full action entry for a target, or nil if none exists.
func (s *Store) GetAction(targetType, targetName string) (*ActionEntry, error) {
	var e ActionEntry
	var sourcePath, reason, actionsJSON sql.NullString
	err := s.db.QueryRow(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
		 FROM actions WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	).Scan(&e.ID, &e.TargetType, &e.TargetName, &sourcePath, &actionsJSON, &reason, &e.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: get action: %w", err)
	}
	e.SourcePath = sourcePath.String
	e.Reason = reason.String
	if actionsJSON.String != "" {
		_ = json.Unmarshal([]byte(actionsJSON.String), &e.Actions)
	}
	return &e, nil
}

// HasAction checks if a target has a specific field set to a specific value.
func (s *Store) HasAction(targetType, targetName, field, value string) (bool, error) {
	if err := validateActionFieldAndValue(field, value); err != nil {
		return false, err
	}
	var count int
	query := fmt.Sprintf(
		`SELECT COUNT(*) FROM actions WHERE target_type = ? AND target_name = ? AND json_extract(actions_json, '$.%s') = ?`,
		field)
	err := s.db.QueryRow(query, targetType, targetName, value).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("audit: has action: %w", err)
	}
	return count > 0, nil
}

// ListByAction returns all entries where a given field has a given value.
func (s *Store) ListByAction(field, value string) ([]ActionEntry, error) {
	if err := validateActionFieldAndValue(field, value); err != nil {
		return nil, err
	}
	query := fmt.Sprintf(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
		 FROM actions WHERE json_extract(actions_json, '$.%s') = ?
		 ORDER BY updated_at DESC`, field)
	return s.queryActions(query, value)
}

// ListByActionAndType filters by both action field/value and target_type.
func (s *Store) ListByActionAndType(field, value, targetType string) ([]ActionEntry, error) {
	if err := validateActionFieldAndValue(field, value); err != nil {
		return nil, err
	}
	query := fmt.Sprintf(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
		 FROM actions WHERE json_extract(actions_json, '$.%s') = ? AND target_type = ?
		 ORDER BY updated_at DESC`, field)
	return s.queryActions(query, value, targetType)
}

// ListActionsByType returns all action entries for a given target type.
func (s *Store) ListActionsByType(targetType string) ([]ActionEntry, error) {
	return s.queryActions(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
		 FROM actions WHERE target_type = ? ORDER BY updated_at DESC`, targetType)
}

// ListAllActions returns every action entry.
func (s *Store) ListAllActions() ([]ActionEntry, error) {
	return s.queryActions(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at
		 FROM actions ORDER BY updated_at DESC`)
}

func (s *Store) queryActions(query string, args ...any) ([]ActionEntry, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query actions: %w", err)
	}
	defer rows.Close()

	var entries []ActionEntry
	for rows.Next() {
		var e ActionEntry
		var sourcePath, reason, actionsJSON sql.NullString
		if err := rows.Scan(&e.ID, &e.TargetType, &e.TargetName, &sourcePath, &actionsJSON, &reason, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan action row: %w", err)
		}
		e.SourcePath = sourcePath.String
		e.Reason = reason.String
		if actionsJSON.String != "" {
			_ = json.Unmarshal([]byte(actionsJSON.String), &e.Actions)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func validateActionFieldAndValue(field, value string) error {
	switch field {
	case "install":
		switch value {
		case "", "block", "allow", "none":
			return nil
		default:
			return fmt.Errorf("audit: invalid install action value %q", value)
		}
	case "file":
		switch value {
		case "", "quarantine", "none":
			return nil
		default:
			return fmt.Errorf("audit: invalid file action value %q", value)
		}
	case "runtime":
		switch value {
		case "", "disable", "enable":
			return nil
		default:
			return fmt.Errorf("audit: invalid runtime action value %q", value)
		}
	default:
		return fmt.Errorf("audit: invalid action field %q", field)
	}
}

// --- TUI Queries ---

type ScanResultRow struct {
	ID           string    `json:"id"`
	Scanner      string    `json:"scanner"`
	Target       string    `json:"target"`
	Timestamp    time.Time `json:"timestamp"`
	DurationMs   int64     `json:"duration_ms"`
	FindingCount int       `json:"finding_count"`
	MaxSeverity  string    `json:"max_severity"`
}

type FindingRow struct {
	ID          string `json:"id"`
	ScanID      string `json:"scan_id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Remediation string `json:"remediation"`
	Scanner     string `json:"scanner"`
}

func (s *Store) ListAlerts(limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, timestamp, action, target, actor, details, severity, run_id
		 FROM audit_events
		 WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW','ERROR','INFO')
		   AND action NOT LIKE 'dismiss%'
		 ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list alerts: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var target, details, severity, runID sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &target, &e.Actor, &details, &severity, &runID); err != nil {
			return nil, fmt.Errorf("audit: scan alert row: %w", err)
		}
		e.Target = target.String
		e.Details = details.String
		e.Severity = severity.String
		e.RunID = runID.String
		events = append(events, e)
	}
	return events, rows.Err()
}

// AcknowledgeAlerts clears alerts by downgrading their severity to ACK.
// Returns the number of alerts acknowledged.
func (s *Store) AcknowledgeAlerts(severityFilter string) (int64, error) {
	var res sql.Result
	var err error
	if severityFilter == "" || severityFilter == "all" {
		res, err = s.db.Exec(
			`UPDATE audit_events SET severity = 'ACK'
			 WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW')`)
	} else {
		res, err = s.db.Exec(
			`UPDATE audit_events SET severity = 'ACK'
			 WHERE severity = ?`, severityFilter)
	}
	if err != nil {
		return 0, fmt.Errorf("audit: acknowledge alerts: %w", err)
	}
	n, _ := res.RowsAffected()

	_ = s.LogEvent(Event{
		Action:   "acknowledge-alerts",
		Target:   severityFilter,
		Details:  fmt.Sprintf("acknowledged %d alerts", n),
		Severity: "ACK",
	})

	return n, nil
}

// AcknowledgeByIDs clears specific alerts by their event IDs.
func (s *Store) AcknowledgeByIDs(ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	query := fmt.Sprintf(
		`UPDATE audit_events SET severity = 'ACK' WHERE id IN (%s) AND severity IN ('CRITICAL','HIGH','MEDIUM','LOW')`,
		strings.Join(placeholders, ","))
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("audit: acknowledge by IDs: %w", err)
	}
	n, _ := res.RowsAffected()

	_ = s.LogEvent(Event{
		Action:   "acknowledge-alerts",
		Details:  fmt.Sprintf("acknowledged %d selected alerts", n),
		Severity: "ACK",
	})

	return n, nil
}

// ListEventsByTarget returns recent audit events for a given target path.
func (s *Store) ListEventsByTarget(target string, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT id, timestamp, action, target, actor, details, severity, run_id
		 FROM audit_events
		 WHERE target = ?
		 ORDER BY timestamp DESC LIMIT ?`, target, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list events by target: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var tgt, details, severity, runID sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &tgt, &e.Actor, &details, &severity, &runID); err != nil {
			return nil, fmt.Errorf("audit: scan event row: %w", err)
		}
		e.Target = tgt.String
		e.Details = details.String
		e.Severity = severity.String
		e.RunID = runID.String
		events = append(events, e)
	}
	return events, rows.Err()
}

// ListFindingsByRunID returns findings from the scan whose ID matches the run_id.
func (s *Store) ListFindingsByRunID(runID string) ([]FindingRow, error) {
	if runID == "" {
		return nil, nil
	}
	return s.ListFindingsByScan(runID)
}

func (s *Store) ListScanResults(limit int) ([]ScanResultRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, scanner, target, timestamp, duration_ms, finding_count, max_severity
		 FROM scan_results ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list scan results: %w", err)
	}
	defer rows.Close()

	var results []ScanResultRow
	for rows.Next() {
		var r ScanResultRow
		var maxSev sql.NullString
		if err := rows.Scan(&r.ID, &r.Scanner, &r.Target, &r.Timestamp, &r.DurationMs, &r.FindingCount, &maxSev); err != nil {
			return nil, fmt.Errorf("audit: scan result row: %w", err)
		}
		r.MaxSeverity = maxSev.String
		results = append(results, r)
	}
	return results, rows.Err()
}

func (s *Store) ListFindingsByScan(scanID string) ([]FindingRow, error) {
	rows, err := s.db.Query(
		`SELECT id, scan_id, severity, title, description, location, remediation, scanner
		 FROM findings WHERE scan_id = ? ORDER BY severity DESC`, scanID,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list findings: %w", err)
	}
	defer rows.Close()

	var findings []FindingRow
	for rows.Next() {
		var f FindingRow
		var desc, loc, rem sql.NullString
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Severity, &f.Title, &desc, &loc, &rem, &f.Scanner); err != nil {
			return nil, fmt.Errorf("audit: scan finding row: %w", err)
		}
		f.Description = desc.String
		f.Location = loc.String
		f.Remediation = rem.String
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

type Counts struct {
	BlockedSkills      int
	AllowedSkills      int
	BlockedMCPs        int
	AllowedMCPs        int
	Alerts             int
	TotalScans         int
	BlockedEgressCalls int // total outbound network calls blocked by policy
}

func (s *Store) GetCounts() (Counts, error) {
	var c Counts
	queries := []struct {
		sql  string
		dest *int
	}{
		{`SELECT COUNT(*) FROM actions WHERE target_type = 'skill' AND json_extract(actions_json, '$.install') = 'block'`, &c.BlockedSkills},
		{`SELECT COUNT(*) FROM actions WHERE target_type = 'skill' AND json_extract(actions_json, '$.install') = 'allow'`, &c.AllowedSkills},
		{`SELECT COUNT(*) FROM actions WHERE target_type = 'mcp' AND json_extract(actions_json, '$.install') = 'block'`, &c.BlockedMCPs},
		{`SELECT COUNT(*) FROM actions WHERE target_type = 'mcp' AND json_extract(actions_json, '$.install') = 'allow'`, &c.AllowedMCPs},
		{`SELECT COUNT(*) FROM audit_events WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW')`, &c.Alerts},
		{`SELECT COUNT(*) FROM scan_results`, &c.TotalScans},
		{`SELECT COUNT(*) FROM network_egress_events WHERE blocked = 1`, &c.BlockedEgressCalls},
	}
	for _, q := range queries {
		if err := s.db.QueryRow(q.sql).Scan(q.dest); err != nil {
			return c, fmt.Errorf("audit: count query: %w", err)
		}
	}
	return c, nil
}

// NetworkEgressFilter parameterises QueryNetworkEgressEvents.
// Zero values mean "no filter". Limit defaults to 100 when zero.
type NetworkEgressFilter struct {
	Hostname  string    // exact match; empty = all hosts
	SessionID string    // exact match; empty = all sessions
	Since     time.Time // only events at or after this time; zero = all time
	Blocked   *bool     // nil = all; &true = blocked only; &false = allowed only
	Limit     int       // defaults to 100
}

// QueryNetworkEgressEvents returns egress events matching the filter, newest first.
func (s *Store) QueryNetworkEgressEvents(f NetworkEgressFilter) ([]NetworkEgressRow, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, timestamp, session_id, hostname, url, http_method, protocol,
	                 policy_outcome, decision_code, blocked, severity, details
	          FROM network_egress_events WHERE 1=1`
	var args []any

	if f.Hostname != "" {
		query += " AND hostname = ?"
		args = append(args, f.Hostname)
	}
	if f.SessionID != "" {
		query += " AND session_id = ?"
		args = append(args, f.SessionID)
	}
	if !f.Since.IsZero() {
		query += " AND julianday(timestamp) >= julianday(?)"
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if f.Blocked != nil {
		blocked := 0
		if *f.Blocked {
			blocked = 1
		}
		query += " AND blocked = ?"
		args = append(args, blocked)
	}
	query += " ORDER BY julianday(timestamp) DESC, timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query network egress events: %w", err)
	}
	defer rows.Close()

	var events []NetworkEgressRow
	for rows.Next() {
		var e NetworkEgressRow
		var sessionID, url, httpMethod, protocol, decisionCode, details sql.NullString
		var blocked int
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &sessionID, &e.Hostname, &url, &httpMethod, &protocol,
			&e.PolicyOutcome, &decisionCode, &blocked, &e.Severity, &details,
		); err != nil {
			return nil, fmt.Errorf("audit: scan egress row: %w", err)
		}
		e.SessionID = sessionID.String
		e.URL = url.String
		e.HTTPMethod = httpMethod.String
		e.Protocol = protocol.String
		e.DecisionCode = decisionCode.String
		e.Details = details.String
		e.Blocked = blocked != 0
		events = append(events, e)
	}
	return events, rows.Err()
}

type LatestScanInfo struct {
	ID           string
	Target       string
	Timestamp    time.Time
	FindingCount int
	MaxSeverity  string
	RawJSON      string
}

func (s *Store) LatestScansByScanner(scannerName string) ([]LatestScanInfo, error) {
	rows, err := s.db.Query(`
		SELECT sr.id, sr.target, sr.timestamp, sr.finding_count, sr.max_severity, sr.raw_json
		FROM scan_results sr
		INNER JOIN (
			SELECT target, MAX(timestamp) as max_ts
			FROM scan_results
			WHERE scanner = ?
			GROUP BY target
		) latest ON sr.target = latest.target AND sr.timestamp = latest.max_ts
		WHERE sr.scanner = ?
	`, scannerName, scannerName)
	if err != nil {
		return nil, fmt.Errorf("audit: latest scans by scanner: %w", err)
	}
	defer rows.Close()

	var results []LatestScanInfo
	for rows.Next() {
		var r LatestScanInfo
		var maxSev, rawJSON sql.NullString
		if err := rows.Scan(&r.ID, &r.Target, &r.Timestamp, &r.FindingCount, &maxSev, &rawJSON); err != nil {
			return nil, fmt.Errorf("audit: scan latest row: %w", err)
		}
		r.MaxSeverity = maxSev.String
		r.RawJSON = rawJSON.String
		results = append(results, r)
	}
	return results, rows.Err()
}

// --- Network Egress Events ---

// NetworkEgressRow is the persisted shape of a network_egress_events row.
type NetworkEgressRow struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	SessionID     string    `json:"session_id,omitempty"`
	Hostname      string    `json:"hostname"`
	URL           string    `json:"url,omitempty"`
	HTTPMethod    string    `json:"http_method,omitempty"`
	Protocol      string    `json:"protocol,omitempty"`
	PolicyOutcome string    `json:"policy_outcome"`
	DecisionCode  string    `json:"decision_code,omitempty"`
	Blocked       bool      `json:"blocked"`
	Severity      string    `json:"severity"`
	Details       string    `json:"details,omitempty"`
}

// InsertNetworkEgressEvent persists one outbound network call as a structured row.
func (s *Store) InsertNetworkEgressEvent(e NetworkEgressRow) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = "INFO"
	}
	ts := e.Timestamp.Format(time.RFC3339Nano)
	blocked := 0
	if e.Blocked {
		blocked = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO network_egress_events
		 (id, timestamp, session_id, hostname, url, http_method, protocol, policy_outcome, decision_code, blocked, severity, details)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, ts,
		nullStr(e.SessionID), e.Hostname, nullStr(e.URL), nullStr(e.HTTPMethod), nullStr(e.Protocol),
		e.PolicyOutcome, nullStr(e.DecisionCode), blocked, e.Severity, nullStr(e.Details),
	)
	if err != nil {
		return fmt.Errorf("audit: insert network egress event: %w", err)
	}
	return nil
}

// GetScanRawJSON returns the raw JSON blob for a scan result by ID.
func (s *Store) GetScanRawJSON(scanID string) (string, error) {
	var raw string
	err := s.db.QueryRow("SELECT raw_json FROM scan_results WHERE id = ?", scanID).Scan(&raw)
	if err != nil {
		return "", fmt.Errorf("audit: get scan raw json: %w", err)
	}
	return raw, nil
}

// SnapshotRow represents a stored target snapshot for drift detection.
type SnapshotRow struct {
	ID               string    `json:"id"`
	TargetType       string    `json:"target_type"`
	TargetPath       string    `json:"target_path"`
	ContentHash      string    `json:"content_hash"`
	DependencyHashes string    `json:"dependency_hashes"`
	ConfigHashes     string    `json:"config_hashes"`
	NetworkEndpoints string    `json:"network_endpoints"`
	ScanID           string    `json:"scan_id"`
	CapturedAt       time.Time `json:"captured_at"`
}

// SetTargetSnapshot upserts a snapshot baseline for drift comparison.
func (s *Store) SetTargetSnapshot(targetType, targetPath, contentHash, depHashes, cfgHashes, endpoints, scanID string) error {
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err := s.db.Exec(
		`INSERT INTO target_snapshots (id, target_type, target_path, content_hash, dependency_hashes, config_hashes, network_endpoints, scan_id, captured_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(target_type, target_path) DO UPDATE SET
		 	content_hash = excluded.content_hash,
		 	dependency_hashes = excluded.dependency_hashes,
		 	config_hashes = excluded.config_hashes,
		 	network_endpoints = excluded.network_endpoints,
		 	scan_id = excluded.scan_id,
		 	captured_at = excluded.captured_at`,
		id, targetType, targetPath, contentHash, depHashes, cfgHashes, endpoints, scanID, now,
	)
	if err != nil {
		return fmt.Errorf("audit: set target snapshot: %w", err)
	}
	return nil
}

// ListNetworkEgressEvents returns recent egress events. Optionally filter by
// hostname prefix (empty string returns all). Results are newest-first.
func (s *Store) ListNetworkEgressEvents(limit int, hostname string) ([]NetworkEgressRow, error) {
	if limit <= 0 {
		limit = 100
	}

	var (
		rows *sql.Rows
		err  error
	)
	if hostname == "" {
		rows, err = s.db.Query(
			`SELECT id, timestamp, session_id, hostname, url, http_method, protocol,
			        policy_outcome, decision_code, blocked, severity, details
			 FROM network_egress_events
			 ORDER BY julianday(timestamp) DESC, timestamp DESC LIMIT ?`, limit,
		)
	} else {
		rows, err = s.db.Query(
			`SELECT id, timestamp, session_id, hostname, url, http_method, protocol,
			        policy_outcome, decision_code, blocked, severity, details
			 FROM network_egress_events WHERE hostname = ?
			 ORDER BY julianday(timestamp) DESC, timestamp DESC LIMIT ?`, hostname, limit,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("audit: list network egress events: %w", err)
	}
	defer rows.Close()

	var events []NetworkEgressRow
	for rows.Next() {
		var e NetworkEgressRow
		var sessionID, url, httpMethod, protocol, decisionCode, details sql.NullString
		var blocked int
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &sessionID, &e.Hostname, &url, &httpMethod, &protocol,
			&e.PolicyOutcome, &decisionCode, &blocked, &e.Severity, &details,
		); err != nil {
			return nil, fmt.Errorf("audit: scan egress row: %w", err)
		}
		e.SessionID = sessionID.String
		e.URL = url.String
		e.HTTPMethod = httpMethod.String
		e.Protocol = protocol.String
		e.DecisionCode = decisionCode.String
		e.Details = details.String
		e.Blocked = blocked != 0
		events = append(events, e)
	}
	return events, rows.Err()
}

// CountBlockedEgress returns the total number of blocked egress events.
func (s *Store) CountBlockedEgress() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM network_egress_events WHERE blocked = 1`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("audit: count blocked egress: %w", err)
	}
	return count, nil
}

// GetTargetSnapshot loads the stored baseline snapshot for a target.
func (s *Store) GetTargetSnapshot(targetType, targetPath string) (*SnapshotRow, error) {
	row := s.db.QueryRow(
		`SELECT id, target_type, target_path, content_hash, dependency_hashes, config_hashes, network_endpoints, scan_id, captured_at
		 FROM target_snapshots WHERE target_type = ? AND target_path = ?`,
		targetType, targetPath,
	)
	var r SnapshotRow
	var ts string
	err := row.Scan(&r.ID, &r.TargetType, &r.TargetPath, &r.ContentHash, &r.DependencyHashes, &r.ConfigHashes, &r.NetworkEndpoints, &r.ScanID, &ts)
	if err != nil {
		return nil, fmt.Errorf("audit: get target snapshot: %w", err)
	}
	r.CapturedAt, _ = time.Parse(time.RFC3339Nano, ts)
	if r.CapturedAt.IsZero() {
		r.CapturedAt, _ = time.Parse("2006-01-02 15:04:05", ts)
	}
	return &r, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func currentRunID() string {
	return strings.TrimSpace(os.Getenv("DEFENSECLAW_RUN_ID"))
}
