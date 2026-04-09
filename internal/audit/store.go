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

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: set WAL mode: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		action TEXT NOT NULL,
		target TEXT,
		actor TEXT NOT NULL DEFAULT 'defenseclaw',
		details TEXT,
		severity TEXT,
		run_id TEXT
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

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
	CREATE INDEX IF NOT EXISTS idx_scan_scanner ON scan_results(scanner);
	CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_type_name ON actions(target_type, target_name);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("audit: init schema: %w", err)
	}
	if err := s.ensureRunIDColumns(); err != nil {
		return fmt.Errorf("audit: ensure run_id columns: %w", err)
	}

	if err := s.migrateOldLists(); err != nil {
		return fmt.Errorf("audit: migrate old lists: %w", err)
	}

	return nil
}

func (s *Store) migrateOldLists() error {
	var blockCount, allowCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='block_list'`).Scan(&blockCount); err != nil {
		return err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='allow_list'`).Scan(&allowCount); err != nil {
		return err
	}
	if blockCount == 0 && allowCount == 0 {
		return nil
	}

	if blockCount > 0 {
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
			SELECT id, target_type, target_name, NULL, '{"install":"block"}', reason, created_at FROM block_list`); err != nil {
			return fmt.Errorf("migrate block_list: %w", err)
		}
	}
	if allowCount > 0 {
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
			SELECT id, target_type, target_name, NULL, '{"install":"allow"}', reason, created_at FROM allow_list`); err != nil {
			return fmt.Errorf("migrate allow_list: %w", err)
		}
	}
	if _, err := s.db.Exec(`DROP TABLE IF EXISTS block_list`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DROP TABLE IF EXISTS allow_list`); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureRunIDColumns() error {
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_audit_run_id ON audit_events(run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_run_id ON scan_results(run_id)`,
	}
	for _, spec := range []struct {
		table  string
		column string
		stmt   string
	}{
		{
			table:  "audit_events",
			column: "run_id",
			stmt:   `ALTER TABLE audit_events ADD COLUMN run_id TEXT`,
		},
		{
			table:  "scan_results",
			column: "run_id",
			stmt:   `ALTER TABLE scan_results ADD COLUMN run_id TEXT`,
		},
	} {
		exists, err := s.hasColumn(spec.table, spec.column)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := s.db.Exec(spec.stmt); err != nil {
			return fmt.Errorf("alter %s.%s: %w", spec.table, spec.column, err)
		}
	}
	for _, stmt := range indexes {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("create run_id index: %w", err)
		}
	}
	return nil
}

func (s *Store) hasColumn(table, column string) (bool, error) {
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
		`INSERT INTO audit_events (id, timestamp, action, target, actor, details, severity, run_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, ts, e.Action, e.Target, e.Actor, e.Details, e.Severity, nullStr(e.RunID),
	)
	if err != nil {
		return fmt.Errorf("audit: log event: %w", err)
	}
	return nil
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
		`SELECT id, timestamp, action, target, actor, details, severity, run_id
		 FROM audit_events ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var target, details, severity, runID sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &target, &e.Actor, &details, &severity, &runID); err != nil {
			return nil, fmt.Errorf("audit: scan row: %w", err)
		}
		e.Target = target.String
		e.Details = details.String
		e.Severity = severity.String
		e.RunID = runID.String
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
	BlockedSkills int
	AllowedSkills int
	BlockedMCPs   int
	AllowedMCPs   int
	Alerts        int
	TotalScans    int
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
	}
	for _, q := range queries {
		if err := s.db.QueryRow(q.sql).Scan(q.dest); err != nil {
			return c, fmt.Errorf("audit: count query: %w", err)
		}
	}
	return c, nil
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

func (s *Store) Close() error {
	return s.db.Close()
}

func currentRunID() string {
	return strings.TrimSpace(os.Getenv("DEFENSECLAW_RUN_ID"))
}
