// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// Compile-time check: Store implements scanner.ScanPersistence.
var _ scanner.ScanPersistence = (*Store)(nil)

// InsertScanSummary persists a v7 scan_results row (scan_id == id).
func (s *Store) InsertScanSummary(p scanner.ScanSummaryParams) error {
	runID := p.RunID
	if runID == "" {
		runID = currentRunID()
	}
	ts := p.Timestamp.UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`
INSERT INTO scan_results (
  id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json, run_id,
  verdict, exit_code, error,
  schema_version, content_hash, generation, binary_version,
  agent_id, agent_instance_id, sidecar_instance_id, session_id, request_id, trace_id
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.ScanID,
		p.Scanner,
		p.Target,
		ts,
		p.DurationMs,
		p.FindingCount,
		p.MaxSeverity,
		p.RawJSON,
		nullStr(runID),
		nullStr(p.Verdict),
		p.ExitCode,
		nullStr(p.ScanError),
		nullInt(p.SchemaVersion),
		nullStr(p.ContentHash),
		nullUint64(p.Generation),
		nullStr(p.BinaryVersion),
		nullStr(p.AgentID),
		nullStr(p.AgentInstanceID),
		nullStr(p.SidecarInstanceID),
		nullStr(p.SessionID),
		nullStr(p.RequestID),
		nullStr(p.TraceID),
	)
	if err != nil {
		return fmt.Errorf("audit: insert scan summary: %w", err)
	}
	return nil
}

// InsertScanFindings writes one row per finding into scan_findings.
func (s *Store) InsertScanFindings(scanID, target string, findings []scanner.Finding, meta scanner.ScanFindingMeta) error {
	if len(findings) == 0 {
		return nil
	}
	ts := meta.Timestamp.UTC().Format(time.RFC3339Nano)
	if meta.Timestamp.IsZero() {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}

	for i := range findings {
		f := &findings[i]
		tagsJSON, _ := json.Marshal(f.Tags)
		safeDescription := redaction.ForSinkString(f.Description)
		safeLocation := redaction.ForSinkString(f.Location)
		safeRemediation := redaction.ForSinkString(f.Remediation)

		var line interface{}
		if f.LineNumber != nil {
			line = *f.LineNumber
		}

		id := uuid.New().String()
		_, err := s.db.Exec(`
INSERT INTO scan_findings (
  id, scan_id, scanner, target, rule_id, category, severity, title, description, location, line_number,
  remediation, tags, timestamp,
  run_id, request_id, session_id, agent_id, agent_instance_id, sidecar_instance_id,
  schema_version, content_hash, generation, binary_version
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id,
			scanID,
			f.Scanner,
			target,
			nullStr(f.RuleID),
			nullStr(f.Category),
			string(f.Severity),
			f.Title,
			safeDescription,
			safeLocation,
			line,
			safeRemediation,
			string(tagsJSON),
			ts,
			nullStr(meta.RunID),
			nullStr(meta.RequestID),
			nullStr(meta.SessionID),
			nullStr(meta.AgentID),
			nullStr(meta.AgentInstanceID),
			nullStr(meta.SidecarInstanceID),
			nullInt(meta.SchemaVersion),
			nullStr(meta.ContentHash),
			nullUint64(meta.Generation),
			nullStr(meta.BinaryVersion),
		)
		if err != nil {
			return fmt.Errorf("audit: insert scan finding: %w", err)
		}
	}
	return nil
}

// ScanFindingRow is a scan_findings table projection for tests and APIs.
type ScanFindingRow struct {
	ID          string
	ScanID      string
	Scanner     string
	Target      string
	RuleID      sql.NullString
	Category    sql.NullString
	Severity    string
	Title       sql.NullString
	Description sql.NullString
	Location    sql.NullString
	LineNumber  sql.NullInt64
	Remediation sql.NullString
	Tags        sql.NullString
}

// ListScanFindings returns persisted findings for a scan_id.
func (s *Store) ListScanFindings(scanID string) ([]ScanFindingRow, error) {
	rows, err := s.db.Query(`
SELECT id, scan_id, scanner, target, rule_id, category, severity, title, description, location, line_number, remediation, tags
FROM scan_findings WHERE scan_id = ? ORDER BY severity`, scanID)
	if err != nil {
		return nil, fmt.Errorf("audit: list scan findings: %w", err)
	}
	defer rows.Close()

	var out []ScanFindingRow
	for rows.Next() {
		var r ScanFindingRow
		if err := rows.Scan(
			&r.ID, &r.ScanID, &r.Scanner, &r.Target, &r.RuleID, &r.Category,
			&r.Severity, &r.Title, &r.Description, &r.Location, &r.LineNumber, &r.Remediation, &r.Tags,
		); err != nil {
			return nil, fmt.Errorf("audit: scan finding row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
