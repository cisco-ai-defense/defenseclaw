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
  agent_id, agent_instance_id, sidecar_instance_id, session_id, request_id, trace_id,
  evaluation_id
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
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
		nullStr(p.EvaluationID),
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
		safeDescription := redaction.StringForSink(f.Description, meta.SinkPolicy)
		safeLocation := redaction.StringForSink(f.Location, meta.SinkPolicy)
		safeRemediation := redaction.StringForSink(f.Remediation, meta.SinkPolicy)

		var line interface{}
		if f.LineNumber != nil {
			line = *f.LineNumber
		}

		var dataAxis interface{}
		if len(f.DataAxis) > 0 {
			b, _ := json.Marshal(f.DataAxis)
			dataAxis = string(b)
		}

		var turnID interface{}
		if f.TurnID != nil {
			turnID = *f.TurnID
		}

		var decisionPath interface{}
		if len(f.DecisionPath) > 0 {
			decisionPath = string(f.DecisionPath)
		}

		var confidence interface{}
		if f.Confidence > 0 {
			confidence = f.Confidence
		}

		id := uuid.New().String()
		_, err := s.db.Exec(`
INSERT INTO scan_findings (
  id, scan_id, scanner, target, rule_id, category, severity, title, description, location, line_number,
  remediation, tags, timestamp,
  run_id, request_id, session_id, agent_id, agent_instance_id, sidecar_instance_id,
  schema_version, content_hash, generation, binary_version,
  data_axis, tool_capability_class, content_fingerprint, external_endpoint, turn_id, decision_path,
  confidence, evaluation_id
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
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
			dataAxis,
			nullStr(f.ToolCapabilityClass),
			nullStr(f.ContentFingerprint),
			nullStr(f.ExternalEndpoint),
			turnID,
			decisionPath,
			confidence,
			nullStr(meta.EvaluationID),
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
	// Confidence is the per-finding model/heuristic score (0.0-1.0).
	// Populated for runtime detections (hooks, inspect, proxy
	// guardrail, mid-stream); zero for classic scanner CLIs that
	// don't emit a confidence channel.
	Confidence float64
	// EvaluationID is the join key back to the upstream runtime
	// evaluation (hook handler, /api/v1/inspect/*, proxy guardrail,
	// rescan). Empty for classic scanner-CLI invocations.
	EvaluationID string
}

// ListScanFindings returns persisted findings for a scan_id.
func (s *Store) ListScanFindings(scanID string) ([]ScanFindingRow, error) {
	rows, err := s.db.Query(`
SELECT id, scan_id, scanner, target, rule_id, category, severity, title, description, location, line_number,
       remediation, tags, confidence, evaluation_id
FROM scan_findings WHERE scan_id = ? ORDER BY severity`, scanID)
	if err != nil {
		return nil, fmt.Errorf("audit: list scan findings: %w", err)
	}
	defer rows.Close()

	var out []ScanFindingRow
	for rows.Next() {
		var r ScanFindingRow
		var confidence sql.NullFloat64
		var evaluationID sql.NullString
		if err := rows.Scan(
			&r.ID, &r.ScanID, &r.Scanner, &r.Target, &r.RuleID, &r.Category,
			&r.Severity, &r.Title, &r.Description, &r.Location, &r.LineNumber, &r.Remediation, &r.Tags,
			&confidence, &evaluationID,
		); err != nil {
			return nil, fmt.Errorf("audit: scan finding row: %w", err)
		}
		if confidence.Valid {
			r.Confidence = confidence.Float64
		}
		if evaluationID.Valid {
			r.EvaluationID = evaluationID.String
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CorrelationFindingRow is the projection the sliding-window correlator
// reads — severity + rule_id + category + the enrichment columns that
// drive pattern matching.
type CorrelationFindingRow struct {
	ID                  string
	RuleID              sql.NullString
	Category            sql.NullString
	Severity            string
	DataAxis            sql.NullString
	ToolCapabilityClass sql.NullString
	ContentFingerprint  sql.NullString
	ExternalEndpoint    sql.NullString
	TurnID              sql.NullInt64
	Timestamp           string
}

// ListRecentFindingsInSession returns up to `limit` most-recent findings
// for a given (session_id, agent_instance_id) pair, newest first. The
// correlator calls this on every new finding insert to evaluate its
// pattern library against a sliding event window.
func (s *Store) ListRecentFindingsInSession(sessionID, agentInstanceID string, limit int) ([]CorrelationFindingRow, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`
SELECT id, rule_id, category, severity,
       data_axis, tool_capability_class, content_fingerprint, external_endpoint, turn_id, timestamp
FROM scan_findings
WHERE session_id = ? AND agent_instance_id = ?
ORDER BY timestamp DESC
LIMIT ?`, sessionID, agentInstanceID, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list recent findings in session: %w", err)
	}
	defer rows.Close()

	var out []CorrelationFindingRow
	for rows.Next() {
		var r CorrelationFindingRow
		if err := rows.Scan(
			&r.ID, &r.RuleID, &r.Category, &r.Severity,
			&r.DataAxis, &r.ToolCapabilityClass, &r.ContentFingerprint,
			&r.ExternalEndpoint, &r.TurnID, &r.Timestamp,
		); err != nil {
			return nil, fmt.Errorf("audit: correlation finding row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
