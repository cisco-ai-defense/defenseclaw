// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

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

		id := f.FindingOccurrenceID
		if id == "" {
			id = uuid.New().String()
		}
		_, err := s.db.Exec(`
INSERT INTO scan_findings (
  id, scan_id, scanner, target, rule_id, category, severity, title, description, evidence_summary, location, line_number,
  remediation, tags, timestamp,
  run_id, request_id, session_id, agent_id, agent_instance_id, sidecar_instance_id,
  schema_version, content_hash, generation, binary_version,
  data_axis, tool_capability_class, content_fingerprint, external_endpoint, turn_id, decision_path,
  confidence, evaluation_id
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id,
			scanID,
			f.Scanner,
			target,
			nullStr(f.RuleID),
			nullStr(f.Category),
			string(f.Severity),
			f.Title,
			f.Description,
			nullStr(f.EvidenceSummary),
			f.Location,
			line,
			f.Remediation,
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
	ID              string
	ScanID          string
	Scanner         string
	Target          string
	RuleID          sql.NullString
	Category        sql.NullString
	Severity        string
	Title           sql.NullString
	Description     sql.NullString
	EvidenceSummary sql.NullString
	Location        sql.NullString
	LineNumber      sql.NullInt64
	Remediation     sql.NullString
	Tags            sql.NullString
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
SELECT id, scan_id, scanner, target, rule_id, category, severity, title, description, evidence_summary, location, line_number,
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
			&r.Severity, &r.Title, &r.Description, &r.EvidenceSummary, &r.Location, &r.LineNumber, &r.Remediation, &r.Tags,
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
	AgentID             string
	AgentInstanceID     string
	Scanner             string
	RuleID              sql.NullString
	Category            sql.NullString
	Severity            string
	Tags                []string
	DataAxis            sql.NullString
	ToolCapabilityClass sql.NullString
	ContentFingerprint  sql.NullString
	ExternalEndpoint    sql.NullString
	TurnID              sql.NullInt64
	Timestamp           string
}

const correlationCandidateMultiplier = 8

// correlationAgentPartitionSQL returns the exact identity predicate used by
// both the contributor window and durable firing ledger. When an instance is
// present, a known logical agent must match inside it; missing logical identity
// is isolated from known agents. When the instance is absent, only rows that
// also lack an instance may use agent_id as a conservative fallback.
func correlationAgentPartitionSQL(sessionID, agentInstanceID, agentID string) (string, []any, bool) {
	sessionID = strings.TrimSpace(sessionID)
	agentInstanceID = strings.TrimSpace(agentInstanceID)
	agentID = strings.TrimSpace(agentID)
	if sessionID == "" || (agentInstanceID == "" && agentID == "") {
		return "", nil, false
	}
	if agentInstanceID != "" && agentID != "" {
		return `session_id = ? AND agent_instance_id = ? AND agent_id = ?`,
			[]any{sessionID, agentInstanceID, agentID}, true
	}
	if agentInstanceID != "" {
		return `session_id = ? AND agent_instance_id = ? AND TRIM(COALESCE(agent_id, '')) = ''`,
			[]any{sessionID, agentInstanceID}, true
	}
	return `session_id = ? AND TRIM(COALESCE(agent_instance_id, '')) = '' AND agent_id = ?`,
		[]any{sessionID, agentID}, true
}

// ListRecentFindingsInSession returns up to limit most-recent findings for one
// exact session/agent partition, newest first. The correlator calls this on
// every new finding insert to evaluate its pattern library against a sliding
// event window.
func (s *Store) ListRecentFindingsInSession(
	sessionID, agentInstanceID, agentID string,
	limit int,
) ([]CorrelationFindingRow, error) {
	if limit <= 0 {
		limit = 20
	}
	identityWhere, identityArgs, ok := correlationAgentPartitionSQL(sessionID, agentInstanceID, agentID)
	if !ok {
		return nil, nil
	}
	// Read a bounded overscan so duplicate primitives can be collapsed before
	// the declared correlation window is applied. This recovers older distinct
	// signals after ordinary alert replay without turning every new finding into
	// an unbounded full-session query.
	candidateLimit := limit
	if maxInt := int(^uint(0) >> 1); limit <= maxInt/correlationCandidateMultiplier {
		candidateLimit = limit * correlationCandidateMultiplier
	}
	query := fmt.Sprintf(`
WITH eligible AS (
	SELECT id, COALESCE(agent_id, '') AS agent_id,
	       COALESCE(agent_instance_id, '') AS agent_instance_id,
	       scanner, rule_id, category, severity, tags,
	       data_axis, tool_capability_class, content_fingerprint, external_endpoint, turn_id, timestamp
	FROM scan_findings
	WHERE %s
		AND COALESCE(scanner, '') <> ? COLLATE NOCASE
		AND NOT EXISTS (
			SELECT 1
			FROM json_each(
				CASE
					WHEN json_valid(COALESCE(tags, '')) THEN
						CASE WHEN json_type(tags) = 'array' THEN tags ELSE '[]' END
					ELSE '[]'
				END
			) AS finding_tag
			WHERE LOWER(TRIM(CAST(finding_tag.value AS TEXT))) = ?
		)
	ORDER BY timestamp DESC, id DESC
	LIMIT ?
), ranked AS (
	SELECT eligible.*,
	       ROW_NUMBER() OVER (
			PARTITION BY
				CASE WHEN TRIM(COALESCE(content_fingerprint, '')) = '' THEN id ELSE '' END,
				CASE WHEN TRIM(COALESCE(content_fingerprint, '')) = '' THEN '' ELSE LOWER(TRIM(COALESCE(rule_id, ''))) END,
				CASE WHEN TRIM(COALESCE(content_fingerprint, '')) = '' THEN '' ELSE LOWER(TRIM(COALESCE(category, ''))) END,
				CASE WHEN TRIM(COALESCE(content_fingerprint, '')) = '' THEN '' ELSE LOWER(TRIM(content_fingerprint)) END
			ORDER BY timestamp ASC, id ASC
	       ) AS primitive_rank
	FROM eligible
)
SELECT id, agent_id, agent_instance_id, scanner, rule_id, category, severity, tags,
       data_axis, tool_capability_class, content_fingerprint, external_endpoint, turn_id, timestamp
FROM ranked
WHERE primitive_rank = 1
ORDER BY timestamp DESC, id DESC
	LIMIT ?`, identityWhere)
	queryArgs := append([]any(nil), identityArgs...)
	queryArgs = append(queryArgs, "correlator", strings.ToLower(scanner.FindingTagDetectionOnly), candidateLimit, limit)
	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("audit: list recent findings in session: %w", err)
	}
	defer rows.Close()

	var out []CorrelationFindingRow
	for rows.Next() {
		var r CorrelationFindingRow
		var tagsJSON sql.NullString
		if err := rows.Scan(
			&r.ID, &r.AgentID, &r.AgentInstanceID, &r.Scanner, &r.RuleID, &r.Category, &r.Severity, &tagsJSON,
			&r.DataAxis, &r.ToolCapabilityClass, &r.ContentFingerprint,
			&r.ExternalEndpoint, &r.TurnID, &r.Timestamp,
		); err != nil {
			return nil, fmt.Errorf("audit: correlation finding row: %w", err)
		}
		if tagsJSON.Valid {
			if err := json.Unmarshal([]byte(tagsJSON.String), &r.Tags); err != nil {
				return nil, fmt.Errorf("audit: decode correlation finding tags for %s: %w", r.ID, err)
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

const correlationLedgerBatchSize = 100

// ListFiredCorrelationRuleIDsInSession returns the subset of candidate CORR-*
// rule IDs already persisted for a session. Synthetic rows remain excluded
// from contributor windows; this narrow metadata lookup is only the durable
// once-per-session firing ledger used after a process restart.
func (s *Store) ListFiredCorrelationRuleIDsInSession(
	sessionID, agentInstanceID, agentID string,
	candidateRuleIDs []string,
) ([]string, error) {
	if len(candidateRuleIDs) == 0 {
		return nil, nil
	}
	identityWhere, identityArgs, ok := correlationAgentPartitionSQL(sessionID, agentInstanceID, agentID)
	if !ok {
		return nil, nil
	}

	// Normalize and deduplicate the caller's bounded pattern set before
	// constructing parameterized IN queries. Batching stays below SQLite's
	// variable ceiling even for an unusually large operator rule pack.
	wanted := make(map[string]string, len(candidateRuleIDs))
	ordered := make([]string, 0, len(candidateRuleIDs))
	for _, ruleID := range candidateRuleIDs {
		trimmed := strings.TrimSpace(ruleID)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, duplicate := wanted[key]; duplicate {
			continue
		}
		wanted[key] = trimmed
		ordered = append(ordered, key)
	}

	fired := make([]string, 0, len(ordered))
	for start := 0; start < len(ordered); start += correlationLedgerBatchSize {
		end := start + correlationLedgerBatchSize
		if end > len(ordered) {
			end = len(ordered)
		}
		batch := ordered[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",")
		query := fmt.Sprintf(`
SELECT DISTINCT LOWER(TRIM(rule_id))
FROM scan_findings
WHERE %s
	AND LOWER(TRIM(COALESCE(scanner, ''))) = ?
	AND LOWER(TRIM(COALESCE(rule_id, ''))) IN (%s)
ORDER BY LOWER(TRIM(rule_id))`, identityWhere, placeholders)
		args := make([]any, 0, len(identityArgs)+len(batch)+1)
		args = append(args, identityArgs...)
		args = append(args, "correlator")
		for _, ruleID := range batch {
			args = append(args, ruleID)
		}
		rows, err := s.db.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("audit: list fired correlation rules in session: %w", err)
		}
		for rows.Next() {
			var normalizedRuleID string
			if err := rows.Scan(&normalizedRuleID); err != nil {
				rows.Close()
				return nil, fmt.Errorf("audit: fired correlation rule row: %w", err)
			}
			if original, ok := wanted[normalizedRuleID]; ok {
				fired = append(fired, original)
			}
		}
		rowsErr := rows.Err()
		if closeErr := rows.Close(); rowsErr == nil {
			rowsErr = closeErr
		}
		if rowsErr != nil {
			return nil, fmt.Errorf("audit: iterate fired correlation rules in session: %w", rowsErr)
		}
	}
	return fired, nil
}
