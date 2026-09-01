// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

const (
	findingStateActive   = "active"
	findingStateResolved = "resolved"
)

var _ scanner.ScanLifecyclePersistence = (*Store)(nil)

// migrateFindingLifecycleState adds a compact mutable projection beside the
// scan_findings transition ledger. Runtime findings remain append-only forensic
// occurrences. Successful static scans persist only meaningful transitions in
// scan_findings and upsert every observation into finding_states, so an
// unchanged rescan does not grow one detail row per finding. No historical rows
// are backfilled: the first complete post-upgrade scan establishes an honest
// current baseline instead of guessing resolution state from incomplete legacy
// history.
func migrateFindingLifecycleState(ex dbExecer) error {
	scanFindingsPresent, err := tableExists(ex, "scan_findings")
	if err != nil {
		return fmt.Errorf("inspect scan finding occurrence table: %w", err)
	}
	if scanFindingsPresent {
		present, columnErr := hasColumnDB(ex, "scan_findings", "finding_fingerprint")
		if columnErr != nil {
			return fmt.Errorf("inspect scan finding lifecycle identity: %w", columnErr)
		}
		if !present {
			if _, alterErr := ex.Exec(`ALTER TABLE scan_findings ADD COLUMN finding_fingerprint TEXT
				CHECK (finding_fingerprint IS NULL OR length(finding_fingerprint) = 64)`); alterErr != nil {
				return fmt.Errorf("add scan finding lifecycle identity: %w", alterErr)
			}
		}
		hasTimestamp, timestampErr := hasColumnDB(ex, "scan_findings", "timestamp")
		hasID, idErr := hasColumnDB(ex, "scan_findings", "id")
		if timestampErr != nil {
			return fmt.Errorf("inspect scan finding lifecycle timestamp: %w", timestampErr)
		}
		if idErr != nil {
			return fmt.Errorf("inspect scan finding lifecycle occurrence ID: %w", idErr)
		}
		if hasTimestamp && hasID {
			if _, indexErr := ex.Exec(`CREATE INDEX IF NOT EXISTS idx_scan_findings_finding_fingerprint
				ON scan_findings(finding_fingerprint, timestamp DESC, id DESC)`); indexErr != nil {
				return fmt.Errorf("index scan finding lifecycle identity: %w", indexErr)
			}
		}
	}
	_, err = ex.Exec(`
		CREATE TABLE IF NOT EXISTS finding_scopes (
			scope_scanner TEXT NOT NULL,
			target_type TEXT NOT NULL,
			normalized_target TEXT NOT NULL,
			target TEXT NOT NULL,
			last_completed_at DATETIME NOT NULL,
			last_completed_unix_nano INTEGER NOT NULL,
			last_scan_id TEXT NOT NULL,
			PRIMARY KEY (scope_scanner, target_type, normalized_target)
		);
		CREATE TABLE IF NOT EXISTS finding_states (
			fingerprint TEXT PRIMARY KEY CHECK (length(fingerprint) = 64),
			scope_scanner TEXT NOT NULL,
			finding_scanner TEXT NOT NULL,
			target TEXT NOT NULL,
			normalized_target TEXT NOT NULL,
			target_type TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			file_path TEXT NOT NULL,
			normalized_file_path TEXT NOT NULL,
			line_number INTEGER NOT NULL DEFAULT 0 CHECK (line_number >= 0),
			content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
			severity TEXT NOT NULL,
			title TEXT NOT NULL DEFAULT '',
			description TEXT,
			evidence_summary TEXT,
			location TEXT,
			remediation TEXT,
			tags TEXT NOT NULL DEFAULT '[]',
			first_seen DATETIME NOT NULL,
			first_seen_unix_nano INTEGER NOT NULL,
			last_seen DATETIME NOT NULL,
			last_seen_unix_nano INTEGER NOT NULL,
			resolved_at DATETIME,
			resolved_at_unix_nano INTEGER,
			occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count > 0),
			state TEXT NOT NULL CHECK (state IN ('active','resolved')),
			first_scan_id TEXT NOT NULL,
			last_scan_id TEXT NOT NULL,
			last_occurrence_id TEXT NOT NULL,
			CHECK (
				(state = 'active' AND resolved_at IS NULL AND resolved_at_unix_nano IS NULL) OR
				(state = 'resolved' AND resolved_at IS NOT NULL AND resolved_at_unix_nano IS NOT NULL)
			)
		);
		CREATE INDEX IF NOT EXISTS idx_finding_states_scope_state
			ON finding_states(scope_scanner, target_type, normalized_target, state);
		CREATE INDEX IF NOT EXISTS idx_finding_states_last_seen
			ON finding_states(last_seen_unix_nano DESC, fingerprint);
		CREATE INDEX IF NOT EXISTS idx_finding_states_first_seen
			ON finding_states(first_seen_unix_nano DESC, fingerprint);
		CREATE INDEX IF NOT EXISTS idx_finding_states_resolved_at
			ON finding_states(resolved_at_unix_nano DESC, fingerprint);
		CREATE INDEX IF NOT EXISTS idx_finding_states_rule_state
			ON finding_states(rule_id, state);
	`)
	if err != nil {
		return fmt.Errorf("create finding lifecycle state: %w", err)
	}
	return nil
}

// FindingStateRow is the default distinct-finding reporting projection.
// Runtime occurrences and meaningful static transitions remain available
// through ListScanFindings.
type FindingStateRow struct {
	Fingerprint        string     `json:"fingerprint"`
	ScopeScanner       string     `json:"scope_scanner"`
	Scanner            string     `json:"scanner"`
	Target             string     `json:"target"`
	NormalizedTarget   string     `json:"normalized_target"`
	TargetType         string     `json:"target_type"`
	RuleID             string     `json:"rule_id"`
	FilePath           string     `json:"file_path"`
	NormalizedFilePath string     `json:"normalized_file_path"`
	LineNumber         int        `json:"line_number,omitempty"`
	ContentDigest      string     `json:"content_digest"`
	Severity           string     `json:"severity"`
	Title              string     `json:"title"`
	Description        string     `json:"description,omitempty"`
	EvidenceSummary    string     `json:"evidence_summary,omitempty"`
	Location           string     `json:"location,omitempty"`
	Remediation        string     `json:"remediation,omitempty"`
	Tags               []string   `json:"tags,omitempty"`
	FirstSeen          time.Time  `json:"first_seen"`
	LastSeen           time.Time  `json:"last_seen"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
	OccurrenceCount    int64      `json:"occurrence_count"`
	State              string     `json:"state"`
	FirstScanID        string     `json:"first_scan_id"`
	LastScanID         string     `json:"last_scan_id"`
	LastOccurrenceID   string     `json:"last_occurrence_id"`
}

// FindingStateQuery selects the distinct lifecycle projection used for
// operator reporting. Active current state is the default. Since selects any
// state observed or resolved at/after the cutoff; NewOnly narrows that to
// fingerprints whose first observation is at/after the cutoff.
type FindingStateQuery struct {
	Scanner         string
	Target          string
	IncludeResolved bool
	Since           *time.Time
	NewOnly         bool
	Limit           int
}

type findingStateQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// QueryFindingStates returns distinct finding state newest-first.
func (s *Store) QueryFindingStates(query FindingStateQuery) ([]FindingStateRow, error) {
	return queryFindingStates(s.db, query)
}

func queryFindingStates(source findingStateQuerier, query FindingStateQuery) ([]FindingStateRow, error) {
	if query.Limit <= 0 {
		query.Limit = 100
	}
	if query.Limit > 10_000 {
		query.Limit = 10_000
	}
	where, args := findingStatePredicates(query)
	args = append(args, query.Limit)
	rows, err := source.Query(`
		SELECT fingerprint, scope_scanner, finding_scanner, target, normalized_target,
		       target_type, rule_id, file_path, normalized_file_path, line_number,
		       content_digest, severity, title, description, evidence_summary, location,
		       remediation, tags, first_seen_unix_nano, last_seen_unix_nano,
		       resolved_at_unix_nano, occurrence_count, state, first_scan_id,
		       last_scan_id, last_occurrence_id
		FROM finding_states WHERE `+strings.Join(where, " AND ")+`
		ORDER BY MAX(last_seen_unix_nano, COALESCE(resolved_at_unix_nano, 0)) DESC,
		         fingerprint ASC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list finding states: %w", err)
	}
	defer rows.Close()

	result := make([]FindingStateRow, 0)
	for rows.Next() {
		var row FindingStateRow
		var description, evidence, location, remediation sql.NullString
		var tagsJSON string
		var firstSeen, lastSeen int64
		var resolvedAt sql.NullInt64
		if err := rows.Scan(
			&row.Fingerprint, &row.ScopeScanner, &row.Scanner, &row.Target,
			&row.NormalizedTarget, &row.TargetType, &row.RuleID, &row.FilePath,
			&row.NormalizedFilePath, &row.LineNumber, &row.ContentDigest, &row.Severity,
			&row.Title, &description, &evidence, &location, &remediation, &tagsJSON,
			&firstSeen, &lastSeen, &resolvedAt, &row.OccurrenceCount, &row.State,
			&row.FirstScanID, &row.LastScanID, &row.LastOccurrenceID,
		); err != nil {
			return nil, fmt.Errorf("audit: scan finding state: %w", err)
		}
		row.Description = description.String
		row.EvidenceSummary = evidence.String
		row.Location = location.String
		row.Remediation = remediation.String
		if err := json.Unmarshal([]byte(tagsJSON), &row.Tags); err != nil {
			return nil, fmt.Errorf("audit: decode finding state tags: %w", err)
		}
		row.FirstSeen = time.Unix(0, firstSeen).UTC()
		row.LastSeen = time.Unix(0, lastSeen).UTC()
		if resolvedAt.Valid {
			value := time.Unix(0, resolvedAt.Int64).UTC()
			row.ResolvedAt = &value
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// CountFindingStates returns the complete distinct count for the same filters
// as QueryFindingStates. Limit is intentionally ignored so reports can expose
// an honest headline count alongside a bounded result page.
func (s *Store) CountFindingStates(query FindingStateQuery) (int64, error) {
	return countFindingStates(s.db, query)
}

func countFindingStates(source findingStateQuerier, query FindingStateQuery) (int64, error) {
	where, args := findingStatePredicates(query)
	var count int64
	if err := source.QueryRow(`SELECT COUNT(*) FROM finding_states WHERE `+
		strings.Join(where, " AND "), args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("audit: count finding states: %w", err)
	}
	return count, nil
}

// QueryFindingStatesWithCount returns a bounded page and its complete count
// from one SQLite read snapshot, so a concurrent scanner cannot make the
// headline count disagree with the returned lifecycle rows.
func (s *Store) QueryFindingStatesWithCount(
	ctx context.Context,
	query FindingStateQuery,
) ([]FindingStateRow, int64, error) {
	if ctx == nil {
		return nil, 0, fmt.Errorf("audit: finding state query context is required")
	}
	release, err := s.acquireReady()
	if err != nil {
		return nil, 0, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("audit: begin finding state read snapshot: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	rows, err := queryFindingStates(tx, query)
	if err != nil {
		return nil, 0, err
	}
	count, err := countFindingStates(tx, query)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, fmt.Errorf("audit: commit finding state read snapshot: %w", err)
	}
	return rows, count, nil
}

func findingStatePredicates(query FindingStateQuery) ([]string, []any) {
	where := []string{"1=1"}
	args := make([]any, 0, 6)
	if scannerName := strings.ToLower(strings.TrimSpace(query.Scanner)); scannerName != "" {
		where = append(where, "scope_scanner = ?")
		args = append(args, scannerName)
	}
	if target := scanner.NormalizeFindingStateTarget(query.Target); target != "" {
		where = append(where, "normalized_target = ?")
		args = append(args, target)
	}
	if !query.IncludeResolved {
		where = append(where, "state = 'active'")
	}
	if query.Since != nil {
		cutoff := query.Since.UTC().UnixNano()
		if query.NewOnly {
			where = append(where, "first_seen_unix_nano >= ?")
			args = append(args, cutoff)
		} else {
			// A finding can disappear after its last observation. Include that
			// resolution transition in a since report even when last_seen is older.
			where = append(where, "(last_seen_unix_nano >= ? OR COALESCE(resolved_at_unix_nano, 0) >= ?)")
			args = append(args, cutoff, cutoff)
		}
	}
	return where, args
}

// ListFindingStates preserves the compact call site used by existing APIs and
// tests. New reporting surfaces should use QueryFindingStates.
func (s *Store) ListFindingStates(scannerName, target string, includeResolved bool, limit int) ([]FindingStateRow, error) {
	return s.QueryFindingStates(FindingStateQuery{
		Scanner: scannerName, Target: target, IncludeResolved: includeResolved, Limit: limit,
	})
}

// PersistScanLifecycle atomically commits the scan summary and either a compact
// static lifecycle transition or every runtime/failed forensic occurrence.
// Successful classic asset scans always upsert current state; an unchanged
// repeat therefore updates last_seen/occurrence_count without adding another
// scan_findings row.
func (s *Store) PersistScanLifecycle(
	summary scanner.ScanSummaryParams,
	findings []scanner.Finding,
	meta scanner.ScanFindingMeta,
) (scanner.FindingLifecycleDelta, error) {
	delta := scanner.FindingLifecycleDelta{}
	s.findingLifecycleMu.Lock()
	defer s.findingLifecycleMu.Unlock()
	if summary.Timestamp.IsZero() {
		summary.Timestamp = meta.Timestamp
		if summary.Timestamp.IsZero() {
			summary.Timestamp = time.Now().UTC()
		}
	}
	meta.Timestamp = summary.Timestamp
	tx, err := s.db.Begin()
	if err != nil {
		return delta, fmt.Errorf("audit: begin scan lifecycle: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if err := insertScanSummary(tx, summary); err != nil {
		return delta, err
	}
	if findingLifecycleEligible(summary) {
		delta, err = applyFindingLifecycle(tx, summary, findings, meta)
		if err != nil {
			return scanner.FindingLifecycleDelta{}, err
		}
		if err := insertFindingLifecycleTransitions(tx, summary, findings, meta, delta); err != nil {
			return scanner.FindingLifecycleDelta{}, err
		}
	} else if err := insertScanFindings(tx, summary.ScanID, summary.Target, findings, meta); err != nil {
		return delta, err
	}
	if err := tx.Commit(); err != nil {
		return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: commit scan lifecycle: %w", err)
	}
	if delta.Managed {
		scopeKey := findingLifecycleScopeKey(summary.Scanner, summary.TargetType, summary.Target)
		if s.findingGaugeInitialized == nil {
			s.findingGaugeInitialized = make(map[string]struct{})
		}
		if _, initialized := s.findingGaugeInitialized[scopeKey]; !initialized {
			// Up/down counters reset with the metric runtime. The first complete
			// scan of each durable scope therefore publishes its current absolute
			// contribution; subsequent scans publish only lifecycle deltas.
			delta.GaugeDelta = make(map[scanner.Severity]int64, len(delta.CurrentBySeverity))
			for severity, count := range delta.CurrentBySeverity {
				if count != 0 {
					delta.GaugeDelta[severity] = count
				}
			}
			s.findingGaugeInitialized[scopeKey] = struct{}{}
		}
	}
	return delta, nil
}

// insertFindingLifecycleTransitions keeps scan_findings useful as a forensic
// transition ledger without repeating the same static finding on every scan.
// New, reopened, and materially updated findings are emitted by the canonical
// log/metric path and retain a matching occurrence row. Repeated observations
// are represented solely by the finding_states upsert.
func insertFindingLifecycleTransitions(
	tx *sql.Tx,
	summary scanner.ScanSummaryParams,
	findings []scanner.Finding,
	meta scanner.ScanFindingMeta,
	delta scanner.FindingLifecycleDelta,
) error {
	byOccurrence := make(map[string]scanner.FindingLifecycleObservation, len(delta.Observations))
	for _, observation := range delta.Observations {
		if observation.PersistOccurrence {
			byOccurrence[observation.OccurrenceID] = observation
		}
	}
	transitions := make([]scanner.Finding, 0, len(byOccurrence))
	for index := range findings {
		if _, ok := byOccurrence[findings[index].FindingOccurrenceID]; ok {
			transitions = append(transitions, findings[index])
		}
	}
	if err := insertScanFindings(tx, summary.ScanID, summary.Target, transitions, meta); err != nil {
		return err
	}
	for _, finding := range transitions {
		observation := byOccurrence[finding.FindingOccurrenceID]
		result, err := tx.Exec(`UPDATE scan_findings SET finding_fingerprint = ?
			WHERE scan_id = ? AND id = ?`, observation.Fingerprint, summary.ScanID, finding.FindingOccurrenceID)
		if err != nil {
			return fmt.Errorf("audit: link finding transition state: %w", err)
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr != nil || affected != 1 {
			if rowsErr != nil {
				return fmt.Errorf("audit: confirm finding transition state link: %w", rowsErr)
			}
			return fmt.Errorf("audit: finding transition state link matched %d rows", affected)
		}
	}
	return nil
}

func (s *Store) resetFindingGaugeBaselines() {
	if s == nil {
		return
	}
	s.findingLifecycleMu.Lock()
	s.findingGaugeInitialized = nil
	s.findingLifecycleMu.Unlock()
}

func findingLifecycleScopeKey(scannerName, targetType, target string) string {
	if targetType = scanner.NormalizeFindingStateTargetType(targetType); targetType == "" {
		targetType = scanner.NormalizeFindingStateTargetType(scanner.InferTargetType(scannerName))
	}
	parts := []string{
		strings.ToLower(strings.TrimSpace(scannerName)),
		targetType,
		scanner.NormalizeFindingStateTarget(target),
	}
	return strings.Join(parts, "\x00")
}

func findingLifecycleEligible(summary scanner.ScanSummaryParams) bool {
	if summary.ExitCode != 0 || strings.TrimSpace(summary.ScanError) != "" ||
		strings.TrimSpace(summary.EvaluationID) != "" {
		return false
	}
	scannerName := strings.ToLower(strings.TrimSpace(summary.Scanner))
	switch scannerName {
	case "hook-rules", "inline-codeguard", "ai-defense", "asset-policy",
		"tool-call-inspect", "inspect-http", "guardrail-llm", "mid-stream", "rescan":
		return false
	}
	targetType := strings.ToLower(strings.TrimSpace(summary.TargetType))
	switch targetType {
	case "file", "code", "skill", "mcp", "plugin", "aibom", "inventory":
		return true
	case "tool_call", "prompt", "completion", "tool_response", "inspect":
		return false
	}
	if targetType != "" && targetType != "unknown" {
		return false
	}
	switch scannerName {
	case "skill", "skill-scanner", "skill_scanner",
		"mcp", "mcp-scanner", "mcp_scanner",
		"plugin", "plugin-scanner", "plugin_scanner", "defenseclaw-plugin-scanner",
		"aibom", "aibom-claw", "codeguard", "clawshield-vuln",
		"clawshield-secrets", "clawshield-pii", "clawshield-malware", "clawshield-injection":
		return true
	default:
		return false
	}
}

type persistedFindingState struct {
	State             string
	Severity          scanner.Severity
	FirstSeenUnixNano int64
	LastSeenUnixNano  int64
}

func applyFindingLifecycle(
	tx *sql.Tx,
	summary scanner.ScanSummaryParams,
	findings []scanner.Finding,
	meta scanner.ScanFindingMeta,
) (scanner.FindingLifecycleDelta, error) {
	delta := scanner.FindingLifecycleDelta{
		Managed:           true,
		Observations:      make([]scanner.FindingLifecycleObservation, 0, len(findings)),
		GaugeDelta:        make(map[scanner.Severity]int64),
		CurrentBySeverity: make(map[scanner.Severity]int64),
	}
	scopeScanner := strings.ToLower(strings.TrimSpace(summary.Scanner))
	targetType := scanner.NormalizeFindingStateTargetType(summary.TargetType)
	if targetType == "" {
		targetType = scanner.NormalizeFindingStateTargetType(scanner.InferTargetType(summary.Scanner))
	}
	normalizedTarget := scanner.NormalizeFindingStateTarget(summary.Target)
	observedAt := summary.Timestamp.UTC()
	if observedAt.IsZero() {
		observedAt = meta.Timestamp.UTC()
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	observedUnixNano := observedAt.UnixNano()
	observedText := observedAt.Format(time.RFC3339Nano)

	var priorScopeUnixNano int64
	var priorScopeScanID string
	scopeErr := tx.QueryRow(`
		SELECT last_completed_unix_nano, last_scan_id FROM finding_scopes
		WHERE scope_scanner = ? AND target_type = ? AND normalized_target = ?`,
		scopeScanner, targetType, normalizedTarget,
	).Scan(&priorScopeUnixNano, &priorScopeScanID)
	if scopeErr != nil && !errors.Is(scopeErr, sql.ErrNoRows) {
		return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: read finding scope: %w", scopeErr)
	}
	isNewestCompleteScan := errors.Is(scopeErr, sql.ErrNoRows) || observedUnixNano >= priorScopeUnixNano
	seen := make(map[string]struct{}, len(findings))

	for index := range findings {
		finding := findings[index]
		identity := scanner.StableFindingStateIdentity(summary.Scanner, targetType, summary.Target, finding)
		seen[identity.Fingerprint] = struct{}{}
		observation := scanner.FindingLifecycleObservation{
			OccurrenceID: finding.FindingOccurrenceID,
			Fingerprint:  identity.Fingerprint,
			RuleID:       finding.RuleID,
			Severity:     finding.Severity,
			Status:       scanner.FindingLifecycleRepeated,
		}

		prior, found, readErr := readPersistedFindingState(tx, identity.Fingerprint)
		if readErr != nil {
			return scanner.FindingLifecycleDelta{}, readErr
		}
		if !isNewestCompleteScan {
			if found {
				firstSeen := prior.FirstSeenUnixNano
				if observedUnixNano < firstSeen {
					firstSeen = observedUnixNano
				}
				if _, err := tx.Exec(`UPDATE finding_states
					SET occurrence_count = occurrence_count + 1,
					    first_seen = ?, first_seen_unix_nano = ?
					WHERE fingerprint = ?`,
					time.Unix(0, firstSeen).UTC().Format(time.RFC3339Nano), firstSeen,
					identity.Fingerprint,
				); err != nil {
					return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: count stale finding occurrence: %w", err)
				}
			} else if err := insertFindingState(
				tx, summary, targetType, finding, identity, observedText, observedUnixNano,
				findingStateResolved, time.Unix(0, priorScopeUnixNano).UTC(), priorScopeScanID,
			); err != nil {
				return scanner.FindingLifecycleDelta{}, err
			} else {
				// A previously unknown observation from an older completed scan is
				// historical rather than current, but it is still a distinct forensic
				// transition and must retain its matching scan_findings row.
				observation.PersistOccurrence = true
			}
			delta.Observations = append(delta.Observations, observation)
			continue
		}

		switch {
		case !found:
			if err := insertFindingState(
				tx, summary, targetType, finding, identity, observedText, observedUnixNano,
				findingStateActive, time.Time{}, "",
			); err != nil {
				return scanner.FindingLifecycleDelta{}, err
			}
			observation.Status = scanner.FindingLifecycleNew
			observation.PersistOccurrence = true
			delta.GaugeDelta[finding.Severity]++
		case observedUnixNano < prior.LastSeenUnixNano:
			firstSeen := prior.FirstSeenUnixNano
			if observedUnixNano < firstSeen {
				firstSeen = observedUnixNano
			}
			if _, err := tx.Exec(`UPDATE finding_states
				SET occurrence_count = occurrence_count + 1,
				    first_seen = ?, first_seen_unix_nano = ?
				WHERE fingerprint = ?`,
				time.Unix(0, firstSeen).UTC().Format(time.RFC3339Nano), firstSeen,
				identity.Fingerprint,
			); err != nil {
				return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: count out-of-order finding occurrence: %w", err)
			}
		default:
			if prior.State == findingStateResolved {
				observation.Status = scanner.FindingLifecycleReopened
				observation.PersistOccurrence = true
				delta.GaugeDelta[finding.Severity]++
			} else if prior.Severity != finding.Severity {
				observation.Status = scanner.FindingLifecycleUpdated
				observation.PersistOccurrence = true
				delta.GaugeDelta[prior.Severity]--
				delta.GaugeDelta[finding.Severity]++
			}
			if err := updateFindingState(
				tx, summary, finding, identity, observedText, observedUnixNano,
				observation.Status != scanner.FindingLifecycleRepeated,
			); err != nil {
				return scanner.FindingLifecycleDelta{}, err
			}
		}
		delta.Observations = append(delta.Observations, observation)
	}

	if isNewestCompleteScan {
		rows, err := tx.Query(`SELECT fingerprint, rule_id, severity
			FROM finding_states
			WHERE scope_scanner = ? AND target_type = ? AND normalized_target = ?
			  AND state = 'active'`, scopeScanner, targetType, normalizedTarget)
		if err != nil {
			return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: list active finding states: %w", err)
		}
		type activeState struct {
			fingerprint string
			ruleID      string
			severity    scanner.Severity
		}
		active := make([]activeState, 0)
		for rows.Next() {
			var state activeState
			if err := rows.Scan(&state.fingerprint, &state.ruleID, &state.severity); err != nil {
				rows.Close()
				return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: scan active finding state: %w", err)
			}
			active = append(active, state)
		}
		if err := rows.Close(); err != nil {
			return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: close active finding states: %w", err)
		}
		for _, state := range active {
			if _, present := seen[state.fingerprint]; present {
				continue
			}
			if _, err := tx.Exec(`UPDATE finding_states
				SET state = 'resolved', resolved_at = ?, resolved_at_unix_nano = ?,
				    last_scan_id = ? WHERE fingerprint = ? AND state = 'active'`,
				observedText, observedUnixNano, summary.ScanID, state.fingerprint,
			); err != nil {
				return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: resolve finding state: %w", err)
			}
			delta.Resolved = append(delta.Resolved, scanner.FindingLifecycleResolution{
				Fingerprint: state.fingerprint, RuleID: state.ruleID, Severity: state.severity,
			})
			delta.GaugeDelta[state.severity]--
		}

		if _, err := tx.Exec(`INSERT INTO finding_scopes (
			scope_scanner, target_type, normalized_target, target,
			last_completed_at, last_completed_unix_nano, last_scan_id
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scope_scanner, target_type, normalized_target) DO UPDATE SET
			target = excluded.target,
			last_completed_at = excluded.last_completed_at,
			last_completed_unix_nano = excluded.last_completed_unix_nano,
			last_scan_id = excluded.last_scan_id`,
			scopeScanner, targetType, normalizedTarget, summary.Target,
			observedText, observedUnixNano, summary.ScanID,
		); err != nil {
			return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: update finding scope: %w", err)
		}
	}

	countRows, err := tx.Query(`SELECT severity, COUNT(*) FROM finding_states
		WHERE scope_scanner = ? AND target_type = ? AND normalized_target = ?
		  AND state = 'active' GROUP BY severity`, scopeScanner, targetType, normalizedTarget)
	if err != nil {
		return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: count current finding states: %w", err)
	}
	for countRows.Next() {
		var severity scanner.Severity
		var count int64
		if err := countRows.Scan(&severity, &count); err != nil {
			countRows.Close()
			return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: scan current finding count: %w", err)
		}
		delta.CurrentBySeverity[severity] = count
	}
	if err := countRows.Close(); err != nil {
		return scanner.FindingLifecycleDelta{}, fmt.Errorf("audit: close current finding counts: %w", err)
	}
	delta.IndexOccurrenceEmissions()
	return delta, nil
}

func readPersistedFindingState(tx *sql.Tx, fingerprint string) (persistedFindingState, bool, error) {
	var state persistedFindingState
	err := tx.QueryRow(`SELECT state, severity, first_seen_unix_nano, last_seen_unix_nano
		FROM finding_states WHERE fingerprint = ?`, fingerprint).Scan(
		&state.State, &state.Severity, &state.FirstSeenUnixNano, &state.LastSeenUnixNano,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedFindingState{}, false, nil
	}
	if err != nil {
		return persistedFindingState{}, false, fmt.Errorf("audit: read finding state: %w", err)
	}
	return state, true, nil
}

func insertFindingState(
	tx *sql.Tx,
	summary scanner.ScanSummaryParams,
	targetType string,
	finding scanner.Finding,
	identity scanner.FindingStateIdentity,
	observedText string,
	observedUnixNano int64,
	state string,
	resolvedAt time.Time,
	resolvedScanID string,
) error {
	tags, _ := json.Marshal(finding.Tags)
	findingScanner := strings.TrimSpace(finding.Scanner)
	if findingScanner == "" {
		findingScanner = summary.Scanner
	}
	var resolvedText any
	var resolvedUnixNano any
	if state == findingStateResolved {
		resolvedText = resolvedAt.UTC().Format(time.RFC3339Nano)
		resolvedUnixNano = resolvedAt.UnixNano()
	}
	lastScanID := summary.ScanID
	if resolvedScanID != "" {
		lastScanID = resolvedScanID
	}
	_, err := tx.Exec(`INSERT INTO finding_states (
		fingerprint, scope_scanner, finding_scanner, target, normalized_target,
		target_type, rule_id, file_path, normalized_file_path, line_number,
		content_digest, severity, title, description, evidence_summary, location,
		remediation, tags, first_seen, first_seen_unix_nano, last_seen,
		last_seen_unix_nano, resolved_at, resolved_at_unix_nano, occurrence_count,
		state, first_scan_id, last_scan_id, last_occurrence_id
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
		identity.Fingerprint, strings.ToLower(strings.TrimSpace(summary.Scanner)), findingScanner,
		summary.Target, identity.NormalizedTarget, targetType,
		finding.RuleID, identity.FilePath, identity.NormalizedFilePath, identity.LineNumber,
		identity.ContentDigest, string(finding.Severity), finding.Title, nullStr(finding.Description),
		nullStr(finding.EvidenceSummary), nullStr(finding.Location), nullStr(finding.Remediation),
		string(tags), observedText, observedUnixNano, observedText, observedUnixNano,
		resolvedText, resolvedUnixNano, state, summary.ScanID, lastScanID,
		finding.FindingOccurrenceID,
	)
	if err != nil {
		return fmt.Errorf("audit: insert finding state: %w", err)
	}
	return nil
}

func updateFindingState(
	tx *sql.Tx,
	summary scanner.ScanSummaryParams,
	finding scanner.Finding,
	identity scanner.FindingStateIdentity,
	observedText string,
	observedUnixNano int64,
	meaningfulTransition bool,
) error {
	tags, _ := json.Marshal(finding.Tags)
	findingScanner := strings.TrimSpace(finding.Scanner)
	if findingScanner == "" {
		findingScanner = summary.Scanner
	}
	lastOccurrenceID := "last_occurrence_id"
	args := []any{
		findingScanner, summary.Target, finding.RuleID, identity.FilePath,
		identity.NormalizedFilePath, identity.LineNumber, identity.ContentDigest,
		string(finding.Severity), finding.Title, nullStr(finding.Description),
		nullStr(finding.EvidenceSummary), nullStr(finding.Location), nullStr(finding.Remediation),
		string(tags), observedText, observedUnixNano, summary.ScanID,
	}
	if meaningfulTransition {
		lastOccurrenceID = "?"
		args = append(args, finding.FindingOccurrenceID)
	}
	args = append(args, identity.Fingerprint)
	_, err := tx.Exec(`UPDATE finding_states SET
		finding_scanner = ?, target = ?, rule_id = ?, file_path = ?,
		normalized_file_path = ?, line_number = ?, content_digest = ?, severity = ?,
		title = ?, description = ?, evidence_summary = ?, location = ?, remediation = ?,
		tags = ?, last_seen = ?, last_seen_unix_nano = ?, resolved_at = NULL,
		resolved_at_unix_nano = NULL, occurrence_count = occurrence_count + 1,
		state = 'active', last_scan_id = ?, last_occurrence_id = `+lastOccurrenceID+`
		WHERE fingerprint = ?`, args...)
	if err != nil {
		return fmt.Errorf("audit: update finding state: %w", err)
	}
	return nil
}
