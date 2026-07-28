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
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const judgeBodyCutoverBatchSize = 1000

type judgeBodyCutoverPhase string

const (
	judgeBodyPhaseTargetCommitted     judgeBodyCutoverPhase = "target_committed"
	judgeBodyPhaseMarkersCommitted    judgeBodyCutoverPhase = "markers_committed"
	judgeBodyPhaseCompletionCommitted judgeBodyCutoverPhase = "completion_committed"
	judgeBodyPhaseSourceCommitted     judgeBodyCutoverPhase = "source_committed"
)

type judgeBodyCutoverHooks struct {
	afterPhase func(judgeBodyCutoverPhase) error
}

func (hooks judgeBodyCutoverHooks) run(phase judgeBodyCutoverPhase) error {
	if hooks.afterPhase == nil {
		return nil
	}
	return hooks.afterPhase(phase)
}

const legacyJudgeNoInsertTriggerName = "defenseclaw_judge_responses_no_insert"
const legacyJudgeNoUpdateTriggerName = "defenseclaw_judge_responses_no_update"

const legacyJudgeNoInsertTriggerSQL = `CREATE TRIGGER defenseclaw_judge_responses_no_insert
BEFORE INSERT ON judge_responses
BEGIN
	SELECT RAISE(ABORT, 'judge_responses is read-only after v8 cutover');
END`

const legacyJudgeNoUpdateTriggerSQL = `CREATE TRIGGER defenseclaw_judge_responses_no_update
BEFORE UPDATE ON judge_responses
BEGIN
	SELECT RAISE(ABORT, 'judge_responses is read-only after v8 cutover');
END`

const judgeBodyColumnNames = `
	id, timestamp, timestamp_unix_nano, kind, direction, model, action, severity,
	latency_ms, parse_error, raw_response, request_id, trace_id, run_id,
	session_id, input_hash, confidence, fail_closed_applied, inspected_model,
	prompt_template_id, schema_version, content_hash, generation, binary_version,
	agent_id, agent_instance_id, sidecar_instance_id, policy_id, destination_app,
	tool_name, tool_id`

const judgeBodySelectColumns = `
	id, CAST(timestamp AS TEXT), timestamp_unix_nano, kind, direction, model, action, severity,
	latency_ms, parse_error, raw_response, request_id, trace_id, run_id,
	session_id, input_hash, confidence, fail_closed_applied, inspected_model,
	prompt_template_id, schema_version, content_hash, generation, binary_version,
	agent_id, agent_instance_id, sidecar_instance_id, policy_id, destination_app,
	tool_name, tool_id`

// legacyJudgeBodyRow deliberately preserves nullable columns and the timestamp's
// stored text. Cutover inserts these exact values rather than round-tripping
// through JudgeResponse defaults/truncation, preserving historical body bytes and
// provenance exactly.
type legacyJudgeBodyRow struct {
	id                string
	timestamp         string
	timestampUnixNano int64
	kind              string
	direction         sql.NullString
	model             sql.NullString
	action            sql.NullString
	severity          sql.NullString
	latencyMS         sql.NullInt64
	parseError        sql.NullString
	rawResponse       string
	requestID         sql.NullString
	traceID           sql.NullString
	runID             sql.NullString
	sessionID         sql.NullString
	inputHash         sql.NullString
	confidence        sql.NullFloat64
	failClosedApplied int64
	inspectedModel    sql.NullString
	promptTemplateID  sql.NullString
	schemaVersion     sql.NullInt64
	contentHash       sql.NullString
	generation        sql.NullInt64
	binaryVersion     sql.NullString
	agentID           sql.NullString
	agentInstanceID   sql.NullString
	sidecarInstanceID sql.NullString
	policyID          sql.NullString
	destinationApp    sql.NullString
	toolName          sql.NullString
	toolID            sql.NullString
}

type judgeBodyRowScanner interface {
	Scan(dest ...any) error
}

// HasLegacyJudgeBodies reports whether audit.db contains compatibility rows that
// require the authoritative database to be opened even when new capture is off.
func HasLegacyJudgeBodies(ctx context.Context, legacy *Store) (bool, error) {
	if legacy == nil || legacy.db == nil {
		return false, errors.New("judge_body: legacy audit store is required")
	}
	var exists int
	if err := legacy.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM judge_responses LIMIT 1)`).Scan(&exists); err != nil {
		return false, fmt.Errorf("judge_body: inspect legacy cutover work: %w", err)
	}
	return exists != 0, nil
}

func scanLegacyJudgeBody(scan judgeBodyRowScanner) (legacyJudgeBodyRow, error) {
	var row legacyJudgeBodyRow
	err := scan.Scan(
		&row.id, &row.timestamp, &row.timestampUnixNano, &row.kind, &row.direction, &row.model,
		&row.action, &row.severity, &row.latencyMS, &row.parseError,
		&row.rawResponse, &row.requestID, &row.traceID, &row.runID,
		&row.sessionID, &row.inputHash, &row.confidence,
		&row.failClosedApplied, &row.inspectedModel, &row.promptTemplateID,
		&row.schemaVersion, &row.contentHash, &row.generation,
		&row.binaryVersion, &row.agentID, &row.agentInstanceID,
		&row.sidecarInstanceID, &row.policyID, &row.destinationApp,
		&row.toolName, &row.toolID,
	)
	return row, err
}

func (r legacyJudgeBodyRow) insertArgs() []any {
	return []any{
		r.id, r.timestamp, r.timestampUnixNano, r.kind, r.direction, r.model, r.action, r.severity,
		r.latencyMS, r.parseError, r.rawResponse, r.requestID, r.traceID,
		r.runID, r.sessionID, r.inputHash, r.confidence,
		r.failClosedApplied, r.inspectedModel, r.promptTemplateID,
		r.schemaVersion, r.contentHash, r.generation, r.binaryVersion,
		r.agentID, r.agentInstanceID, r.sidecarInstanceID, r.policyID,
		r.destinationApp, r.toolName, r.toolID,
	}
}

func (r legacyJudgeBodyRow) equal(other legacyJudgeBodyRow) bool {
	return r.id == other.id && r.timestamp == other.timestamp &&
		r.timestampUnixNano == other.timestampUnixNano &&
		r.kind == other.kind && r.direction == other.direction &&
		r.model == other.model && r.action == other.action &&
		r.severity == other.severity && r.latencyMS == other.latencyMS &&
		r.parseError == other.parseError && r.rawResponse == other.rawResponse &&
		r.requestID == other.requestID && r.traceID == other.traceID &&
		r.runID == other.runID && r.sessionID == other.sessionID &&
		r.inputHash == other.inputHash && r.confidence == other.confidence &&
		r.failClosedApplied == other.failClosedApplied &&
		r.inspectedModel == other.inspectedModel &&
		r.promptTemplateID == other.promptTemplateID &&
		r.schemaVersion == other.schemaVersion &&
		r.contentHash == other.contentHash && r.generation == other.generation &&
		r.binaryVersion == other.binaryVersion && r.agentID == other.agentID &&
		r.agentInstanceID == other.agentInstanceID &&
		r.sidecarInstanceID == other.sidecarInstanceID &&
		r.policyID == other.policyID && r.destinationApp == other.destinationApp &&
		r.toolName == other.toolName && r.toolID == other.toolID
}

// CutoverLegacyJudgeBodies performs the v8 writer cutover. It holds an IMMEDIATE
// transaction on audit.db for the entire operation, so no pre-cutover writer can
// race the deterministic copy. Each target batch is committed, read back and
// byte-for-byte verified before its stable IDs are marked. The source INSERT and
// UPDATE triggers and completion record commit before the lock is released; only
// then is the authoritative runtime writer enabled.
func (s *JudgeBodyStore) CutoverLegacyJudgeBodies(ctx context.Context, legacy *Store) error {
	return s.cutoverLegacyJudgeBodiesWithHooks(
		ctx, legacy, judgeBodyCutoverBatchSize, judgeBodyCutoverHooks{},
	)
}

func (s *JudgeBodyStore) cutoverLegacyJudgeBodies(ctx context.Context, legacy *Store, batchSize int) (retErr error) {
	return s.cutoverLegacyJudgeBodiesWithHooks(ctx, legacy, batchSize, judgeBodyCutoverHooks{})
}

func (s *JudgeBodyStore) cutoverLegacyJudgeBodiesWithHooks(
	ctx context.Context,
	legacy *Store,
	batchSize int,
	hooks judgeBodyCutoverHooks,
) (retErr error) {
	if s == nil || s.db == nil {
		return errors.New("judge_body: authoritative store is not initialized")
	}
	if legacy == nil || legacy.db == nil {
		return errors.New("judge_body: legacy audit store is required for cutover")
	}
	if batchSize <= 0 {
		return errors.New("judge_body: cutover batch size must be positive")
	}

	s.cutoverMu.Lock()
	defer s.cutoverMu.Unlock()
	// Cutover is a state transition, not a constructor convention. Even an
	// immediately-ready standalone store becomes unavailable before the source
	// lock/copy begins and remains unavailable on every failure path.
	s.cutoverReady.Store(false)

	conn, err := legacy.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("judge_body: acquire legacy cutover connection: %w", err)
	}
	defer conn.Close()

	sourceKey, sourcePath, err := legacyJudgeSourceKey(ctx, conn)
	if err != nil {
		return err
	}
	if sameSQLitePath(sourcePath, s.path) {
		return errors.New("judge_body: authoritative and legacy databases must use different files")
	}

	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("judge_body: acquire legacy writer cutover lock: %w", err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	// A completed cutover plus the exact permanent source guards is a durable
	// writer switch. Because the guards prohibit INSERT/UPDATE, remaining legacy
	// rows can only be a deletion-only subset of the rows already copied and
	// verified. Trust that committed state on restart instead of re-reading every
	// raw body under an audit.db IMMEDIATE lock for the whole retention window.
	completed, err := s.legacyJudgeCutoverCompleted(ctx, sourceKey)
	if err != nil {
		return err
	}
	if completed && verifyLegacyJudgeReadOnlyTriggers(ctx, conn) == nil {
		if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
			return fmt.Errorf("judge_body: commit completed legacy cutover check: %w", err)
		}
		locked = false
		s.cutoverReady.Store(true)
		return nil
	}

	lastID := ""
	started := false
	verifiedTotal := int64(0)
	for {
		rows, err := conn.QueryContext(ctx, `SELECT `+judgeBodySelectColumns+`
			FROM judge_responses
			WHERE (? = 0 OR id > ?)
			ORDER BY id ASC
			LIMIT ?`, judgeBoolInt(started), lastID, batchSize)
		if err != nil {
			return fmt.Errorf("judge_body: read deterministic legacy batch: %w", err)
		}
		batch := make([]legacyJudgeBodyRow, 0, batchSize)
		for rows.Next() {
			row, scanErr := scanLegacyJudgeBody(rows)
			if scanErr != nil {
				_ = rows.Close()
				return fmt.Errorf("judge_body: scan legacy row: %w", scanErr)
			}
			batch = append(batch, row)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("judge_body: iterate legacy batch: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("judge_body: close legacy batch: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		if err := s.copyAndVerifyLegacyBatch(ctx, sourceKey, batch, hooks); err != nil {
			return err
		}
		verifiedTotal += int64(len(batch))
		lastID = batch[len(batch)-1].id
		started = true
	}

	// Reinstall rather than trusting names left by an older or tampered schema.
	// Deletion intentionally remains allowed for the legacy-first purge protocol.
	if err := reinstallLegacyJudgeReadOnlyTriggers(ctx, conn); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO legacy_judge_cutover_state(source_key, completed_at, verified_rows)
		VALUES (?, ?, ?)
		ON CONFLICT(source_key) DO UPDATE SET
			completed_at=excluded.completed_at,
			verified_rows=excluded.verified_rows`,
		sourceKey, time.Now().UTC().Format(time.RFC3339Nano), verifiedTotal); err != nil {
		return fmt.Errorf("judge_body: record completed cutover: %w", err)
	}
	if err := hooks.run(judgeBodyPhaseCompletionCommitted); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("judge_body: commit legacy writer cutover: %w", err)
	}
	locked = false
	if err := hooks.run(judgeBodyPhaseSourceCommitted); err != nil {
		return err
	}
	if err := verifyLegacyJudgeReadOnlyTriggers(ctx, conn); err != nil {
		return err
	}
	s.cutoverReady.Store(true)
	return nil
}

func (s *JudgeBodyStore) legacyJudgeCutoverCompleted(ctx context.Context, sourceKey string) (bool, error) {
	var completed int
	if err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM legacy_judge_cutover_state WHERE source_key = ?)`,
		sourceKey,
	).Scan(&completed); err != nil {
		return false, fmt.Errorf("judge_body: inspect completed legacy cutover state: %w", err)
	}
	return completed != 0, nil
}

func (s *JudgeBodyStore) copyAndVerifyLegacyBatch(
	ctx context.Context,
	sourceKey string,
	batch []legacyJudgeBodyRow,
	hooks judgeBodyCutoverHooks,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("judge_body: begin legacy target batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	insertSQL := `INSERT OR IGNORE INTO judge_responses (` + judgeBodyColumnNames + `)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	for _, row := range batch {
		if _, err := tx.ExecContext(ctx, insertSQL, row.insertArgs()...); err != nil {
			return fmt.Errorf("judge_body: copy legacy row %q: %w", row.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("judge_body: commit legacy target batch: %w", err)
	}
	if err := hooks.run(judgeBodyPhaseTargetCommitted); err != nil {
		return err
	}

	// Verification intentionally happens after target commit. A crash or marker
	// failure causes the batch to be replayed through INSERT OR IGNORE, followed
	// by the same exact comparison.
	for _, want := range batch {
		got, err := s.readLegacyShapeByID(ctx, want.id)
		if err != nil {
			return fmt.Errorf("judge_body: verify legacy row %q: %w", want.id, err)
		}
		if !want.equal(got) {
			return fmt.Errorf("judge_body: verify legacy row %q: authoritative row conflicts with legacy source", want.id)
		}
	}

	markTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("judge_body: begin legacy verification markers: %w", err)
	}
	defer markTx.Rollback() //nolint:errcheck
	verifiedAt := time.Now().UTC().Format(time.RFC3339Nano)
	for _, row := range batch {
		if _, err := markTx.ExecContext(ctx, `
			INSERT INTO legacy_judge_cutover_rows(source_key, legacy_id, verified_at)
			VALUES (?, ?, ?)
			ON CONFLICT(source_key, legacy_id) DO UPDATE SET verified_at=excluded.verified_at`,
			sourceKey, row.id, verifiedAt); err != nil {
			return fmt.Errorf("judge_body: mark verified legacy row %q: %w", row.id, err)
		}
	}
	if err := markTx.Commit(); err != nil {
		return fmt.Errorf("judge_body: commit legacy verification markers: %w", err)
	}
	if err := hooks.run(judgeBodyPhaseMarkersCommitted); err != nil {
		return err
	}
	return nil
}

func reinstallLegacyJudgeReadOnlyTriggers(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, `
		DROP TRIGGER IF EXISTS defenseclaw_judge_responses_no_insert;
		DROP TRIGGER IF EXISTS defenseclaw_judge_responses_no_update;
	`); err != nil {
		return fmt.Errorf("judge_body: remove stale legacy read-only guards: %w", err)
	}
	for _, statement := range []string{legacyJudgeNoInsertTriggerSQL, legacyJudgeNoUpdateTriggerSQL} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("judge_body: install exact legacy read-only guards: %w", err)
		}
	}
	return verifyLegacyJudgeReadOnlyTriggers(ctx, conn)
}

func verifyLegacyJudgeReadOnlyTriggers(ctx context.Context, conn *sql.Conn) error {
	for _, trigger := range []struct {
		name string
		sql  string
	}{
		{name: legacyJudgeNoInsertTriggerName, sql: legacyJudgeNoInsertTriggerSQL},
		{name: legacyJudgeNoUpdateTriggerName, sql: legacyJudgeNoUpdateTriggerSQL},
	} {
		var actual string
		if err := conn.QueryRowContext(ctx,
			`SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?`, trigger.name,
		).Scan(&actual); err != nil {
			return fmt.Errorf("judge_body: verify legacy read-only guard %s: %w", trigger.name, err)
		}
		if normalizeSQLiteDDL(actual) != normalizeSQLiteDDL(trigger.sql) {
			return fmt.Errorf("judge_body: legacy read-only guard %s does not match the required definition", trigger.name)
		}
	}
	return nil
}

func normalizeSQLiteDDL(statement string) string {
	return strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(statement), ";")), " ")
}

func (s *JudgeBodyStore) readLegacyShapeByID(ctx context.Context, id string) (legacyJudgeBodyRow, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+judgeBodySelectColumns+`
		FROM judge_responses WHERE id = ?`, id)
	got, err := scanLegacyJudgeBody(row)
	if err != nil {
		return legacyJudgeBodyRow{}, err
	}
	return got, nil
}

func legacyJudgeSourceKey(ctx context.Context, conn *sql.Conn) (key, path string, err error) {
	rows, err := conn.QueryContext(ctx, `PRAGMA database_list`)
	if err != nil {
		return "", "", fmt.Errorf("judge_body: identify legacy database: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return "", "", fmt.Errorf("judge_body: scan legacy database identity: %w", err)
		}
		if name == "main" {
			clean := filepath.Clean(file)
			digest := sha256.Sum256([]byte("defenseclaw/judge-cutover-source/v1\x00" + clean))
			return hex.EncodeToString(digest[:]), clean, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", "", fmt.Errorf("judge_body: iterate legacy database identity: %w", err)
	}
	return "", "", errors.New("judge_body: legacy main database identity is unavailable")
}

func sameSQLitePath(a, b string) bool {
	return sameJudgeBodyDatabaseFile(a, b)
}

func judgeBoolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ListCompatibleJudgeResponsesCtx returns authoritative rows first and adds only
// legacy IDs that are absent from judge_bodies.db. The final ordering is newest
// first with stable ID as a deterministic tie-breaker.
func (s *JudgeBodyStore) ListCompatibleJudgeResponsesCtx(ctx context.Context, legacy *Store, limit int) ([]JudgeResponse, error) {
	release, err := s.acquireRuntime()
	if err != nil {
		return nil, err
	}
	defer release()
	if legacy == nil || legacy.db == nil {
		return nil, errors.New("judge_body: legacy audit store is required for compatibility reads")
	}
	if limit <= 0 {
		limit = 50
	}
	authoritative, err := s.listJudgeResponsesCtxUnlocked(ctx, limit)
	if err != nil {
		return nil, err
	}
	legacyRows, err := listLegacyJudgeResponsesCtx(ctx, legacy, limit)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(authoritative))
	combined := make([]JudgeResponse, 0, len(authoritative)+len(legacyRows))
	for _, row := range authoritative {
		seen[row.ID] = struct{}{}
		combined = append(combined, row)
	}
	for _, row := range legacyRows {
		if _, duplicate := seen[row.ID]; duplicate {
			continue
		}
		seen[row.ID] = struct{}{}
		combined = append(combined, row)
	}
	sort.SliceStable(combined, func(i, j int) bool {
		if combined[i].Timestamp.Equal(combined[j].Timestamp) {
			return combined[i].ID > combined[j].ID
		}
		return combined[i].Timestamp.After(combined[j].Timestamp)
	})
	if len(combined) > limit {
		combined = combined[:limit]
	}
	return combined, nil
}

func listLegacyJudgeResponsesCtx(ctx context.Context, legacy *Store, limit int) ([]JudgeResponse, error) {
	if err := verifyJudgeBodyTimestampUnixNanoReady(legacy.db); err != nil {
		return nil, fmt.Errorf("judge_body: legacy timestamp readiness: %w", err)
	}
	rows, err := legacy.queryDB(ctx, "judge_body_compat_list", `
		SELECT id, timestamp, timestamp_unix_nano, kind, COALESCE(direction,''), COALESCE(model,''),
			COALESCE(action,''), COALESCE(severity,''), COALESCE(latency_ms,0),
			COALESCE(parse_error,''), raw_response,
			COALESCE(request_id,''), COALESCE(trace_id,''), COALESCE(run_id,''),
			COALESCE(session_id,''), COALESCE(input_hash,''), COALESCE(confidence,0),
			COALESCE(fail_closed_applied,0), COALESCE(inspected_model,''),
			COALESCE(prompt_template_id,''), COALESCE(schema_version,0),
			COALESCE(content_hash,''), COALESCE(generation,0),
			COALESCE(binary_version,''), COALESCE(agent_id,''),
			COALESCE(agent_instance_id,''), COALESCE(sidecar_instance_id,''),
			COALESCE(policy_id,''), COALESCE(destination_app,''),
			COALESCE(tool_name,''), COALESCE(tool_id,'')
		FROM judge_responses
		ORDER BY timestamp_unix_nano DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("judge_body: list legacy compatibility rows: %w", err)
	}
	defer rows.Close()
	return scanJudgeResponses(rows, limit, "judge_body: scan legacy compatibility row")
}

func scanJudgeResponses(rows *sql.Rows, capacity int, scanMessage string) ([]JudgeResponse, error) {
	out := make([]JudgeResponse, 0, capacity)
	for rows.Next() {
		var row JudgeResponse
		var timestamp string
		var timestampUnixNano int64
		var failClosed int
		var generation int64
		if err := rows.Scan(
			&row.ID, &timestamp, &timestampUnixNano, &row.Kind, &row.Direction, &row.Model,
			&row.Action, &row.Severity, &row.LatencyMs, &row.ParseError, &row.Raw,
			&row.RequestID, &row.TraceID, &row.RunID, &row.SessionID,
			&row.InputHash, &row.Confidence, &failClosed, &row.InspectedModel,
			&row.PromptTemplateID, &row.SchemaVersion, &row.ContentHash,
			&generation, &row.BinaryVersion, &row.AgentID, &row.AgentInstanceID,
			&row.SidecarInstanceID, &row.PolicyID, &row.DestinationApp,
			&row.ToolName, &row.ToolID,
		); err != nil {
			return nil, fmt.Errorf("%s: %w", scanMessage, err)
		}
		row.Generation = uint64(generation)
		row.FailClosedApplied = failClosed != 0
		if err := assignJudgeResponseTimestamp(&row, timestamp, timestampUnixNano, scanMessage); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("judge_body: iterate compatibility rows: %w", err)
	}
	return out, nil
}

// PurgeJudgeResponsesBeforeCtx deletes matching legacy copies first and commits
// before deleting authoritative rows. A failure between databases therefore
// leaves the authoritative body available and cannot resurrect a deleted target
// through compatibility reads.
func (s *JudgeBodyStore) PurgeJudgeResponsesBeforeCtx(ctx context.Context, legacy *Store, cutoff time.Time, batchSize int) (legacyDeleted, authoritativeDeleted int64, err error) {
	return s.purgeJudgeResponsesBeforeCtx(ctx, legacy, cutoff, batchSize, nil)
}

func (s *JudgeBodyStore) purgeJudgeResponsesBeforeCtx(ctx context.Context, legacy *Store, cutoff time.Time, batchSize int, afterLegacy func() error) (int64, int64, error) {
	release, err := s.acquireRuntime()
	if err != nil {
		return 0, 0, err
	}
	defer release()
	if legacy == nil || legacy.db == nil {
		return 0, 0, errors.New("judge_body: legacy audit store is required for ordered purge")
	}
	if batchSize <= 0 {
		return 0, 0, errors.New("judge_body: purge batch size must be positive")
	}
	cutoff = cutoff.UTC()
	legacyDeleted, err := deleteJudgeBodiesBefore(ctx, legacy.db, cutoff, batchSize)
	if err != nil {
		return 0, 0, fmt.Errorf("judge_body: purge legacy rows: %w", err)
	}
	if afterLegacy != nil {
		if err := afterLegacy(); err != nil {
			return legacyDeleted, 0, err
		}
	}
	authoritativeDeleted, err := deleteJudgeBodiesBefore(ctx, s.db, cutoff, batchSize)
	if err != nil {
		return legacyDeleted, 0, fmt.Errorf("judge_body: purge authoritative rows: %w", err)
	}
	return legacyDeleted, authoritativeDeleted, nil
}

func deleteJudgeBodiesBefore(ctx context.Context, db *sql.DB, cutoff time.Time, batchSize int) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		deleted, err := deleteJudgeBodyBatch(ctx, db, cutoff, batchSize)
		if err != nil {
			return total, err
		}
		total += deleted
		if deleted < int64(batchSize) {
			return total, nil
		}
	}
}

func deleteJudgeBodyBatch(ctx context.Context, db *sql.DB, cutoff time.Time, batchSize int) (int64, error) {
	if err := verifyJudgeBodyTimestampUnixNanoReady(db); err != nil {
		return 0, fmt.Errorf("judge_body: timestamp readiness before purge: %w", err)
	}
	cutoffUnixNano, err := judgeBodyUnixNano(cutoff)
	if err != nil {
		return 0, fmt.Errorf("judge_body: normalize retention cutoff: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	result, err := tx.ExecContext(ctx, `DELETE FROM judge_responses WHERE id IN (
		SELECT id FROM judge_responses
		WHERE timestamp_unix_nano < ?
		ORDER BY timestamp_unix_nano ASC, id ASC
		LIMIT ?
	)`, cutoffUnixNano, batchSize)
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}
