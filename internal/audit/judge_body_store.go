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
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// JudgeBodyStore is a dedicated SQLite database for LLM-judge bodies
// (judge_responses rows). It lives in its own file so the very
// high write-volume body INSERTs do not contend with audit_events,
// activity_events, sink_health, or any other "narrow row" writes
// in audit.db.
//
// Why split? Even with WAL + busy_timeout + retry, every fsync on
// audit.db serializes ALL writers — a burst of judge bodies (each
// up to MaxJudgeRawBytes = 64 KiB) measurably delays admission-
// decision audit rows. Putting bodies on their own file gives
// each fsync window a single writer class and decouples the SLOs
// of "verdicts" from "judge forensic detail". The pragma /
// pool / retry hygiene is identical to audit.Store so each DB is
// individually hardened.
//
// Schema: standalone — the `judge_responses` table is anchored at
// migration v1 inside this file rather than reusing the audit
// migration list. Historical audit.db rows move through the explicit,
// verified cutover in judge_body_cutover.go and remain there only as a
// read-only compatibility source until retention or authorized purge.
type JudgeBodyStore struct {
	db   *sql.DB
	path string

	// cutoverReady gates the runtime writer and compatibility reader when
	// the store was opened by NewJudgeBodyStoreForCutover. The gateway uses
	// that constructor so a partial/failed legacy copy can never be served
	// or receive new v8 rows. The ordinary constructor remains immediately
	// writable for standalone tools and tests that have no legacy source.
	cutoverReady atomic.Bool
	cutoverMu    sync.RWMutex

	sqliteBusyMu       sync.RWMutex
	sqliteBusyObserver SQLiteBusyObservabilityV8
}

// BindSQLiteBusyObservabilityV8 publishes or detaches the canonical generated
// contention metric owner for the dedicated judge-body database.
func (s *JudgeBodyStore) BindSQLiteBusyObservabilityV8(observer SQLiteBusyObservabilityV8) {
	if s == nil {
		return
	}
	s.sqliteBusyMu.Lock()
	s.sqliteBusyObserver = observer
	s.sqliteBusyMu.Unlock()
}

func (s *JudgeBodyStore) sqliteBusyObservabilityV8() SQLiteBusyObservabilityV8 {
	if s == nil {
		return nil
	}
	s.sqliteBusyMu.RLock()
	observer := s.sqliteBusyObserver
	s.sqliteBusyMu.RUnlock()
	return observer
}

// NewJudgeBodyStore opens (or creates) a standalone judge bodies database at
// dbPath, applies the same DSN-resident pragmas + single-connection
// pool the audit store uses, and runs the standalone migration list
// in init(). Returns a ready-to-write store.
//
// Gateway startup must use NewJudgeBodyStoreForCutover instead. This immediate-
// ready constructor is for standalone operation where no legacy audit source is
// in scope and for focused tests.
//
// On first creation we ensure the parent directory exists (0700) and
// then chmod the SQLite file down to 0600 — judge bodies can include
// snippets of the model prompt/output and must not inherit the
// process umask's default 0644. Mirrors the inventory store hygiene
// in internal/inventory/store.go.
func NewJudgeBodyStore(dbPath string) (*JudgeBodyStore, error) {
	return newJudgeBodyStore(dbPath, false)
}

// NewJudgeBodyStoreForCutover opens the authoritative database with reads and
// writes disabled until CutoverLegacyJudgeBodies completes successfully. The
// gateway MUST use this constructor whenever audit.db is present.
func NewJudgeBodyStoreForCutover(dbPath string) (*JudgeBodyStore, error) {
	return newJudgeBodyStore(dbPath, true)
}

func newJudgeBodyStore(dbPath string, requireCutover bool) (*JudgeBodyStore, error) {
	return newJudgeBodyStoreWithPathHooks(dbPath, requireCutover, judgeBodyPathHooks{})
}

func newJudgeBodyStoreWithPathHooks(
	dbPath string,
	requireCutover bool,
	hooks judgeBodyPathHooks,
) (*JudgeBodyStore, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("judge_body: db path is required")
	}
	hooks = hooks.withDefaults()
	prepared, err := prepareJudgeBodyDatabasePath(filepath.Clean(dbPath), hooks)
	if err != nil {
		return nil, err
	}
	defer prepared.close()
	dbPath = prepared.path
	if hooks.beforeSQLiteOpen != nil {
		if err := hooks.beforeSQLiteOpen(dbPath); err != nil {
			return nil, fmt.Errorf("judge_body: pre-open path check: %w", err)
		}
	}
	db, err := openSQLite(dbPath)
	if err != nil {
		// Strip the leading "audit:" tier that openSQLite stamps so
		// the operator sees the correct subsystem in the wrapped
		// error chain. openSQLite is shared across both DBs, so the
		// tier disambiguation happens at the caller boundary.
		return nil, fmt.Errorf("judge_body: open db %s: %w", dbPath, unwrapOpenSQLiteErr(err))
	}
	st := &JudgeBodyStore{db: db, path: dbPath}
	st.cutoverReady.Store(!requireCutover)
	if err := st.init(); err != nil {
		_ = st.Close()
		return nil, err
	}
	if err := prepared.validateAfterOpen(); err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
}

// unwrapOpenSQLiteErr strips the shared "audit:" prefix from the
// openSQLite helper so the caller-side wrap shows the right tier.
// Falls back to the original error when the prefix isn't present.
func unwrapOpenSQLiteErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	const prefix = "audit: "
	if strings.HasPrefix(msg, prefix) {
		return errors.New(strings.TrimPrefix(msg, prefix))
	}
	return err
}

// Close releases the underlying connection pool. Idempotent.
func (s *JudgeBodyStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// retry helpers reuse the audit-package retryBusy under the hood;
// the JudgeBodyStore lives in the same Go package so we get the
// shared backoff schedule without duplicating constants.
func (s *JudgeBodyStore) execDB(ctx context.Context, op, query string, args ...any) (sql.Result, error) {
	var res sql.Result
	err := retryBusy(ctx, op, func() error {
		var execErr error
		res, execErr = s.db.ExecContext(ctx, query, args...)
		return execErr
	})
	return res, err
}

func (s *JudgeBodyStore) queryDB(ctx context.Context, op, query string, args ...any) (*sql.Rows, error) {
	var rows *sql.Rows
	err := retryBusy(ctx, op, func() error {
		var qErr error
		rows, qErr = s.db.QueryContext(ctx, query, args...)
		return qErr
	})
	return rows, err
}

// judgeBodyMigrations is the append-only migration list for the
// standalone judge bodies database. v1 mirrors the cumulative
// schema the audit DB ended up with for judge_responses (initial
// table + correlation columns + v7 session/policy/tool columns),
// rolled up into a single CREATE TABLE so a fresh install lands at
// the latest shape immediately.
var judgeBodyMigrations = []migration{
	{
		description: "v1: judge_responses (full v7 shape) + indices",
		apply: func(ex dbExecer) error {
			if _, err := ex.Exec(`
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
				raw_response TEXT NOT NULL,
				request_id TEXT,
				trace_id TEXT,
				run_id TEXT,
				input_hash TEXT,
				confidence REAL,
				fail_closed_applied INTEGER NOT NULL DEFAULT 0,
				inspected_model TEXT,
				prompt_template_id TEXT,
				session_id TEXT,
				agent_instance_id TEXT,
				policy_id TEXT,
				destination_app TEXT,
				tool_name TEXT,
				tool_id TEXT,
				schema_version INTEGER,
				content_hash TEXT,
				generation INTEGER,
				binary_version TEXT,
				agent_id TEXT,
				sidecar_instance_id TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_jb_timestamp  ON judge_responses(timestamp);
			CREATE INDEX IF NOT EXISTS idx_jb_kind       ON judge_responses(kind);
			CREATE INDEX IF NOT EXISTS idx_jb_severity   ON judge_responses(severity);
			CREATE INDEX IF NOT EXISTS idx_jb_request_id ON judge_responses(request_id);
			CREATE INDEX IF NOT EXISTS idx_jb_trace_id   ON judge_responses(trace_id);
			CREATE INDEX IF NOT EXISTS idx_jb_run_id     ON judge_responses(run_id);
			`); err != nil {
				return err
			}
			return nil
		},
	},
	{
		description: "v2: verified legacy cutover state",
		apply: func(ex dbExecer) error {
			_, err := ex.Exec(`
			CREATE TABLE IF NOT EXISTS legacy_judge_cutover_rows (
				source_key TEXT NOT NULL,
				legacy_id TEXT NOT NULL,
				verified_at DATETIME NOT NULL,
				PRIMARY KEY (source_key, legacy_id)
			);
			CREATE TABLE IF NOT EXISTS legacy_judge_cutover_state (
				source_key TEXT PRIMARY KEY,
				completed_at DATETIME NOT NULL,
				verified_rows INTEGER NOT NULL
			);
			`)
			return err
		},
	},
	{
		description: "v3: normalize judge timestamps for indexed retention",
		apply: func(ex dbExecer) error {
			return migrateJudgeBodyTimestampUnixNano(ex, judgeBodyTimestampUnixNanoIndex)
		},
	},
}

func (s *JudgeBodyStore) init() error {
	if _, err := s.execDB(context.Background(), "judge_body_schema", `CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL
	)`); err != nil {
		return fmt.Errorf("judge_body: create schema_version: %w", err)
	}

	current := 0
	row := s.db.QueryRowContext(context.Background(), `SELECT COALESCE(MAX(version), 0) FROM schema_version`)
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("judge_body: read schema version: %w", err)
	}

	for i := current; i < len(judgeBodyMigrations); i++ {
		ver := i + 1
		m := judgeBodyMigrations[i]
		fmt.Fprintf(os.Stderr, "[judge_body] applying migration %d: %s\n", ver, m.description)
		if err := s.applyMigration(ver, m); err != nil {
			return err
		}
	}
	if err := ensureJudgeBodyTimestampUnixNano(s.db, judgeBodyTimestampUnixNanoIndex); err != nil {
		return fmt.Errorf("judge_body: verify timestamp retention index: %w", err)
	}
	return nil
}

func (s *JudgeBodyStore) applyMigration(ver int, m migration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("judge_body: begin migration %d: %w", ver, err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := m.apply(tx); err != nil {
		return fmt.Errorf("judge_body: migration %d (%s): %w", ver, m.description, err)
	}
	if _, err := txExecContextObserved(context.Background(), tx, "judge_body_migration_version_insert", s.sqliteBusyObservabilityV8(),
		`INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`,
		ver, time.Now().UTC()); err != nil {
		return fmt.Errorf("judge_body: record migration %d: %w", ver, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("judge_body: commit migration %d: %w", ver, err)
	}
	return nil
}

// InsertJudgeResponse persists a single judge body. Mirrors the
// audit store version (truncation, default IDs/timestamps, fail-
// closed marshaling) so callers behave identically against either
// backend.
//
// Deprecated: prefer InsertJudgeResponseCtx so caller cancellation
// and request-scoped deadlines flow through to retryBusy.
func (s *JudgeBodyStore) InsertJudgeResponse(e JudgeResponse) error {
	return s.InsertJudgeResponseCtx(context.Background(), e)
}

// InsertJudgeResponseCtx is the context-aware variant. Used by the
// async worker so a SIGTERM-cancelled request immediately aborts
// any in-flight retryBusy loop instead of waiting out the backoff
// schedule.
func (s *JudgeBodyStore) InsertJudgeResponseCtx(ctx context.Context, e JudgeResponse) error {
	release, err := s.acquireRuntime()
	if err != nil {
		return err
	}
	defer release()
	if e.Raw == "" {
		return nil
	}
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.RunID == "" {
		e.RunID = currentRunID()
	}
	timestampUnixNano, err := judgeBodyUnixNano(e.Timestamp)
	if err != nil {
		return fmt.Errorf("judge_body: normalize timestamp: %w", err)
	}
	raw := truncateJudgeRaw(e.Raw, MaxJudgeRawBytes)
	failClosed := 0
	if e.FailClosedApplied {
		failClosed = 1
	}
	_, err = s.execDB(ctx, "judge_body_insert",
		`INSERT INTO judge_responses
			(id, timestamp, timestamp_unix_nano, kind, direction, model, action, severity, latency_ms,
			 parse_error, raw_response, request_id, trace_id, run_id, session_id, input_hash,
			 confidence, fail_closed_applied, inspected_model, prompt_template_id,
			 schema_version, content_hash, generation, binary_version,
			 agent_id, agent_instance_id, sidecar_instance_id,
			 policy_id, destination_app, tool_name, tool_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID,
		e.Timestamp.Format(time.RFC3339Nano),
		timestampUnixNano,
		e.Kind,
		nullStr(e.Direction),
		nullStr(e.Model),
		nullStr(e.Action),
		nullStr(e.Severity),
		e.LatencyMs,
		nullStr(e.ParseError),
		raw,
		nullStr(e.RequestID),
		nullStr(e.TraceID),
		nullStr(e.RunID),
		nullStr(e.SessionID),
		nullStr(e.InputHash),
		e.Confidence,
		failClosed,
		nullStr(e.InspectedModel),
		nullStr(e.PromptTemplateID),
		nullInt(e.SchemaVersion),
		nullStr(e.ContentHash),
		int64(e.Generation),
		nullStr(e.BinaryVersion),
		nullStr(e.AgentID),
		nullStr(e.AgentInstanceID),
		nullStr(e.SidecarInstanceID),
		nullStr(e.PolicyID),
		nullStr(e.DestinationApp),
		nullStr(e.ToolName),
		nullStr(e.ToolID),
	)
	if err != nil {
		return fmt.Errorf("judge_body: insert: %w", err)
	}
	return nil
}

// ListJudgeResponses returns the most recent N persisted judge bodies
// from the standalone DB. Same shape as Store.ListJudgeResponses
// for caller parity.
//
// Deprecated: prefer ListJudgeResponsesCtx so caller cancellation
// flows through.
func (s *JudgeBodyStore) ListJudgeResponses(limit int) ([]JudgeResponse, error) {
	return s.ListJudgeResponsesCtx(context.Background(), limit)
}

// ListJudgeResponsesCtx is the context-aware variant of ListJudgeResponses.
func (s *JudgeBodyStore) ListJudgeResponsesCtx(ctx context.Context, limit int) ([]JudgeResponse, error) {
	release, err := s.acquireRuntime()
	if err != nil {
		return nil, err
	}
	defer release()
	return s.listJudgeResponsesCtxUnlocked(ctx, limit)
}

func (s *JudgeBodyStore) listJudgeResponsesCtxUnlocked(ctx context.Context, limit int) ([]JudgeResponse, error) {
	if err := verifyJudgeBodyTimestampUnixNanoReady(s.db); err != nil {
		return nil, fmt.Errorf("judge_body: timestamp readiness: %w", err)
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.queryDB(ctx, "judge_body_list", `
		SELECT id, timestamp, timestamp_unix_nano, kind, COALESCE(direction,''), COALESCE(model,''),
			COALESCE(action,''), COALESCE(severity,''), COALESCE(latency_ms,0),
			COALESCE(parse_error,''), raw_response,
			COALESCE(request_id,''), COALESCE(trace_id,''), COALESCE(run_id,''),
			COALESCE(session_id,''), COALESCE(input_hash,''), COALESCE(confidence,0),
			COALESCE(fail_closed_applied,0),
			COALESCE(inspected_model,''), COALESCE(prompt_template_id,''),
			COALESCE(schema_version,0), COALESCE(content_hash,''), COALESCE(generation,0), COALESCE(binary_version,''),
			COALESCE(agent_id,''), COALESCE(agent_instance_id,''), COALESCE(sidecar_instance_id,''),
			COALESCE(policy_id,''), COALESCE(destination_app,''), COALESCE(tool_name,''), COALESCE(tool_id,'')
		FROM judge_responses
		ORDER BY timestamp_unix_nano DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("judge_body: list: %w", err)
	}
	defer rows.Close()

	out := make([]JudgeResponse, 0, limit)
	for rows.Next() {
		var r JudgeResponse
		var ts string
		var timestampUnixNano int64
		var failClosed int
		var gen int64
		if err := rows.Scan(&r.ID, &ts, &timestampUnixNano, &r.Kind, &r.Direction, &r.Model,
			&r.Action, &r.Severity, &r.LatencyMs, &r.ParseError, &r.Raw,
			&r.RequestID, &r.TraceID, &r.RunID, &r.SessionID, &r.InputHash, &r.Confidence,
			&failClosed, &r.InspectedModel, &r.PromptTemplateID,
			&r.SchemaVersion, &r.ContentHash, &gen, &r.BinaryVersion,
			&r.AgentID, &r.AgentInstanceID, &r.SidecarInstanceID,
			&r.PolicyID, &r.DestinationApp, &r.ToolName, &r.ToolID); err != nil {
			return nil, fmt.Errorf("judge_body: scan: %w", err)
		}
		r.Generation = uint64(gen)
		r.FailClosedApplied = failClosed != 0
		if err := assignJudgeResponseTimestamp(&r, ts, timestampUnixNano, "judge_body: list"); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("judge_body: iterate: %w", err)
	}
	return out, nil
}

// BeginJudgeBatch opens a transaction for batched INSERTs from the
// gateway worker. Mirrors Store.BeginJudgeBatch so the same JudgeBatch
// handle works against either backend without an adapter.
func (s *JudgeBodyStore) BeginJudgeBatch(ctx context.Context) (*JudgeBatch, error) {
	release, err := s.acquireRuntime()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		release()
		return nil, fmt.Errorf("judge_body: begin batch: %w", err)
	}
	return &JudgeBatch{
		tx: tx, ctx: ctx, release: release,
		sqliteBusyObserver: s.sqliteBusyObservabilityV8(),
	}, nil
}

func (s *JudgeBodyStore) acquireRuntime() (func(), error) {
	if s == nil || s.db == nil {
		return nil, errors.New("judge_body: store is not initialized")
	}
	s.cutoverMu.RLock()
	if !s.cutoverReady.Load() {
		s.cutoverMu.RUnlock()
		return nil, errors.New("judge_body: legacy cutover is incomplete")
	}
	return s.cutoverMu.RUnlock, nil
}

// CutoverReady reports whether runtime reads and writes are enabled. It is
// primarily useful to startup coordination and tests; a false result is a hard
// fail-closed state, never a signal to fall back to audit.db.
func (s *JudgeBodyStore) CutoverReady() bool {
	return s != nil && s.cutoverReady.Load()
}

// DB is a test-only escape hatch for asserting pool settings.
// Not part of the supported API surface.
func (s *JudgeBodyStore) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

// silence "imported and not used" when telemetry is otherwise
// unreferenced in test builds. The runtime store actually uses
// it via the retryBusy helper.
