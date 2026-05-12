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
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/telemetry"
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
// migration list. Migrations from the audit DB are not replayed;
// historical rows in audit.db remain there and can be reclaimed
// with `sqlite3 audit.db "DROP TABLE judge_responses"` whenever the
// operator is ready.
type JudgeBodyStore struct {
	db *sql.DB
}

// NewJudgeBodyStore opens (or creates) the judge bodies database at
// dbPath, applies the same DSN-resident pragmas + single-connection
// pool the audit store uses, and runs the standalone migration list
// in init(). Returns a ready-to-write store.
func NewJudgeBodyStore(dbPath string) (*JudgeBodyStore, error) {
	db, err := openSQLite(dbPath)
	if err != nil {
		return nil, fmt.Errorf("judge_body: open db %s: %w", dbPath, err)
	}
	st := &JudgeBodyStore{db: db}
	if err := st.init(); err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
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
	if _, err := txExec(tx, "judge_body_migration_version_insert",
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
func (s *JudgeBodyStore) InsertJudgeResponse(e JudgeResponse) error {
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
	raw := truncateJudgeRaw(e.Raw, MaxJudgeRawBytes)
	failClosed := 0
	if e.FailClosedApplied {
		failClosed = 1
	}
	_, err := s.execDB(context.Background(), "judge_body_insert",
		`INSERT INTO judge_responses
			(id, timestamp, kind, direction, model, action, severity, latency_ms,
			 parse_error, raw_response, request_id, trace_id, run_id, session_id, input_hash,
			 confidence, fail_closed_applied, inspected_model, prompt_template_id,
			 schema_version, content_hash, generation, binary_version,
			 agent_id, agent_instance_id, sidecar_instance_id,
			 policy_id, destination_app, tool_name, tool_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
func (s *JudgeBodyStore) ListJudgeResponses(limit int) ([]JudgeResponse, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.queryDB(context.Background(), "judge_body_list", `
		SELECT id, timestamp, kind, COALESCE(direction,''), COALESCE(model,''),
			COALESCE(action,''), COALESCE(severity,''), COALESCE(latency_ms,0),
			COALESCE(parse_error,''), raw_response,
			COALESCE(request_id,''), COALESCE(trace_id,''), COALESCE(run_id,''),
			COALESCE(session_id,''), COALESCE(input_hash,''), COALESCE(confidence,0),
			COALESCE(fail_closed_applied,0),
			COALESCE(inspected_model,''), COALESCE(prompt_template_id,''),
			COALESCE(schema_version,0), COALESCE(content_hash,''), COALESCE(generation,0), COALESCE(binary_version,''),
			COALESCE(agent_id,''), COALESCE(agent_instance_id,''), COALESCE(sidecar_instance_id,''),
			COALESCE(policy_id,''), COALESCE(destination_app,''), COALESCE(tool_name,''), COALESCE(tool_id,'')
		FROM judge_responses ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("judge_body: list: %w", err)
	}
	defer rows.Close()

	out := make([]JudgeResponse, 0, limit)
	for rows.Next() {
		var r JudgeResponse
		var ts string
		var failClosed int
		var gen int64
		if err := rows.Scan(&r.ID, &ts, &r.Kind, &r.Direction, &r.Model,
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
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			r.Timestamp = t
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("judge_body: begin batch: %w", err)
	}
	return &JudgeBatch{tx: tx}, nil
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
var _ = telemetry.RecordSQLiteBusy
