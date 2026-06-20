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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
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
	// RequestID is the per-request correlation key minted at the
	// top of every proxy path. Populated in Phase 5 via the
	// gateway context threading; older call sites may leave it
	// empty, in which case the column stays NULL in SQLite.
	RequestID string `json:"request_id,omitempty"`

	// SessionID ties every event produced during a single
	// OpenClaw agent session (derived from the WebSocket
	// sessionKey or from the guardrail-proxy conversation id)
	// so downstream consumers can fold tool-call, approval,
	// and verdict events into one row per session.
	SessionID string `json:"session_id,omitempty"`

	// TurnID identifies a single agent turn inside a session. It is
	// currently sink-only for audit events; gatewaylog events persist it
	// directly in the canonical JSON envelope.
	TurnID string `json:"turn_id,omitempty"`

	// AgentName is the logical name of the agent producing the
	// event (e.g. "openclaw", "nemoclaw", or a caller-supplied
	// name from the incoming stream envelope). Falls back to
	// cfg.Claw.Mode at the router boundary when the stream does
	// not supply one.
	AgentName string `json:"agent_name,omitempty"`

	// AgentInstanceID identifies a single agent SESSION (v7 clean
	// break from v6). It is populated when the event has session
	// anchoring — i.e. deterministic hash of the session key so
	// multi-turn conversations cluster correctly. For events with
	// no session context (watcher admission, operator mutations,
	// scanner results fired outside a request), this stays empty.
	// The process-scoped identifier lives on SidecarInstanceID.
	AgentInstanceID string `json:"agent_instance_id,omitempty"`

	// PolicyID is the identifier of the policy that produced the
	// verdict / enforcement decision recorded by this event.
	// Required by downstream Splunk dashboards (see
	// splunk/apps/defenseclaw_local_mode/default/macros.conf)
	// which previously defaulted to "(none)" for every row.
	PolicyID string `json:"policy_id,omitempty"`

	// DestinationApp is the upstream system the event targets.
	// For tool events this is the tool provider (builtin |
	// mcp:<server> | skill:<key>); for LLM events this is the
	// gen_ai.system identifier (openai | anthropic | …).
	DestinationApp string `json:"destination_app,omitempty"`

	// ToolName / ToolID are populated on tool-runtime and
	// approval-flow events so /v1/agentwatch/summary can render
	// top_tools without re-parsing Details strings.
	ToolName string `json:"tool_name,omitempty"`
	ToolID   string `json:"tool_id,omitempty"`

	// v7 provenance + identity (SQLite columns from migration 10).
	SchemaVersion     int    `json:"schema_version,omitempty"`
	ContentHash       string `json:"content_hash,omitempty"`
	Generation        uint64 `json:"generation,omitempty"`
	BinaryVersion     string `json:"binary_version,omitempty"`
	AgentID           string `json:"agent_id,omitempty"`
	SidecarInstanceID string `json:"sidecar_instance_id,omitempty"`

	// Multi-connector identity + per-turn / enforcement fields
	// (SQLite columns from migration 16). All optional and additive —
	// older rows leave the columns NULL, and non-hook events (admin
	// mutations, scanner results) simply don't populate them.
	//
	//   - Connector: the hook connector that produced this event
	//     (codex, claudecode, antigravity, ...), recovered from the
	//     request context. Empty for proxy / non-connector events.
	//   - StepIdx: 1-indexed turn counter within a session_id. All hook
	//     events emitted during the same agent turn share one StepIdx;
	//     a new turn increments it. Zero means "not turn-anchored".
	//   - Enforced: true when the guardrail decision was actually
	//     enforced (blocked), as opposed to observe-mode would-block.
	//   - RulePackDir: the effective rule-pack directory the verdict was
	//     evaluated against (per-connector override or global).
	Connector   string `json:"connector,omitempty"`
	StepIdx     int    `json:"step_idx,omitempty"`
	Enforced    bool   `json:"enforced,omitempty"`
	RulePackDir string `json:"rule_pack_dir,omitempty"`

	// Structured carries sanitized machine-readable data for sink fanout.
	// It is intentionally not persisted in SQLite audit_events; callers that
	// need durable structured records should use their native table/log path.
	Structured map[string]any `json:"structured,omitempty"`
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
	// Connector scopes the entry (SK-4). "" means the entry is global — it
	// applies to every connector. A non-empty value (e.g. "hermes") scopes
	// the action to one connector. The actions table is unique on
	// (target_type, target_name, connector), so a target can carry one global
	// entry plus one entry per connector. Mirrors ActionEntry.connector in
	// cli/defenseclaw/models.py.
	Connector string `json:"connector,omitempty"`
}

type Store struct {
	db *sql.DB
}

// auditPragmas is the pragma set applied to every connection in the
// audit store's pool via the DSN query string. Putting them in the
// DSN (as opposed to db.Exec at startup) is critical: PRAGMA
// statements run via db.Exec only mutate the *connection* that
// happened to serve them, but Go's database/sql pool can open new
// connections at any time. With the DSN form, modernc.org/sqlite
// replays the pragmas on every fresh connection so busy_timeout and
// synchronous stay consistent across the pool.
//
// Settings explained:
//   - journal_mode=WAL          enables write-ahead logging so readers
//     and writers do not block each other.
//   - busy_timeout=5000         SQLite waits up to 5 seconds before
//     returning SQLITE_BUSY, absorbing the
//     vast majority of write contention.
//   - synchronous=NORMAL        the sweet spot for WAL: durable
//     across crashes (loses only the last
//     transaction on power loss) while ~3x
//     faster than the FULL default.
//   - cache_size=-20000         negative => kilobytes; ~20 MB of
//     in-memory page cache per connection.
//   - temp_store=MEMORY         spill temp tables to RAM instead of
//     disk; eliminates a common contention
//     source on writes that allocate temp.
//   - mmap_size=268435456       map up to 256 MB of the DB into the
//     process address space for read-heavy
//     queries (audit views, exports).
//   - foreign_keys=ON           defenseclaw relies on the FK between
//     findings and scan_results; turning
//     this off at the DSN level would be a
//     silent correctness regression.
const auditPragmas = "?_pragma=journal_mode(WAL)" +
	"&_pragma=busy_timeout(5000)" +
	"&_pragma=synchronous(NORMAL)" +
	"&_pragma=cache_size(-20000)" +
	"&_pragma=temp_store(MEMORY)" +
	"&_pragma=mmap_size(268435456)" +
	"&_pragma=foreign_keys(ON)"

// openSQLite opens a SQLite connection with the audit-tier hardening
// applied (DSN pragmas + a single-connection pool). Sharing this
// helper between NewStore and the upcoming judge_body_store keeps
// the contention guarantees in lockstep.
//
// Pool sizing: SQLite serializes writers internally, so opening
// multiple connections for the same DB just races them for the same
// write lock and surfaces as SQLITE_BUSY. We cap MaxOpenConns at 1
// and let Go's database/sql mutex serialize callers — this is the
// canonical pattern recommended by modernc.org/sqlite. Reads share
// the same connection, which is fine in practice because every
// audit write completes in microseconds; if read latency ever
// becomes a problem, we can introduce a separate read-only pool
// without touching this hot path.
func openSQLite(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath+auditPragmas)
	if err != nil {
		return nil, fmt.Errorf("audit: open db %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	return db, nil
}

func NewStore(dbPath string) (*Store, error) {
	db, err := openSQLite(dbPath)
	if err != nil {
		return nil, err
	}
	st := &Store{db: db}
	telemetry.RegisterAuditDB(db)
	return st, nil
}

// sqliteCoded is the structural interface implemented by the
// modernc.org/sqlite *Error type (Code() int returns the underlying
// SQLite result code). We match on it via errors.As so the
// detection survives error-wrapping (fmt.Errorf("...: %w", err))
// and stays decoupled from the concrete driver type.
type sqliteCoded interface {
	Code() int
}

// SQLite result codes we treat as "transient contention; safe to
// retry". Values mirror modernc.org/sqlite/lib (SQLITE_BUSY = 5,
// SQLITE_LOCKED = 6). Hard-coded here to avoid pulling the driver
// into a typed import that the rest of the package doesn't need.
const (
	sqliteCodeBusy   = 5
	sqliteCodeLocked = 6
)

// isSQLiteBusy reports whether err signals transient SQLite write
// contention. We check the driver's result code first (the
// authoritative source) and fall back to a substring match so the
// detection stays robust against driver versions that surface BUSY
// only in the rendered message (older modernc releases, or third-
// party drivers that wrap errors before returning them).
func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	var coded sqliteCoded
	if errors.As(err, &coded) {
		switch coded.Code() {
		case sqliteCodeBusy, sqliteCodeLocked:
			return true
		}
	}
	s := err.Error()
	return strings.Contains(s, "database is locked") ||
		strings.Contains(s, "SQLITE_BUSY") ||
		strings.Contains(s, "SQLITE_LOCKED")
}

// SQLite BUSY retry policy. Even with busy_timeout=5000 some bursts
// outpace SQLite's internal waiter — we layer an application-level
// retry with exponential backoff on top so transient contention
// never bubbles up as a dropped write. The schedule
// (10ms, 20ms, 40ms, 80ms, 160ms; ~310ms worst case) is short
// enough not to push end-to-end latency past the proxy SLO and long
// enough to outlast a single fsync window.
const (
	sqliteRetryAttempts = 5
	sqliteRetryBaseMs   = 10
)

// retryBusy runs fn up to sqliteRetryAttempts times, backing off
// exponentially on BUSY errors. Each retry records a telemetry event
// so operators can correlate contention spikes; the final error
// (whether BUSY-related or not) is returned verbatim. ctx
// cancellation aborts the loop immediately, preserving cancellation
// semantics for request-scoped writes.
func retryBusy(ctx context.Context, op string, fn func() error) error {
	delay := time.Duration(sqliteRetryBaseMs) * time.Millisecond
	var err error
	for attempt := 0; attempt < sqliteRetryAttempts; attempt++ {
		err = fn()
		if !isSQLiteBusy(err) {
			return err
		}
		telemetry.RecordSQLiteBusy(ctx, op)
		if attempt == sqliteRetryAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
	return err
}

func (s *Store) execDB(ctx context.Context, op string, query string, args ...any) (sql.Result, error) {
	var res sql.Result
	err := retryBusy(ctx, op, func() error {
		var execErr error
		res, execErr = s.db.ExecContext(ctx, query, args...)
		return execErr
	})
	return res, err
}

func (s *Store) queryDB(ctx context.Context, op string, query string, args ...any) (*sql.Rows, error) {
	var rows *sql.Rows
	err := retryBusy(ctx, op, func() error {
		var qErr error
		rows, qErr = s.db.QueryContext(ctx, query, args...)
		return qErr
	})
	return rows, err
}

func (s *Store) scanRow(ctx context.Context, op string, row *sql.Row, dest ...any) error {
	return retryBusy(ctx, op, func() error {
		return row.Scan(dest...)
	})
}

// txExec is the in-transaction equivalent. We deliberately do NOT
// retry transactions here — once a tx has been opened the BUSY error
// usually means the whole tx must be rolled back and reattempted by
// the caller (otherwise we'd corrupt invariants halfway through). We
// still record the metric so contention shows up in dashboards.
func txExec(tx *sql.Tx, op string, query string, args ...any) (sql.Result, error) {
	res, err := tx.Exec(query, args...)
	if isSQLiteBusy(err) {
		telemetry.RecordSQLiteBusy(context.Background(), op)
	}
	return res, err
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
				structured_json TEXT,
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
			CREATE INDEX IF NOT EXISTS idx_audit_severity_timestamp ON audit_events(severity, timestamp);
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
		// Phase 3 of the observability refactor: land correlation
		// identifiers (request_id + trace_id) on audit_events so
		// operators can pivot between gateway.jsonl, SQLite, Splunk,
		// and OTel without a separate join table. request_id is
		// minted at the top of every proxy request in Phase 5;
		// trace_id mirrors the OTel span id the audit.Logger
		// already stamps onto emitted spans.
		//
		// The same correlation keys are mirrored onto judge_responses
		// so a single request_id lookup reveals every verdict and
		// every judge response tied to that request.
		description: "add trace_id/request_id columns for end-to-end correlation",
		apply: func(ex dbExecer) error {
			for _, spec := range []struct {
				table, column, stmt string
			}{
				{"audit_events", "trace_id", `ALTER TABLE audit_events ADD COLUMN trace_id TEXT`},
				{"audit_events", "request_id", `ALTER TABLE audit_events ADD COLUMN request_id TEXT`},
				{"judge_responses", "request_id", `ALTER TABLE judge_responses ADD COLUMN request_id TEXT`},
				{"judge_responses", "trace_id", `ALTER TABLE judge_responses ADD COLUMN trace_id TEXT`},
				{"judge_responses", "run_id", `ALTER TABLE judge_responses ADD COLUMN run_id TEXT`},
				{"judge_responses", "input_hash", `ALTER TABLE judge_responses ADD COLUMN input_hash TEXT`},
				{"judge_responses", "confidence", `ALTER TABLE judge_responses ADD COLUMN confidence REAL`},
				{"judge_responses", "fail_closed_applied", `ALTER TABLE judge_responses ADD COLUMN fail_closed_applied INTEGER NOT NULL DEFAULT 0`},
				{"judge_responses", "inspected_model", `ALTER TABLE judge_responses ADD COLUMN inspected_model TEXT`},
				{"judge_responses", "prompt_template_id", `ALTER TABLE judge_responses ADD COLUMN prompt_template_id TEXT`},
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
				`CREATE INDEX IF NOT EXISTS idx_audit_trace_id ON audit_events(trace_id)`,
				`CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_events(request_id)`,
				`CREATE INDEX IF NOT EXISTS idx_judge_request_id ON judge_responses(request_id)`,
				`CREATE INDEX IF NOT EXISTS idx_judge_trace_id ON judge_responses(trace_id)`,
				`CREATE INDEX IF NOT EXISTS idx_judge_run_id ON judge_responses(run_id)`,
			} {
				if _, err := ex.Exec(idx); err != nil {
					return fmt.Errorf("create correlation index: %w", err)
				}
			}
			return nil
		},
	},
	{
		// Observability Phase 6: surface agent/tool/policy context
		// on every audit row so downstream aggregators (top_tools
		// in /v1/agentwatch/summary, Splunk dashboards keyed on
		// policy_id, per-agent incident timelines) can key off
		// first-class columns instead of parsing the free-form
		// details blob.
		description: "add session_id/agent/policy/destination/tool correlation columns",
		apply: func(ex dbExecer) error {
			for _, spec := range []struct {
				table, column, stmt string
			}{
				{"audit_events", "session_id", `ALTER TABLE audit_events ADD COLUMN session_id TEXT`},
				{"audit_events", "agent_name", `ALTER TABLE audit_events ADD COLUMN agent_name TEXT`},
				{"audit_events", "agent_instance_id", `ALTER TABLE audit_events ADD COLUMN agent_instance_id TEXT`},
				{"audit_events", "policy_id", `ALTER TABLE audit_events ADD COLUMN policy_id TEXT`},
				{"audit_events", "destination_app", `ALTER TABLE audit_events ADD COLUMN destination_app TEXT`},
				{"audit_events", "tool_name", `ALTER TABLE audit_events ADD COLUMN tool_name TEXT`},
				{"audit_events", "tool_id", `ALTER TABLE audit_events ADD COLUMN tool_id TEXT`},
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
				`CREATE INDEX IF NOT EXISTS idx_audit_session_id ON audit_events(session_id)`,
				`CREATE INDEX IF NOT EXISTS idx_audit_agent_instance_id ON audit_events(agent_instance_id)`,
				`CREATE INDEX IF NOT EXISTS idx_audit_policy_id ON audit_events(policy_id)`,
				`CREATE INDEX IF NOT EXISTS idx_audit_tool_name ON audit_events(tool_name)`,
			} {
				if _, err := ex.Exec(idx); err != nil {
					return fmt.Errorf("create correlation index: %w", err)
				}
			}
			return nil
		},
	},
	{
		// v7 observability Phase 1 (Track 0 pre-allocation):
		// stamp provenance + three-tier agent identity onto every
		// audit row and judge response. Parallel work tracks (1-10)
		// land the *writers* for these columns; Track 0 only
		// declares the schema so no downstream migration is needed
		// when each track merges.
		description: "v7: add provenance + agent_id + sidecar_instance_id columns",
		apply: func(ex dbExecer) error {
			for _, spec := range []struct {
				table, column, stmt string
			}{
				{"audit_events", "schema_version", `ALTER TABLE audit_events ADD COLUMN schema_version INTEGER`},
				{"audit_events", "content_hash", `ALTER TABLE audit_events ADD COLUMN content_hash TEXT`},
				{"audit_events", "generation", `ALTER TABLE audit_events ADD COLUMN generation INTEGER`},
				{"audit_events", "binary_version", `ALTER TABLE audit_events ADD COLUMN binary_version TEXT`},
				{"audit_events", "agent_id", `ALTER TABLE audit_events ADD COLUMN agent_id TEXT`},
				{"audit_events", "sidecar_instance_id", `ALTER TABLE audit_events ADD COLUMN sidecar_instance_id TEXT`},
				{"judge_responses", "schema_version", `ALTER TABLE judge_responses ADD COLUMN schema_version INTEGER`},
				{"judge_responses", "content_hash", `ALTER TABLE judge_responses ADD COLUMN content_hash TEXT`},
				{"judge_responses", "generation", `ALTER TABLE judge_responses ADD COLUMN generation INTEGER`},
				{"judge_responses", "binary_version", `ALTER TABLE judge_responses ADD COLUMN binary_version TEXT`},
				{"judge_responses", "agent_id", `ALTER TABLE judge_responses ADD COLUMN agent_id TEXT`},
				{"judge_responses", "sidecar_instance_id", `ALTER TABLE judge_responses ADD COLUMN sidecar_instance_id TEXT`},
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
				`CREATE INDEX IF NOT EXISTS idx_audit_agent_id ON audit_events(agent_id)`,
				`CREATE INDEX IF NOT EXISTS idx_audit_generation ON audit_events(generation)`,
				`CREATE INDEX IF NOT EXISTS idx_audit_sidecar_instance_id ON audit_events(sidecar_instance_id)`,
			} {
				if _, err := ex.Exec(idx); err != nil {
					return fmt.Errorf("create v7 index: %w", err)
				}
			}
			return nil
		},
	},
	{
		// v7 observability Phase 2 (Track 0 pre-allocation):
		// scan_findings table is the per-finding row store that
		// backs EventScanFinding. scan_results becomes the summary
		// table (1 row per scan); scan_findings becomes a 1:N
		// detail table (N rows per scan). Tracks 1/2/3 (skill,
		// plugin, mcp scanners) insert into both tables.
		//
		// rule_id + line_number are added to findings (legacy
		// table) so downstream dashboards don't have to special-
		// case old vs new scans.
		description: "v7: add scan_findings detail table + rule_id/line_number on findings",
		apply: func(ex dbExecer) error {
			if _, err := ex.Exec(`
			CREATE TABLE IF NOT EXISTS scan_findings (
				id TEXT PRIMARY KEY,
				scan_id TEXT NOT NULL,
				scanner TEXT NOT NULL,
				target TEXT NOT NULL,
				rule_id TEXT,
				category TEXT,
				severity TEXT NOT NULL,
				title TEXT,
				description TEXT,
				location TEXT,
				line_number INTEGER,
				remediation TEXT,
				tags TEXT,
				timestamp DATETIME NOT NULL,
				run_id TEXT,
				request_id TEXT,
				session_id TEXT,
				agent_id TEXT,
				agent_instance_id TEXT,
				sidecar_instance_id TEXT,
				schema_version INTEGER,
				content_hash TEXT,
				generation INTEGER,
				binary_version TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id ON scan_findings(scan_id);
			CREATE INDEX IF NOT EXISTS idx_scan_findings_scanner ON scan_findings(scanner);
			CREATE INDEX IF NOT EXISTS idx_scan_findings_severity ON scan_findings(severity);
			CREATE INDEX IF NOT EXISTS idx_scan_findings_rule_id ON scan_findings(rule_id);
			CREATE INDEX IF NOT EXISTS idx_scan_findings_timestamp ON scan_findings(timestamp);
			CREATE INDEX IF NOT EXISTS idx_scan_findings_agent_id ON scan_findings(agent_id);
			`); err != nil {
				return fmt.Errorf("create scan_findings: %w", err)
			}
			for _, spec := range []struct {
				table, column, stmt string
			}{
				{"findings", "rule_id", `ALTER TABLE findings ADD COLUMN rule_id TEXT`},
				{"findings", "line_number", `ALTER TABLE findings ADD COLUMN line_number INTEGER`},
				{"scan_results", "verdict", `ALTER TABLE scan_results ADD COLUMN verdict TEXT`},
				{"scan_results", "exit_code", `ALTER TABLE scan_results ADD COLUMN exit_code INTEGER`},
				{"scan_results", "error", `ALTER TABLE scan_results ADD COLUMN error TEXT`},
			} {
				// Some upgrade paths (pre-migration-1 databases)
				// never created the legacy `findings` table; skip
				// the alter if the table simply doesn't exist.
				present, err := tableExists(ex, spec.table)
				if err != nil {
					return err
				}
				if !present {
					continue
				}
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
			return nil
		},
	},
	{
		// v7 observability Phase 3 (Track 0 pre-allocation):
		// activity_events is the SQLite store for EventActivity.
		// Every operator mutation (policy reload, config save,
		// block/allow change, skill approval, sink update) lands
		// here with a full before/after JSON snapshot + structured
		// diff. Track 6 (activity tracking) is the primary writer;
		// other tracks emit via audit.Logger.LogActivity.
		description: "v7: add activity_events table for operator mutations",
		apply: func(ex dbExecer) error {
			_, err := ex.Exec(`
			CREATE TABLE IF NOT EXISTS activity_events (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				actor TEXT NOT NULL,
				action TEXT NOT NULL,
				target_type TEXT NOT NULL,
				target_id TEXT NOT NULL,
				reason TEXT,
				before_json TEXT,
				after_json TEXT,
				diff_json TEXT,
				version_from TEXT,
				version_to TEXT,
				request_id TEXT,
				trace_id TEXT,
				run_id TEXT,
				schema_version INTEGER,
				content_hash TEXT,
				generation INTEGER,
				binary_version TEXT,
				agent_id TEXT,
				sidecar_instance_id TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_events(timestamp);
			CREATE INDEX IF NOT EXISTS idx_activity_actor ON activity_events(actor);
			CREATE INDEX IF NOT EXISTS idx_activity_action ON activity_events(action);
			CREATE INDEX IF NOT EXISTS idx_activity_target ON activity_events(target_type, target_id);
			CREATE INDEX IF NOT EXISTS idx_activity_generation ON activity_events(generation);
			`)
			return err
		},
	},
	{
		// v7 observability Phase 4 (Track 0 pre-allocation):
		// sink_health is an audit store of every audit sink
		// delivery attempt outcome — batches delivered, batches
		// dropped, circuit breaker transitions, queue full events.
		// Track 7 (external integrations) is the primary writer.
		// The table intentionally keeps per-attempt rows so
		// on-call can see the exact batch that tripped a sink
		// into failing rather than rolled-up counters.
		description: "v7: add sink_health table for audit_sink delivery telemetry",
		apply: func(ex dbExecer) error {
			_, err := ex.Exec(`
			CREATE TABLE IF NOT EXISTS sink_health (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				sink_name TEXT NOT NULL,
				sink_kind TEXT NOT NULL,
				outcome TEXT NOT NULL,
				status_code INTEGER,
				latency_ms INTEGER,
				batch_size INTEGER,
				error TEXT,
				queue_depth INTEGER,
				dropped_count INTEGER,
				schema_version INTEGER,
				content_hash TEXT,
				generation INTEGER,
				binary_version TEXT,
				sidecar_instance_id TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_sink_health_timestamp ON sink_health(timestamp);
			CREATE INDEX IF NOT EXISTS idx_sink_health_sink ON sink_health(sink_name);
			CREATE INDEX IF NOT EXISTS idx_sink_health_outcome ON sink_health(outcome);
			`)
			return err
		},
	},
	{
		// v7 observability Phase 5 (Track 0 pre-allocation):
		// lift schema_version / content_hash / generation /
		// binary_version onto the remaining correlated tables so
		// the whole audit database snapshots provenance
		// consistently. Actions + snapshots get them so a config
		// mutation and its resulting scans can be joined by
		// content_hash even if run_id was missed.
		description: "v7: extend actions, snapshots, network_egress with provenance",
		apply: func(ex dbExecer) error {
			tables := []string{"actions", "target_snapshots", "network_egress_events"}
			cols := []struct {
				name, typ string
			}{
				{"schema_version", "INTEGER"},
				{"content_hash", "TEXT"},
				{"generation", "INTEGER"},
				{"binary_version", "TEXT"},
				{"sidecar_instance_id", "TEXT"},
			}
			for _, t := range tables {
				present, err := tableExists(ex, t)
				if err != nil {
					return err
				}
				if !present {
					continue
				}
				for _, c := range cols {
					exists, err := hasColumnDB(ex, t, c.name)
					if err != nil {
						return err
					}
					if !exists {
						stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", t, c.name, c.typ)
						if _, err := ex.Exec(stmt); err != nil {
							return fmt.Errorf("alter %s.%s: %w", t, c.name, err)
						}
					}
				}
			}
			return nil
		},
	},
	{
		// v7 observability Phase 6 (Track 0 pre-allocation):
		// scan_results gets the same provenance quartet +
		// agent_id / sidecar_instance_id so a per-scan aggregate
		// can be drawn up in SQL without joining back to
		// audit_events just to find which sidecar emitted the
		// scan.
		description: "v7: extend scan_results + findings with provenance + agent identity",
		apply: func(ex dbExecer) error {
			extras := []struct {
				table, column, typ string
			}{
				{"scan_results", "schema_version", "INTEGER"},
				{"scan_results", "content_hash", "TEXT"},
				{"scan_results", "generation", "INTEGER"},
				{"scan_results", "binary_version", "TEXT"},
				{"scan_results", "agent_id", "TEXT"},
				{"scan_results", "agent_instance_id", "TEXT"},
				{"scan_results", "sidecar_instance_id", "TEXT"},
				{"scan_results", "session_id", "TEXT"},
				{"scan_results", "request_id", "TEXT"},
				{"scan_results", "trace_id", "TEXT"},
				{"findings", "schema_version", "INTEGER"},
				{"findings", "content_hash", "TEXT"},
				{"findings", "generation", "INTEGER"},
				{"findings", "binary_version", "TEXT"},
				{"findings", "agent_id", "TEXT"},
				{"findings", "sidecar_instance_id", "TEXT"},
			}
			for _, c := range extras {
				present, err := tableExists(ex, c.table)
				if err != nil {
					return err
				}
				if !present {
					continue
				}
				exists, err := hasColumnDB(ex, c.table, c.column)
				if err != nil {
					return err
				}
				if !exists {
					stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", c.table, c.column, c.typ)
					if _, err := ex.Exec(stmt); err != nil {
						return fmt.Errorf("alter %s.%s: %w", c.table, c.column, err)
					}
				}
			}
			for _, idx := range []string{
				`CREATE INDEX IF NOT EXISTS idx_scan_agent_id ON scan_results(agent_id)`,
				`CREATE INDEX IF NOT EXISTS idx_scan_generation ON scan_results(generation)`,
			} {
				if _, err := ex.Exec(idx); err != nil {
					return fmt.Errorf("create v7 scan index: %w", err)
				}
			}
			// findings table may not exist in pre-migration-1 upgrades.
			if ok, _ := tableExists(ex, "findings"); ok {
				if _, err := ex.Exec(`CREATE INDEX IF NOT EXISTS idx_findings_agent_id ON findings(agent_id)`); err != nil {
					return fmt.Errorf("create findings.agent_id index: %w", err)
				}
			}
			return nil
		},
	},
	{
		// Track 3: complete judge_responses correlation for v7 SIEM joins
		// (session, policy, tool context, full three-tier identity).
		description: "v7: extend judge_responses with session/policy/tool/agent_instance",
		apply: func(ex dbExecer) error {
			for _, spec := range []struct {
				table, column, stmt string
			}{
				{"judge_responses", "session_id", `ALTER TABLE judge_responses ADD COLUMN session_id TEXT`},
				{"judge_responses", "agent_instance_id", `ALTER TABLE judge_responses ADD COLUMN agent_instance_id TEXT`},
				{"judge_responses", "policy_id", `ALTER TABLE judge_responses ADD COLUMN policy_id TEXT`},
				{"judge_responses", "destination_app", `ALTER TABLE judge_responses ADD COLUMN destination_app TEXT`},
				{"judge_responses", "tool_name", `ALTER TABLE judge_responses ADD COLUMN tool_name TEXT`},
				{"judge_responses", "tool_id", `ALTER TABLE judge_responses ADD COLUMN tool_id TEXT`},
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
			return nil
		},
	},
	{
		// Sliding-window correlator enrichment: six columns on
		// scan_findings so the correlator can intersect lethal-
		// trifecta axes across a session's recent findings without
		// reaching back into the cleartext content.
		//
		//   data_axis               — CSV of ingress_untrusted /
		//                             sensitive_access / egress_external
		//   tool_capability_class   — read_fs / write_fs / exec_shell /
		//                             network_fetch / send_message
		//   content_fingerprint     — sha256(redacted_value)[:8]
		//   external_endpoint       — host or URL for network findings
		//   turn_id                 — monotonic per-session counter
		//   decision_path           — JSON audit trail of severity
		//                             derivation (regex match, judge
		//                             category, sensitive-context boost,
		//                             rubric reconciliation)
		description: "correlator: enrich scan_findings with axis/capability/fingerprint/endpoint/turn/path",
		apply: func(ex dbExecer) error {
			present, err := tableExists(ex, "scan_findings")
			if err != nil {
				return err
			}
			if !present {
				return nil
			}
			for _, spec := range []struct {
				table, column, stmt string
			}{
				{"scan_findings", "data_axis", `ALTER TABLE scan_findings ADD COLUMN data_axis TEXT`},
				{"scan_findings", "tool_capability_class", `ALTER TABLE scan_findings ADD COLUMN tool_capability_class TEXT`},
				{"scan_findings", "content_fingerprint", `ALTER TABLE scan_findings ADD COLUMN content_fingerprint TEXT`},
				{"scan_findings", "external_endpoint", `ALTER TABLE scan_findings ADD COLUMN external_endpoint TEXT`},
				{"scan_findings", "turn_id", `ALTER TABLE scan_findings ADD COLUMN turn_id INTEGER`},
				{"scan_findings", "decision_path", `ALTER TABLE scan_findings ADD COLUMN decision_path TEXT`},
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
			if _, err := ex.Exec(
				`CREATE INDEX IF NOT EXISTS idx_scan_findings_session_turn ` +
					`ON scan_findings(session_id, agent_instance_id, turn_id)`,
			); err != nil {
				return fmt.Errorf("create idx_scan_findings_session_turn: %w", err)
			}
			return nil
		},
	},
	{
		// First-class structured audit payloads. Hook outcomes used
		// to expose their JSON envelope only as an escaped
		// details_json= token inside the legacy details string. The
		// details column remains for backwards compatibility, but
		// structured_json is now the machine-readable contract for
		// audit sinks and export.
		description: "audit: add structured_json payload column",
		apply: func(ex dbExecer) error {
			present, err := tableExists(ex, "audit_events")
			if err != nil {
				return err
			}
			if !present {
				return nil
			}
			exists, err := hasColumnDB(ex, "audit_events", "structured_json")
			if err != nil {
				return err
			}
			if !exists {
				if _, err := ex.Exec(`ALTER TABLE audit_events ADD COLUMN structured_json TEXT`); err != nil {
					return fmt.Errorf("alter audit_events.structured_json: %w", err)
				}
			}
			return nil
		},
	},
	{
		// Unified runtime finding pipeline: scan_findings.confidence
		// captures the regex / judge / AID detector self-reported
		// score (0..1) so SIEM can rank by certainty alongside
		// severity. evaluation_id on both scan_results and
		// scan_findings joins each row to the upstream runtime
		// evaluation (hook, /api/v1/inspect/*, proxy guardrail,
		// mid-stream, tool-call-inspect, watcher rescan) that
		// produced it. Classic scanner-invocation paths leave
		// evaluation_id NULL.
		description: "runtime findings: add confidence + evaluation_id to scan_results/scan_findings",
		apply: func(ex dbExecer) error {
			present, err := tableExists(ex, "scan_findings")
			if err != nil {
				return err
			}
			if present {
				for _, spec := range []struct {
					table, column, stmt string
				}{
					{"scan_findings", "confidence", `ALTER TABLE scan_findings ADD COLUMN confidence REAL`},
					{"scan_findings", "evaluation_id", `ALTER TABLE scan_findings ADD COLUMN evaluation_id TEXT`},
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
				if _, err := ex.Exec(
					`CREATE INDEX IF NOT EXISTS idx_scan_findings_evaluation_id ` +
						`ON scan_findings(evaluation_id)`,
				); err != nil {
					return fmt.Errorf("create idx_scan_findings_evaluation_id: %w", err)
				}
			}
			summaryPresent, err := tableExists(ex, "scan_results")
			if err != nil {
				return err
			}
			if summaryPresent {
				exists, err := hasColumnDB(ex, "scan_results", "evaluation_id")
				if err != nil {
					return err
				}
				if !exists {
					if _, err := ex.Exec(
						`ALTER TABLE scan_results ADD COLUMN evaluation_id TEXT`,
					); err != nil {
						return fmt.Errorf("alter scan_results.evaluation_id: %w", err)
					}
				}
				if _, err := ex.Exec(
					`CREATE INDEX IF NOT EXISTS idx_scan_results_evaluation_id ` +
						`ON scan_results(evaluation_id)`,
				); err != nil {
					return fmt.Errorf("create idx_scan_results_evaluation_id: %w", err)
				}
			}
			return nil
		},
	},
	{
		// The watcher's periodic re-scan stores a baseline content hash
		// per target. Adding the scanner_fingerprint lets the watcher
		// invalidate that baseline when the scanner binary, ruleset, or
		// scan-affecting config changes — so an upgraded scanner re-runs
		// even on byte-identical content, while unchanged content + an
		// unchanged scanner is skipped entirely.
		description: "watcher: add scanner_fingerprint to target_snapshots for drift-gated rescans",
		apply: func(ex dbExecer) error {
			present, err := tableExists(ex, "target_snapshots")
			if err != nil {
				return err
			}
			if !present {
				return nil
			}
			exists, err := hasColumnDB(ex, "target_snapshots", "scanner_fingerprint")
			if err != nil {
				return err
			}
			if !exists {
				if _, err := ex.Exec(
					`ALTER TABLE target_snapshots ADD COLUMN scanner_fingerprint TEXT NOT NULL DEFAULT ''`,
				); err != nil {
					return fmt.Errorf("alter target_snapshots.scanner_fingerprint: %w", err)
				}
			}
			return nil
		},
	},
	{
		// Multi-connector support: per-connector identity + per-turn
		// counter + enforcement + rule-pack provenance on every audit
		// row. All columns are additive and optional — the ADD COLUMNs
		// are guarded by hasColumnDB so re-running Init on an
		// already-migrated DB is a no-op, and legacy rows keep their
		// existing values with the new columns left NULL. This
		// migration does NOT touch version.SchemaVersion (the v7
		// provenance envelope constant); these are optional fields, not
		// a breaking envelope change.
		description: "multi-connector: add connector + step_idx + enforced + rule_pack_dir columns",
		apply: func(ex dbExecer) error {
			for _, spec := range []struct {
				table, column, stmt string
			}{
				{"audit_events", "connector", `ALTER TABLE audit_events ADD COLUMN connector TEXT`},
				{"audit_events", "step_idx", `ALTER TABLE audit_events ADD COLUMN step_idx INTEGER`},
				{"audit_events", "enforced", `ALTER TABLE audit_events ADD COLUMN enforced INTEGER`},
				{"audit_events", "rule_pack_dir", `ALTER TABLE audit_events ADD COLUMN rule_pack_dir TEXT`},
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
			// Connector is the primary new query dimension (per-connector
			// dashboards, TUI filter chips); index it. step_idx is
			// usually filtered alongside connector or session_id, so no
			// standalone index is warranted yet.
			if _, err := ex.Exec(
				`CREATE INDEX IF NOT EXISTS idx_audit_connector ON audit_events(connector)`,
			); err != nil {
				return fmt.Errorf("create idx_audit_connector: %w", err)
			}
			return nil
		},
	},
	{
		// SK-4 foundation: per-connector scoping for the actions
		// (enforcement) table. Adds an additive connector column and swaps
		// the uniqueness index from (target_type, target_name) to
		// (target_type, target_name, connector), so a target can carry one
		// global entry (connector='') plus one entry per connector.
		//
		// Back-compat anchor: existing rows keep connector='' via the column
		// DEFAULT, meaning global / applies to every connector — so every
		// pre-existing block/allow stays in force after the upgrade. The
		// ADD COLUMN is guarded by hasColumnDB and the index statements use
		// IF EXISTS / IF NOT EXISTS, so re-running Init on an already-migrated
		// DB is a no-op. Mirrors _ensure_connector_column in
		// cli/defenseclaw/db.py. Like the multi-connector audit_events
		// migration above, this does NOT bump version.SchemaVersion — these
		// are additive schema changes, not a breaking envelope change.
		description: "multi-connector: per-connector column on actions + 3-col unique index",
		apply: func(ex dbExecer) error {
			present, err := tableExists(ex, "actions")
			if err != nil {
				return err
			}
			if !present {
				return nil
			}
			exists, err := hasColumnDB(ex, "actions", "connector")
			if err != nil {
				return err
			}
			if !exists {
				if _, err := ex.Exec(
					`ALTER TABLE actions ADD COLUMN connector TEXT NOT NULL DEFAULT ''`,
				); err != nil {
					return fmt.Errorf("alter actions.connector: %w", err)
				}
			}
			// Swap the legacy 2-column uniqueness index for the
			// connector-aware one. DROP first so an upgraded DB cannot keep
			// both (the old one would reject per-connector rows).
			if _, err := ex.Exec(`DROP INDEX IF EXISTS idx_actions_type_name`); err != nil {
				return fmt.Errorf("drop idx_actions_type_name: %w", err)
			}
			if _, err := ex.Exec(
				`CREATE UNIQUE INDEX IF NOT EXISTS idx_actions_type_name_conn ` +
					`ON actions(target_type, target_name, connector)`,
			); err != nil {
				return fmt.Errorf("create idx_actions_type_name_conn: %w", err)
			}
			return nil
		},
	},
}

// tableExists reports whether the given SQLite table is present.
// Safe to call inside a migration transaction; the query targets
// sqlite_master so it reflects changes made earlier in the same tx.
func tableExists(ex dbExecer, table string) (bool, error) {
	var count int
	err := ex.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("audit: sqlite_master lookup for %q: %w", table, err)
	}
	return count > 0, nil
}

func (s *Store) Init() error {
	// Ensure the schema_version tracking table exists.
	if _, err := s.execDB(context.Background(), "audit", `CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL
	)`); err != nil {
		return fmt.Errorf("audit: create schema_version table: %w", err)
	}

	current := 0
	row := s.db.QueryRowContext(context.Background(), `SELECT COALESCE(MAX(version), 0) FROM schema_version`)
	if err := s.scanRow(context.Background(), "schema_version_peek", row, &current); err != nil {
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
	if _, err := txExec(tx, "migration_version_insert", `INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`,
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
	err := s.scanRow(context.Background(), "schema_version",
		s.db.QueryRowContext(context.Background(), `SELECT COALESCE(MAX(version), 0) FROM schema_version`), &v)
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
	"findings":              true,
	"actions":               true,
	"target_snapshots":      true,
	"network_egress_events": true,
	"judge_responses":       true,
	"schema_version":        true,
	// v7 additions
	"scan_findings":   true,
	"activity_events": true,
	"sink_health":     true,
}

func (s *Store) hasColumn(table, column string) (bool, error) {
	if !knownTables[table] {
		return false, fmt.Errorf("audit: hasColumn called with unknown table %q", table)
	}
	rows, err := s.queryDB(context.Background(), "audit", fmt.Sprintf("PRAGMA table_info(%s)", table))
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

	// v7: stamp the provenance quartet + the per-process sidecar UUID
	// at the one true choke point for audit_events. This is the
	// analogue of gatewaylog.Writer.Emit's StampProvenance — callers
	// that forgot (or never knew about) the envelope still produce a
	// fully-populated SQLite row. The snapshot is always taken from
	// version.Current() so a single wire run shows consistent
	// schema/content/generation across every event; pre-stamped
	// callers keep their values so historical replays stay stable.
	prov := version.Current()
	if e.SchemaVersion == 0 {
		e.SchemaVersion = prov.SchemaVersion
	}
	if e.ContentHash == "" {
		e.ContentHash = prov.ContentHash
	}
	if e.Generation == 0 {
		e.Generation = prov.Generation
	}
	if e.BinaryVersion == "" {
		e.BinaryVersion = prov.BinaryVersion
	}
	if e.SidecarInstanceID == "" {
		e.SidecarInstanceID = ProcessAgentInstanceID()
	}

	structuredJSON, err := encodeStructuredPayload(e.Structured)
	if err != nil {
		return fmt.Errorf("audit: marshal structured payload: %w", err)
	}

	ts := e.Timestamp.Format(time.RFC3339Nano)
	_, err = s.execDB(context.Background(), "audit",
		`INSERT INTO audit_events (id, timestamp, action, target, actor, details, structured_json, severity,
			run_id, trace_id, request_id,
			session_id, agent_name, agent_instance_id, policy_id, destination_app, tool_name, tool_id,
			schema_version, content_hash, generation, binary_version, agent_id, sidecar_instance_id,
			connector, step_idx, enforced, rule_pack_dir)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, ts, e.Action, e.Target, e.Actor, e.Details, structuredJSON, e.Severity,
		nullStr(e.RunID), nullStr(e.TraceID), nullStr(e.RequestID),
		nullStr(e.SessionID), nullStr(e.AgentName), nullStr(e.AgentInstanceID),
		nullStr(e.PolicyID), nullStr(e.DestinationApp), nullStr(e.ToolName), nullStr(e.ToolID),
		nullInt(e.SchemaVersion), nullStr(e.ContentHash), nullUint64(e.Generation),
		nullStr(e.BinaryVersion), nullStr(e.AgentID), nullStr(e.SidecarInstanceID),
		nullStr(e.Connector), nullInt(e.StepIdx), nullBool(e.Enforced),
		nullStr(e.RulePackDir),
	)
	if err != nil {
		return fmt.Errorf("audit: log event: %w", err)
	}
	return nil
}

// ActivityEventRow is the SQLite shape for migration #8 activity_events.
type ActivityEventRow struct {
	ID                string    `json:"id"`
	Timestamp         time.Time `json:"timestamp"`
	Actor             string    `json:"actor"`
	Action            string    `json:"action"`
	TargetType        string    `json:"target_type"`
	TargetID          string    `json:"target_id"`
	Reason            string    `json:"reason,omitempty"`
	BeforeJSON        string    `json:"before_json,omitempty"`
	AfterJSON         string    `json:"after_json,omitempty"`
	DiffJSON          string    `json:"diff_json,omitempty"`
	VersionFrom       string    `json:"version_from,omitempty"`
	VersionTo         string    `json:"version_to,omitempty"`
	RequestID         string    `json:"request_id,omitempty"`
	TraceID           string    `json:"trace_id,omitempty"`
	RunID             string    `json:"run_id,omitempty"`
	SchemaVersion     int       `json:"schema_version,omitempty"`
	ContentHash       string    `json:"content_hash,omitempty"`
	Generation        uint64    `json:"generation,omitempty"`
	BinaryVersion     string    `json:"binary_version,omitempty"`
	AgentID           string    `json:"agent_id,omitempty"`
	SidecarInstanceID string    `json:"sidecar_instance_id,omitempty"`
}

// InsertActivityEvent persists a full operator mutation row (no redaction).
func (s *Store) InsertActivityEvent(a ActivityEventRow) error {
	if a.ID == "" {
		return fmt.Errorf("audit: activity id required")
	}
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now().UTC()
	}
	if a.RunID == "" {
		a.RunID = currentRunID()
	}
	_, err := s.execDB(context.Background(), "audit",
		`INSERT INTO activity_events (
			id, timestamp, actor, action, target_type, target_id, reason,
			before_json, after_json, diff_json, version_from, version_to,
			request_id, trace_id, run_id,
			schema_version, content_hash, generation, binary_version,
			agent_id, sidecar_instance_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Timestamp.Format(time.RFC3339Nano),
		a.Actor, a.Action, a.TargetType, a.TargetID, anyString(a.Reason),
		anyString(a.BeforeJSON), anyString(a.AfterJSON), anyString(a.DiffJSON),
		anyString(a.VersionFrom), anyString(a.VersionTo),
		anyString(a.RequestID), anyString(a.TraceID), anyString(a.RunID),
		nullInt(a.SchemaVersion), anyString(a.ContentHash), nullUint64(a.Generation),
		anyString(a.BinaryVersion), anyString(a.AgentID), anyString(a.SidecarInstanceID),
	)
	if err != nil {
		return fmt.Errorf("audit: insert activity event: %w", err)
	}
	return nil
}

// SinkHealthInput is one row in sink_health (migration #9).
type SinkHealthInput struct {
	ID                string
	Timestamp         time.Time
	SinkName          string
	SinkKind          string
	Outcome           string // delivered | failed | dropped_queue | dropped_circuit
	StatusCode        int    // HTTP status; 0 → NULL
	LatencyMs         int64
	BatchSize         int
	Error             string
	QueueDepth        int
	DroppedCount      int
	SchemaVersion     int
	ContentHash       string
	Generation        uint64
	BinaryVersion     string
	SidecarInstanceID string
}

// InsertSinkHealth records a single sink delivery attempt outcome.
func (s *Store) InsertSinkHealth(h SinkHealthInput) error {
	if h.ID == "" {
		h.ID = uuid.New().String()
	}
	if h.Timestamp.IsZero() {
		h.Timestamp = time.Now().UTC()
	}
	var status sql.NullInt64
	if h.StatusCode > 0 {
		status = sql.NullInt64{Int64: int64(h.StatusCode), Valid: true}
	}
	_, err := s.execDB(context.Background(), "audit",
		`INSERT INTO sink_health (
			id, timestamp, sink_name, sink_kind, outcome,
			status_code, latency_ms, batch_size, error,
			queue_depth, dropped_count,
			schema_version, content_hash, generation, binary_version,
			sidecar_instance_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.Timestamp.Format(time.RFC3339Nano),
		h.SinkName, h.SinkKind, h.Outcome,
		status, h.LatencyMs, h.BatchSize, anyString(h.Error),
		nullInt(h.QueueDepth), nullInt(h.DroppedCount),
		nullInt(h.SchemaVersion), nullStr(h.ContentHash), nullUint64(h.Generation),
		nullStr(h.BinaryVersion), nullStr(h.SidecarInstanceID),
	)
	if err != nil {
		return fmt.Errorf("audit: insert sink health: %w", err)
	}
	return nil
}

// ListActivityEvents returns recent activity rows, newest first.
func (s *Store) ListActivityEvents(limit int) ([]ActivityEventRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.queryDB(context.Background(), "audit", `
		SELECT id, timestamp, actor, action, target_type, target_id, COALESCE(reason,''),
			COALESCE(before_json,''), COALESCE(after_json,''), COALESCE(diff_json,''),
			COALESCE(version_from,''), COALESCE(version_to,''),
			COALESCE(request_id,''), COALESCE(trace_id,''), COALESCE(run_id,''),
			COALESCE(schema_version,0), COALESCE(content_hash,''), COALESCE(generation,0),
			COALESCE(binary_version,''), COALESCE(agent_id,''), COALESCE(sidecar_instance_id,'')
		FROM activity_events ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list activity events: %w", err)
	}
	defer rows.Close()

	var out []ActivityEventRow
	for rows.Next() {
		var a ActivityEventRow
		var ts string
		var gen sql.NullInt64
		var schema sql.NullInt64
		if err := rows.Scan(
			&a.ID, &ts, &a.Actor, &a.Action, &a.TargetType, &a.TargetID, &a.Reason,
			&a.BeforeJSON, &a.AfterJSON, &a.DiffJSON,
			&a.VersionFrom, &a.VersionTo,
			&a.RequestID, &a.TraceID, &a.RunID,
			&schema, &a.ContentHash, &gen,
			&a.BinaryVersion, &a.AgentID, &a.SidecarInstanceID,
		); err != nil {
			return nil, fmt.Errorf("audit: scan activity: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			a.Timestamp = t
		}
		if schema.Valid {
			a.SchemaVersion = int(schema.Int64)
		}
		if gen.Valid {
			a.Generation = uint64(gen.Int64)
		}
		out = append(out, a)
	}
	return out, rows.Err()
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

	// Correlation + forensics fields (Phase 3/5). All are optional
	// at the call site — empty values persist as NULL so the audit
	// store stays usable for older callers (migration tests, ad-hoc
	// scripts) that haven't been updated yet.
	RequestID         string
	TraceID           string
	RunID             string
	SessionID         string
	InputHash         string  // sha256 of the judge input, never the raw input
	Confidence        float64 // 0–1 score, 0 when the judge did not return one
	FailClosedApplied bool    // set when a judge parse/timeout error forced a block
	InspectedModel    string  // the upstream model whose traffic we judged
	PromptTemplateID  string  // optional template identifier for drift diagnosis

	// v7 provenance + identity (Track 3 writer)
	SchemaVersion     int
	ContentHash       string
	Generation        uint64
	BinaryVersion     string
	AgentID           string
	AgentInstanceID   string
	SidecarInstanceID string
	PolicyID          string
	DestinationApp    string
	ToolName          string
	ToolID            string
}

// MaxJudgeRawBytes is the upper bound on the raw_response body
// stored in SQLite. Judge models occasionally echo entire
// conversation histories (we've seen >1MB); without a cap, a
// runaway response can bloat the audit DB by gigabytes and
// degrade query performance. 64KiB keeps every realistic
// detection trace intact while preventing pathological blowup.
const MaxJudgeRawBytes = 64 * 1024

// JudgeBatch is the *sql.Tx-backed batch handle returned from
// Store.BeginJudgeBatch. Exported so the gateway worker can declare
// its dependency on the concrete type without an internal-only
// import path. We deliberately do NOT expose the *sql.Tx itself —
// the interface stays tight (Insert / Commit / Rollback) so future
// callers cannot accidentally mix in random queries that defeat
// the per-batch fsync-amortization guarantee.
type JudgeBatch struct {
	tx        *sql.Tx
	committed bool
}

// InsertJudgeResponse writes one row inside the transaction. The
// statement is identical to the single-row path above so any future
// column additions only need updating in one place. We keep this
// method intentionally close to InsertJudgeResponse so reviewers can
// see the parity at a glance.
func (b *JudgeBatch) InsertJudgeResponse(e JudgeResponse) error {
	if b == nil || b.tx == nil {
		return fmt.Errorf("audit: judge batch handle is nil")
	}
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
	if _, err := txExec(b.tx, "audit_batch_insert",
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
	); err != nil {
		return fmt.Errorf("audit: judge batch insert: %w", err)
	}
	return nil
}

// Commit closes the transaction. We only flip b.committed=true on
// SUCCESS; a failed Commit leaves the handle in a state where the
// caller's Rollback() will still drive tx.Rollback() to release the
// connection. Without that order the connection can stay pinned in
// "transaction-in-progress" mode until the *sql.DB pool closes the
// underlying connection, blocking subsequent writes.
//
// After a successful Commit, every subsequent Commit/Rollback call
// on this handle is a no-op so a buggy caller cannot accidentally
// double-commit.
func (b *JudgeBatch) Commit() error {
	if b == nil || b.tx == nil {
		return fmt.Errorf("audit: judge batch handle is nil")
	}
	if b.committed {
		return nil
	}
	if err := b.tx.Commit(); err != nil {
		return err
	}
	b.committed = true
	return nil
}

// Rollback is the cleanup path on commit failure or per-row error.
// Idempotent so the worker can call it without tracking whether
// Commit already ran successfully (in which case Rollback is a
// no-op). When Commit FAILED, b.committed stays false and we
// genuinely drive tx.Rollback() — which is the bug-fix that keeps
// the SQLite connection from being pinned mid-tx.
func (b *JudgeBatch) Rollback() error {
	if b == nil || b.tx == nil {
		return nil
	}
	if b.committed {
		return nil
	}
	// Mark committed BEFORE calling tx.Rollback so a concurrent
	// retry (or a buggy double-call) doesn't fire two rollbacks
	// on the same handle, which would surface as
	// "sql: transaction has already been committed or rolled back".
	b.committed = true
	return b.tx.Rollback()
}

// BeginJudgeBatch opens a transaction dedicated to a single batch of
// judge_responses inserts. The gateway's async writer goroutine uses
// this to amortize SQLite's per-tx fsync over up to 32 rows.
//
// We return a typed handle so the worker can keep its loop tight:
// InsertJudgeResponse + Commit/Rollback are the only operations
// needed.
func (s *Store) BeginJudgeBatch(ctx context.Context) (*JudgeBatch, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("audit: begin judge batch: %w", err)
	}
	return &JudgeBatch{tx: tx}, nil
}

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
	if e.RunID == "" {
		e.RunID = currentRunID()
	}
	raw := truncateJudgeRaw(e.Raw, MaxJudgeRawBytes)
	failClosed := 0
	if e.FailClosedApplied {
		failClosed = 1
	}
	_, err := s.execDB(context.Background(), "audit",
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
		nullUint64(e.Generation),
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
	rows, err := s.queryDB(context.Background(), "audit", `
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
		return nil, fmt.Errorf("audit: list judge responses: %w", err)
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
			return nil, fmt.Errorf("audit: scan judge response: %w", err)
		}
		r.Generation = uint64(gen)
		r.FailClosedApplied = failClosed != 0
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

// GetJudgeResponsesByRequestID returns every judge row tied to the
// supplied correlation ID, newest first. Used by the TUI Judge panel
// (Phase 4) to pivot from a verdict row into all the judge calls
// that contributed to it.
func (s *Store) GetJudgeResponsesByRequestID(requestID string) ([]JudgeResponse, error) {
	if requestID == "" {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "audit", `
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
		FROM judge_responses WHERE request_id = ? ORDER BY timestamp DESC`, requestID)
	if err != nil {
		return nil, fmt.Errorf("audit: judge by request_id: %w", err)
	}
	defer rows.Close()

	var out []JudgeResponse
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
			return nil, fmt.Errorf("audit: scan judge row: %w", err)
		}
		r.Generation = uint64(gen)
		r.FailClosedApplied = failClosed != 0
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			r.Timestamp = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) InsertScanResult(id, scannerName, target string, ts time.Time, durationMs int64, findingCount int, maxSeverity, rawJSON string) error {
	runID := currentRunID()
	_, err := s.execDB(context.Background(), "audit",
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
	_, err := s.execDB(context.Background(), "audit",
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

	rows, err := s.queryDB(context.Background(), "audit",
		`SELECT id, timestamp, action, target, actor, details, structured_json, severity,
		        run_id, trace_id, request_id,
		        session_id, agent_name, agent_instance_id, policy_id,
		        destination_app, tool_name, tool_id,
		        schema_version, content_hash, generation, binary_version,
		        agent_id, sidecar_instance_id,
		        connector, step_idx, enforced, rule_pack_dir
		 FROM audit_events ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		e, err := scanAuditEventRow(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// scanAuditEventRow centralises the column-scan logic for ListEvents
// and ListEventsByTarget so the Observability Phase 6 columns
// (session_id, agent_name, agent_instance_id, policy_id,
// destination_app, tool_name, tool_id) only have to be threaded
// through the struct in a single place.
func scanAuditEventRow(rows rowScanner) (Event, error) {
	var e Event
	var (
		target, details, structuredJSON, severity       sql.NullString
		runID, traceID, requestID                       sql.NullString
		sessionID, agentName, agentInstanceID, policyID sql.NullString
		destinationApp, toolName, toolID                sql.NullString
		schemaVerI                                      sql.NullInt64
		contentHashStr, binaryVerStr                    sql.NullString
		generation                                      sql.NullInt64
		agentID, sidecarInst                            sql.NullString
		connector, rulePackDir                          sql.NullString
		stepIdx, enforced                               sql.NullInt64
	)
	if err := rows.Scan(
		&e.ID, &e.Timestamp, &e.Action, &target, &e.Actor, &details, &structuredJSON, &severity,
		&runID, &traceID, &requestID,
		&sessionID, &agentName, &agentInstanceID, &policyID,
		&destinationApp, &toolName, &toolID,
		&schemaVerI, &contentHashStr, &generation, &binaryVerStr,
		&agentID, &sidecarInst,
		&connector, &stepIdx, &enforced, &rulePackDir,
	); err != nil {
		return Event{}, fmt.Errorf("audit: scan row: %w", err)
	}
	e.Target = target.String
	e.Details = details.String
	structured, err := decodeStructuredPayload(structuredJSON)
	if err != nil {
		return Event{}, err
	}
	e.Structured = structured
	e.Severity = severity.String
	e.RunID = runID.String
	e.TraceID = traceID.String
	e.RequestID = requestID.String
	e.SessionID = sessionID.String
	e.AgentName = agentName.String
	e.AgentInstanceID = agentInstanceID.String
	e.PolicyID = policyID.String
	e.DestinationApp = destinationApp.String
	e.ToolName = toolName.String
	e.ToolID = toolID.String
	if schemaVerI.Valid {
		e.SchemaVersion = int(schemaVerI.Int64)
	}
	if contentHashStr.Valid {
		e.ContentHash = contentHashStr.String
	}
	if generation.Valid {
		e.Generation = uint64(generation.Int64)
	}
	if binaryVerStr.Valid {
		e.BinaryVersion = binaryVerStr.String
	}
	if agentID.Valid {
		e.AgentID = agentID.String
	}
	if sidecarInst.Valid {
		e.SidecarInstanceID = sidecarInst.String
	}
	if connector.Valid {
		e.Connector = connector.String
	}
	if stepIdx.Valid {
		e.StepIdx = int(stepIdx.Int64)
	}
	if enforced.Valid {
		e.Enforced = enforced.Int64 == 1
	}
	if rulePackDir.Valid {
		e.RulePackDir = rulePackDir.String
	}
	return e, nil
}

// rowScanner lets scanAuditEventRow accept *sql.Rows from either
// ListEvents or ListEventsByTarget without importing database/sql at
// the call site.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// --- Actions ---

// SetAction upserts the full action state for a target's global
// (connector="") entry.
func (s *Store) SetAction(targetType, targetName, sourcePath string, state ActionState, reason string) error {
	return s.SetActionForConnector(targetType, targetName, "", sourcePath, state, reason)
}

// SetActionForConnector upserts the full action state for a target scoped to
// connector (connector="" = global). See ActionEntry.Connector (SK-4).
func (s *Store) SetActionForConnector(targetType, targetName, connector, sourcePath string, state ActionState, reason string) error {
	actionsJSON, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("audit: marshal actions: %w", err)
	}
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err = s.execDB(context.Background(), "audit",
		`INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at, connector)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(target_type, target_name, connector) DO UPDATE SET
		   actions_json = excluded.actions_json,
		   reason = excluded.reason,
		   updated_at = excluded.updated_at,
		   source_path = COALESCE(excluded.source_path, source_path)`,
		id, targetType, targetName, nullStr(sourcePath), string(actionsJSON), reason, now, connector,
	)
	if err != nil {
		return fmt.Errorf("audit: set action: %w", err)
	}
	return nil
}

// SetActionField updates a single action dimension on a target's global
// (connector="") entry without touching others.
func (s *Store) SetActionField(targetType, targetName, field, value, reason string) error {
	return s.SetActionFieldForConnector(targetType, targetName, "", field, value, reason)
}

// SetActionFieldForConnector updates a single action dimension scoped to
// connector (connector="" = global). See ActionEntry.Connector (SK-4).
func (s *Store) SetActionFieldForConnector(targetType, targetName, connector, field, value, reason string) error {
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
		`INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at, connector)
		 VALUES (?, ?, ?, NULL, ?, ?, ?, ?)
		 ON CONFLICT(target_type, target_name, connector) DO UPDATE SET
		   actions_json = json_set(actions_json, ?, ?),
		   reason = excluded.reason,
		   updated_at = excluded.updated_at`
	_, err := s.execDB(context.Background(), "audit", query, id, targetType, targetName, initJSON, reason, now, connector, path, value)
	if err != nil {
		return fmt.Errorf("audit: set action field %s: %w", field, err)
	}
	return nil
}

// SetSourcePath updates just the source_path for a target's global
// (connector="") action row.
func (s *Store) SetSourcePath(targetType, targetName, path string) error {
	return s.SetSourcePathForConnector(targetType, targetName, "", path)
}

// SetSourcePathForConnector updates source_path for the row scoped to
// connector (connector="" = global). See ActionEntry.Connector (SK-4).
func (s *Store) SetSourcePathForConnector(targetType, targetName, connector, path string) error {
	_, err := s.execDB(context.Background(), "audit",
		`UPDATE actions SET source_path = ? WHERE target_type = ? AND target_name = ? AND connector = ?`,
		path, targetType, targetName, connector,
	)
	if err != nil {
		return fmt.Errorf("audit: set source path: %w", err)
	}
	return nil
}

// ClearActionField removes a single dimension from the global (connector="")
// actions JSON. Deletes the row if all dimensions are empty afterward.
func (s *Store) ClearActionField(targetType, targetName, field string) error {
	return s.ClearActionFieldForConnector(targetType, targetName, "", field)
}

// ClearActionFieldForConnector removes a single dimension from the actions
// JSON of the row scoped to connector (connector="" = global). Deletes the row
// if all dimensions are empty afterward. See ActionEntry.Connector (SK-4).
func (s *Store) ClearActionFieldForConnector(targetType, targetName, connector, field string) error {
	if err := validateActionFieldAndValue(field, ""); err != nil {
		return err
	}
	path := "$." + field
	_, err := s.execDB(context.Background(), "audit",
		`UPDATE actions SET actions_json = json_remove(actions_json, ?), updated_at = ?
		 WHERE target_type = ? AND target_name = ? AND connector = ?`,
		path, time.Now().UTC(), targetType, targetName, connector,
	)
	if err != nil {
		return fmt.Errorf("audit: clear action field %s: %w", field, err)
	}
	// Clean up rows with no active actions
	_, _ = s.execDB(context.Background(), "audit",
		`DELETE FROM actions WHERE target_type = ? AND target_name = ? AND connector = ? AND actions_json IN ('{}', 'null', '')`,
		targetType, targetName, connector,
	)
	return nil
}

// RemoveAction deletes the global (connector="") action row for a target.
func (s *Store) RemoveAction(targetType, targetName string) error {
	return s.RemoveActionForConnector(targetType, targetName, "")
}

// RemoveActionForConnector deletes the action row scoped to connector
// (connector="" = global). See ActionEntry.Connector (SK-4).
func (s *Store) RemoveActionForConnector(targetType, targetName, connector string) error {
	_, err := s.execDB(context.Background(), "audit",
		`DELETE FROM actions WHERE target_type = ? AND target_name = ? AND connector = ?`,
		targetType, targetName, connector,
	)
	if err != nil {
		return fmt.Errorf("audit: remove action: %w", err)
	}
	return nil
}

// GetAction returns the global (connector="") action entry for a target, or
// nil if none exists.
func (s *Store) GetAction(targetType, targetName string) (*ActionEntry, error) {
	return s.GetActionForConnector(targetType, targetName, "")
}

// GetActionForConnector returns the action entry scoped to connector
// (connector="" = global), or nil if none exists. This is an exact-match
// lookup: callers wanting most-specific-wins resolution (connector then global
// fallback) compose two lookups. See ActionEntry.Connector (SK-4).
func (s *Store) GetActionForConnector(targetType, targetName, connector string) (*ActionEntry, error) {
	var e ActionEntry
	var sourcePath, reason, actionsJSON sql.NullString
	err := s.scanRow(context.Background(), "get_action",
		s.db.QueryRowContext(context.Background(),
			`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
		 FROM actions WHERE target_type = ? AND target_name = ? AND connector = ?`,
			targetType, targetName, connector,
		), &e.ID, &e.TargetType, &e.TargetName, &sourcePath, &actionsJSON, &reason, &e.UpdatedAt, &e.Connector)
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

// HasAction checks if a target's global (connector="") entry has a specific
// field set to a specific value.
func (s *Store) HasAction(targetType, targetName, field, value string) (bool, error) {
	return s.HasActionForConnector(targetType, targetName, "", field, value)
}

// HasActionForConnector checks if the entry scoped to connector (connector=""
// = global) has a specific field set to a specific value. Exact-match: callers
// wanting most-specific-wins resolution compose connector + global lookups.
// See ActionEntry.Connector (SK-4).
func (s *Store) HasActionForConnector(targetType, targetName, connector, field, value string) (bool, error) {
	if err := validateActionFieldAndValue(field, value); err != nil {
		return false, err
	}
	var count int
	query := fmt.Sprintf(
		`SELECT COUNT(*) FROM actions WHERE target_type = ? AND target_name = ? AND connector = ? AND json_extract(actions_json, '$.%s') = ?`,
		field)
	err := s.scanRow(context.Background(), "has_action",
		s.db.QueryRowContext(context.Background(), query, targetType, targetName, connector, value), &count)
	if err != nil {
		return false, fmt.Errorf("audit: has action: %w", err)
	}
	return count > 0, nil
}

// ListByAction returns all entries (across all connectors) where a given field
// has a given value. Each entry carries its own Connector.
func (s *Store) ListByAction(field, value string) ([]ActionEntry, error) {
	if err := validateActionFieldAndValue(field, value); err != nil {
		return nil, err
	}
	query := fmt.Sprintf(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
		 FROM actions WHERE json_extract(actions_json, '$.%s') = ?
		 ORDER BY updated_at DESC`, field)
	return s.queryActions(query, value)
}

// ListByActionAndType filters by both action field/value and target_type,
// across all connectors. Each entry carries its own Connector.
func (s *Store) ListByActionAndType(field, value, targetType string) ([]ActionEntry, error) {
	if err := validateActionFieldAndValue(field, value); err != nil {
		return nil, err
	}
	query := fmt.Sprintf(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
		 FROM actions WHERE json_extract(actions_json, '$.%s') = ? AND target_type = ?
		 ORDER BY updated_at DESC`, field)
	return s.queryActions(query, value, targetType)
}

// ListActionsByType returns all action entries for a given target type, across
// all connectors. Each entry carries its own Connector (SK-4).
func (s *Store) ListActionsByType(targetType string) ([]ActionEntry, error) {
	return s.queryActions(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
		 FROM actions WHERE target_type = ? ORDER BY updated_at DESC`, targetType)
}

// ListActionsByTypeForConnector returns action entries for a target type
// scoped to exactly one connector (connector="" = global only). See
// ActionEntry.Connector (SK-4).
func (s *Store) ListActionsByTypeForConnector(targetType, connector string) ([]ActionEntry, error) {
	return s.queryActions(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
		 FROM actions WHERE target_type = ? AND connector = ? ORDER BY updated_at DESC`, targetType, connector)
}

// ListAllActions returns every action entry, across all connectors. Each entry
// carries its own Connector.
func (s *Store) ListAllActions() ([]ActionEntry, error) {
	return s.queryActions(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
		 FROM actions ORDER BY updated_at DESC`)
}

func (s *Store) queryActions(query string, args ...any) ([]ActionEntry, error) {
	rows, err := s.queryDB(context.Background(), "audit", query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query actions: %w", err)
	}
	defer rows.Close()

	var entries []ActionEntry
	for rows.Next() {
		var e ActionEntry
		var sourcePath, reason, actionsJSON sql.NullString
		if err := rows.Scan(&e.ID, &e.TargetType, &e.TargetName, &sourcePath, &actionsJSON, &reason, &e.UpdatedAt, &e.Connector); err != nil {
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

func encodeStructuredPayload(payload map[string]any) (sql.NullString, error) {
	if len(payload) == 0 {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

func decodeStructuredPayload(raw sql.NullString) (map[string]any, error) {
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil, nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw.String), &payload); err != nil {
		return nil, fmt.Errorf("audit: decode structured payload: %w", err)
	}
	return payload, nil
}

func nullInt(v int) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(v), Valid: true}
}

func nullUint64(v uint64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(v), Valid: true}
}

// nullBool persists a bool as a nullable INTEGER: true -> 1, false ->
// NULL. NULL (rather than 0) for the false case keeps `WHERE enforced=1`
// queries clean and lets legacy rows (which predate the column) and
// non-enforcement events share the same "absent" representation.
func nullBool(b bool) sql.NullInt64 {
	if !b {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: 1, Valid: true}
}

func anyString(s string) any {
	if s == "" {
		return nil
	}
	return s
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
	rows, err := s.queryDB(context.Background(), "audit",
		`SELECT id, timestamp, action, target, actor, details, structured_json, severity, run_id, trace_id, request_id
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
		var target, details, structuredJSON, severity, runID, traceID, requestID sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &target, &e.Actor, &details, &structuredJSON, &severity, &runID, &traceID, &requestID); err != nil {
			return nil, fmt.Errorf("audit: scan alert row: %w", err)
		}
		e.Target = target.String
		e.Details = details.String
		structured, err := decodeStructuredPayload(structuredJSON)
		if err != nil {
			return nil, err
		}
		e.Structured = structured
		e.Severity = severity.String
		e.RunID = runID.String
		e.TraceID = traceID.String
		e.RequestID = requestID.String
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
		res, err = s.execDB(context.Background(), "audit",
			`UPDATE audit_events SET severity = 'ACK'
			 WHERE severity IN ('CRITICAL','HIGH','MEDIUM','LOW')`)
	} else {
		res, err = s.execDB(context.Background(), "audit",
			`UPDATE audit_events SET severity = 'ACK'
			 WHERE severity = ?`, severityFilter)
	}
	if err != nil {
		return 0, fmt.Errorf("audit: acknowledge alerts: %w", err)
	}
	n, _ := res.RowsAffected()

	_ = s.LogEvent(Event{
		Action:   string(ActionAckAlerts),
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
	res, err := s.execDB(context.Background(), "audit", query, args...)
	if err != nil {
		return 0, fmt.Errorf("audit: acknowledge by IDs: %w", err)
	}
	n, _ := res.RowsAffected()

	_ = s.LogEvent(Event{
		Action:   string(ActionAckAlerts),
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
	rows, err := s.queryDB(context.Background(), "audit",
		`SELECT id, timestamp, action, target, actor, details, structured_json, severity,
		        run_id, trace_id, request_id,
		        session_id, agent_name, agent_instance_id, policy_id,
		        destination_app, tool_name, tool_id,
		        schema_version, content_hash, generation, binary_version,
		        agent_id, sidecar_instance_id,
		        connector, step_idx, enforced, rule_pack_dir
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
		e, err := scanAuditEventRow(rows)
		if err != nil {
			return nil, err
		}
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
	rows, err := s.queryDB(context.Background(), "audit",
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
	rows, err := s.queryDB(context.Background(), "audit",
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
		if err := s.scanRow(context.Background(), "get_counts",
			s.db.QueryRowContext(context.Background(), q.sql), q.dest); err != nil {
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

	rows, err := s.queryDB(context.Background(), "audit", query, args...)
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
	rows, err := s.queryDB(context.Background(), "audit", `
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
	_, err := s.execDB(context.Background(), "audit",
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
	err := s.scanRow(context.Background(), "scan_raw_json",
		s.db.QueryRowContext(context.Background(), "SELECT raw_json FROM scan_results WHERE id = ?", scanID), &raw)
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
	// ScannerFingerprint identifies the scanner binary + ruleset +
	// scan-affecting config that produced ScanID. The watcher
	// re-scans when it no longer matches the current fingerprint so
	// an upgraded scanner re-evaluates byte-identical content.
	ScannerFingerprint string `json:"scanner_fingerprint"`
}

// SetTargetSnapshot upserts a snapshot baseline for drift comparison.
func (s *Store) SetTargetSnapshot(targetType, targetPath, contentHash, depHashes, cfgHashes, endpoints, scanID, scannerFingerprint string) error {
	id := uuid.New().String()
	now := time.Now().UTC()
	_, err := s.execDB(context.Background(), "audit",
		`INSERT INTO target_snapshots (id, target_type, target_path, content_hash, dependency_hashes, config_hashes, network_endpoints, scan_id, captured_at, scanner_fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(target_type, target_path) DO UPDATE SET
		 	content_hash = excluded.content_hash,
		 	dependency_hashes = excluded.dependency_hashes,
		 	config_hashes = excluded.config_hashes,
		 	network_endpoints = excluded.network_endpoints,
		 	scan_id = excluded.scan_id,
		 	captured_at = excluded.captured_at,
		 	scanner_fingerprint = excluded.scanner_fingerprint`,
		id, targetType, targetPath, contentHash, depHashes, cfgHashes, endpoints, scanID, now, scannerFingerprint,
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
		rows, err = s.queryDB(context.Background(), "audit",
			`SELECT id, timestamp, session_id, hostname, url, http_method, protocol,
			        policy_outcome, decision_code, blocked, severity, details
			 FROM network_egress_events
			 ORDER BY julianday(timestamp) DESC, timestamp DESC LIMIT ?`, limit,
		)
	} else {
		rows, err = s.queryDB(context.Background(), "audit",
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
	err := s.scanRow(context.Background(), "count_blocked_egress",
		s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM network_egress_events WHERE blocked = 1`), &count)
	if err != nil {
		return 0, fmt.Errorf("audit: count blocked egress: %w", err)
	}
	return count, nil
}

// GetTargetSnapshot loads the stored baseline snapshot for a target.
func (s *Store) GetTargetSnapshot(targetType, targetPath string) (*SnapshotRow, error) {
	var r SnapshotRow
	var ts string
	err := s.scanRow(context.Background(), "get_target_snapshot",
		s.db.QueryRowContext(context.Background(),
			`SELECT id, target_type, target_path, content_hash, dependency_hashes, config_hashes, network_endpoints, scan_id, captured_at, scanner_fingerprint
		 FROM target_snapshots WHERE target_type = ? AND target_path = ?`,
			targetType, targetPath,
		), &r.ID, &r.TargetType, &r.TargetPath, &r.ContentHash, &r.DependencyHashes, &r.ConfigHashes, &r.NetworkEndpoints, &r.ScanID, &ts, &r.ScannerFingerprint)
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
	telemetry.RegisterAuditDB(nil)
	return s.db.Close()
}

// currentRunID resolves the per-process run id used to stamp audit
// rows whose caller did not supply one. It prefers the atomic value
// installed at sidecar boot by gatewaylog.SetProcessRunID over the
// legacy DEFENSECLAW_RUN_ID env var so short-lived subprocesses and
// `go run` entry points that never exported the env var still emit
// correlatable rows. Empty return is legal — CLI subcommands and
// pre-boot code legitimately have no run to attribute to.
func currentRunID() string {
	if v := gatewaylog.ProcessRunID(); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("DEFENSECLAW_RUN_ID"))
}

// processAgentInstanceID holds the per-process agent instance ID that
// the sidecar installs at startup via SetProcessAgentInstanceID. It
// is the stable fallback every audit row receives when the caller
// doesn't already carry a session-scoped instance id.
//
// We keep it as a package-level atomic string behind a setter rather
// than an env var (unlike currentRunID) because the sidecar mints a
// fresh UUID per process lifetime — there's no operator-facing
// configuration surface for it, and env vars propagate to child
// processes which would accidentally share instance ids.
var processAgentInstanceID atomic.Value

// SetProcessAgentInstanceID installs the per-process stable agent
// instance id. Intended to be called exactly once during sidecar
// boot, before the audit Logger starts receiving traffic. An empty
// value clears it.
func SetProcessAgentInstanceID(id string) {
	processAgentInstanceID.Store(strings.TrimSpace(id))
}

// ProcessAgentInstanceID returns the currently registered
// per-process agent instance id, or empty string if none was set.
func ProcessAgentInstanceID() string {
	v, _ := processAgentInstanceID.Load().(string)
	return v
}
