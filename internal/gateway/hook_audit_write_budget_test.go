// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// hookAuditCommitBudget is the most audit.db commits one Claude Code
// PreToolUse may make (B-26 writes). At 9747dbd11f a call made 25 commits and
// wrote 548 WAL frames: one per generated metric among them. A metric batch
// now commits the correlation observations of all its records at once, so a
// call makes 16. A change that adds a commit per call fails here: under a
// flood every commit is more WAL for the checkpoint to copy while it holds
// the audit writer (GAP-0247).
const hookAuditCommitBudget = 16

// walCommits counts the commit frames a WAL file gained from before to after.
// ok is false when the log restarted in between (a new salt), so the frames
// before and after are not one sequence.
func walCommits(before, after []byte) (commits, frames int, ok bool) {
	const walHeader, frameHeader = 32, 24
	if len(after) < walHeader || (len(before) >= walHeader && !bytes.Equal(before[16:24], after[16:24])) ||
		len(after) < len(before) {
		return 0, 0, false
	}
	pageSize := int(binary.BigEndian.Uint32(after[8:12]))
	offset := max(len(before), walHeader)
	for ; offset+frameHeader+pageSize <= len(after); offset += frameHeader + pageSize {
		frames++
		if binary.BigEndian.Uint32(after[offset+4:]) != 0 {
			commits++
		}
	}
	return commits, frames, true
}

// TestClaudeCodePreToolUseAuditCommitBudget drives the real Claude Code hook
// handler, audit store and v8 runtime, and counts the audit.db commits and
// rows of each PreToolUse from the store's write-ahead log. The rows pin that
// batching lost no record: every call writes its 5 audit rows and 19
// correlation observations (5 logs, 13 metrics, 1 span). The 2 relationship
// change records it also exports are kept in correlation_relationships, not
// again as audit rows (#1384).
func TestClaudeCodePreToolUseAuditCommitBudget(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	cwd := t.TempDir()
	call := func(index int) {
		body, err := json.Marshal(map[string]any{
			"session_id": "audit-commit-budget", "transcript_path": filepath.Join(cwd, "transcript.jsonl"), "cwd": cwd,
			"hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_use_id": fmt.Sprintf("toolu_%06d", index),
			"tool_input":  map[string]any{"command": "echo ok"},
		})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(recorder,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("call %d: status %d body %s", index, recorder.Code, recorder.Body.String())
		}
	}
	reader, err := sql.Open("sqlite", "file:"+fixture.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	rows := func(table string) int {
		var count int
		if err := reader.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	// The first calls of a session write its one-time rows.
	for index := 0; index < 10; index++ {
		call(index)
	}
	const measured = 10
	auditRows, observationRows := rows("audit_events"), rows("correlation_observations")
	totalCommits, totalFrames := 0, 0
	for index := 10; index < 10+measured; index++ {
		before, err := os.ReadFile(fixture.path + "-wal")
		if err != nil {
			t.Fatal(err)
		}
		call(index)
		after, err := os.ReadFile(fixture.path + "-wal")
		if err != nil {
			t.Fatal(err)
		}
		commits, frames, ok := walCommits(before, after)
		if !ok {
			t.Fatalf("call %d: the WAL restarted during the call; the count needs one log", index)
		}
		if commits > hookAuditCommitBudget {
			t.Fatalf("call %d made %d audit.db commits (%d WAL frames); the budget is %d", index, commits, frames, hookAuditCommitBudget)
		}
		totalCommits += commits
		totalFrames += frames
	}
	t.Logf("per PreToolUse: %.1f commits, %.1f WAL frames", float64(totalCommits)/measured, float64(totalFrames)/measured)
	if got := (rows("audit_events") - auditRows) / measured; got != 5 {
		t.Fatalf("audit rows per call = %d, want 5", got)
	}
	if got := (rows("correlation_observations") - observationRows) / measured; got != 19 {
		t.Fatalf("correlation observations per call = %d, want 19", got)
	}
	// rel-1-0-3 GAP-0320: the unique keys a hook call writes are time
	// ordered, so each lands at the end of its index instead of on a random
	// page that a Windows checkpoint has to write on its own.
	for _, key := range []struct{ table, column string }{
		{"audit_events", "id"}, {"correlation_observations", "record_id"}, {"scan_results", "id"},
	} {
		keys, err := reader.Query("SELECT " + key.column + " FROM " + key.table + " ORDER BY rowid DESC LIMIT 50")
		if err != nil {
			t.Fatal(err)
		}
		for keys.Next() {
			var value string
			if err := keys.Scan(&value); err != nil {
				t.Fatal(err)
			}
			if parsed, err := uuid.Parse(value); err != nil || parsed.Version() != 7 {
				t.Fatalf("%s.%s %q is not a UUIDv7", key.table, key.column, value)
			}
		}
		if err := keys.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
