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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// hookAuditWALFramesPerCall bounds the write-ahead-log frames (4 KiB pages)
// one benign Claude Code PreToolUse adds to audit.db. At the 1.0.5 base
// f7142cb7ba a call of this test wrote 369 frames, 1.4 MiB, in 15 commits:
// at 10 calls a second the log grew about 17 MiB/s on a slow disk and passed
// its 256 MiB alarm (GAP-1303, GAP-0614). With the partial sparse-key
// indexes a call wrote 256 in 15 commits; with the call's event-history rows
// and observations in one transaction (audit.CallWriteBatch, GAP-1791) it
// writes about 163 in 6.
const hookAuditWALFramesPerCall = 175

// hookAuditCommitsPerCall bounds the commits of that call: the correlation
// ledger, the tool chain, the call's batch at its audit row (with the rule
// scan's summary since GAP-1790) and at its hook_decision, and the receipt
// (GAP-1791).
const hookAuditCommitsPerCall = 5

// TestHookCallWALFramesBounded drives the real hook handler, audit store and
// v8 runtime over five sessions and counts the log frames of the measured
// calls.
func TestHookCallWALFramesBounded(t *testing.T) {
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
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	cwd := t.TempDir()
	call := func(index int) {
		session := fmt.Sprintf("wal-session-%d", index%5)
		body, err := json.Marshal(map[string]any{
			"session_id": session, "transcript_path": filepath.Join(cwd, "transcript.jsonl"),
			"cwd": cwd, "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_use_id": fmt.Sprintf("toolu_%06d", index),
			"tool_input":  map[string]any{"command": "echo ok", "description": "Print ok"},
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
	// The first calls of each session write its one-time rows.
	for index := 0; index < 50; index++ {
		call(index)
	}
	// Start the measured calls on an empty log.
	checkpoint, err := sql.Open("sqlite", "file:"+fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	var busy, logFrames, copied int
	if err := checkpoint.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &copied); err != nil || busy != 0 {
		t.Fatalf("checkpoint: busy=%d err=%v", busy, err)
	}
	if err := checkpoint.Close(); err != nil {
		t.Fatal(err)
	}
	const measured = 100
	for index := 50; index < 50+measured; index++ {
		call(index)
	}
	wal, err := os.ReadFile(fixture.path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if len(wal) < 32 {
		t.Fatal("the measured calls wrote no log")
	}
	frame := 24 + int(binary.BigEndian.Uint32(wal[8:12]))
	frames, commits := 0, 0
	for offset := 32; offset+frame <= len(wal); offset += frame {
		frames++
		if binary.BigEndian.Uint32(wal[offset+4:offset+8]) != 0 {
			commits++
		}
	}
	perCall := float64(frames) / measured
	t.Logf("per PreToolUse: %.1f WAL frames (%.0f KiB), %.1f commits", perCall,
		perCall*float64(frame)/1024, float64(commits)/measured)
	if perCall > hookAuditWALFramesPerCall {
		t.Errorf("a benign PreToolUse writes %.1f WAL frames; the budget is %d", perCall, hookAuditWALFramesPerCall)
	}
	if perCallCommits := float64(commits) / measured; perCallCommits > hookAuditCommitsPerCall {
		t.Errorf("a benign PreToolUse makes %.1f commits; the budget is %d", perCallCommits, hookAuditCommitsPerCall)
	}
}
