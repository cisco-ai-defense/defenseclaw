// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestConnectorContractProjectionReadsACompactStore builds the store a
// per-user Claude Code session writes since S8 R4 (#1384): a benign allow
// (its hook_decision row only), a settled PreToolUse + PostToolUse pair and a
// blocked call with its alert, whose legacy.audit.* connector-hook rows keep
// no payload_json. The connector contract CI job projects such a store with
// scripts/live-connector-e2e/project-audit-events.py; at rel 7f32dbb3a0 it
// failed every connector with "indexed payload_json is not text".
func TestConnectorContractProjectionReadsACompactStore(t *testing.T) {
	python := ""
	for _, name := range []string{"python3", "python"} {
		if found, err := exec.LookPath(name); err == nil {
			python = found
			break
		}
	}
	if python == "" {
		t.Skip("no Python interpreter to run the projection script")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "live-connector-e2e", "project-audit-events.py"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAuditFailureHookFixture(t, "open")
	cwd := t.TempDir()
	sendBudgetClaudeHook(t, fixture, cwd, "projection", "PreToolUse", 1)
	sendBudgetClaudeHook(t, fixture, cwd, "projection", "PreToolUse", 2)
	sendBudgetClaudeHook(t, fixture, cwd, "projection", "PostToolUse", 2)
	body := mustBenchJSON(t, map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "projection", "cwd": cwd,
		"tool_name": "Bash", "tool_use_id": "toolu_projection_block",
		"tool_input": map[string]any{"command": "rm -rf --no-preserve-root /"},
	})
	recorder := httptest.NewRecorder()
	fixture.api.handleAgentHook("claudecode").ServeHTTP(recorder,
		httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("blocked call: status %d body %.200s", recorder.Code, recorder.Body.String())
	}
	settledStoreBytes(t, fixture.path, func(t *testing.T, path string) map[string]int64 { return storeObjectBytes(t, path, false) })

	reader, err := sql.Open("sqlite", "file:"+fixture.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var compactCompat, hookDecisions, alerts int
	if err := reader.QueryRow(`SELECT
			COALESCE(SUM(event_name LIKE 'legacy.audit.%' AND payload_json IS NULL), 0),
			COALESCE(SUM(event_name = 'hook_decision'), 0),
			COALESCE(SUM(severity IN ('HIGH', 'CRITICAL') OR event_name LIKE 'alert.%'), 0)
		FROM audit_events`).Scan(&compactCompat, &hookDecisions, &alerts); err != nil {
		t.Fatal(err)
	}
	if compactCompat == 0 || hookDecisions < 4 || alerts == 0 {
		t.Fatalf("the store lacks the R4 shape: %d compatibility rows without payload_json, %d hook_decision rows, %d alert rows",
			compactCompat, hookDecisions, alerts)
	}

	out := filepath.Join(t.TempDir(), "audit-projection.jsonl")
	command := exec.Command(python, "-I", script, "--audit-db", fixture.path, "--out", out)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("project-audit-events.py rejected the store: %v\n%s", err, output)
	}
	file, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var projected, projectedDecisions int
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for scanner.Scan() {
		var record struct {
			EventName string `json:"event_name"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("projected line %d is not JSON: %v", projected+1, err)
		}
		projected++
		if record.EventName == "hook_decision" {
			projectedDecisions++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := reader.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if projected != rows || projectedDecisions != hookDecisions {
		t.Fatalf("projected %d records (%d hook_decision) of %d rows (%d hook_decision)",
			projected, projectedDecisions, rows, hookDecisions)
	}
}
