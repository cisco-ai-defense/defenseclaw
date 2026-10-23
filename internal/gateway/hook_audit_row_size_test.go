// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// hookAuditRowBytesBudget bounds the audit_events bytes (the sum of every
// column of the rows one Claude Code PreToolUse writes) of a benign hook
// decision in a long single-session flood. At fc6794381d a decision wrote
// about 44 KB: each native row stored its body three times, in the signed
// envelope, payload_json and an identical structured_json (GAP-0614: audit.db
// grew 79.7 MiB to 1,556.6 MiB over 18,000 decisions on Windows).
const hookAuditRowBytesBudget = 42 << 10

// hookAuditMaxRowBytes bounds one audit row whatever the size of the tool
// input: the hook body is not stored whole in any row.
const hookAuditMaxRowBytes = 24 << 10

// TestClaudeCodePreToolUseAuditRowsBounded drives the real Claude
// Code hook handler, audit store and v8 runtime with one session, as the
// T6Z-08 flood did, and measures what each decision adds to audit_events.
func TestClaudeCodePreToolUseAuditRowsBounded(t *testing.T) {
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
	call := func(index int, command string) {
		body, err := json.Marshal(map[string]any{
			"session_id": "audit-row-size-flood", "transcript_path": filepath.Join(cwd, "transcript.jsonl"),
			"cwd": cwd, "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_use_id": fmt.Sprintf("toolu_%06d", index),
			"tool_input":  map[string]any{"command": command, "description": "Print ok"},
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
	rowBytes := func() (rows, total int64) {
		var columns []string
		list, err := reader.Query(`SELECT name FROM pragma_table_info('audit_events')`)
		if err != nil {
			t.Fatal(err)
		}
		for list.Next() {
			var name string
			if err := list.Scan(&name); err != nil {
				t.Fatal(err)
			}
			columns = append(columns, `COALESCE(LENGTH(CAST("`+name+`" AS BLOB)),0)`)
		}
		list.Close()
		if err := reader.QueryRow(`SELECT COUNT(*), COALESCE(SUM(`+strings.Join(columns, "+")+
			`),0) FROM audit_events`).Scan(&rows, &total); err != nil {
			t.Fatal(err)
		}
		return rows, total
	}
	// The first calls of a session write its one-time rows.
	for index := 0; index < 20; index++ {
		call(index, "echo ok")
	}
	const measured = 200
	rowsBefore, bytesBefore := rowBytes()
	for index := 20; index < 20+measured; index++ {
		call(index, "echo ok")
	}
	rowsAfter, bytesAfter := rowBytes()
	perDecision := float64(bytesAfter-bytesBefore) / measured
	t.Logf("per PreToolUse: %.1f audit rows, %.0f audit_events bytes",
		float64(rowsAfter-rowsBefore)/measured, perDecision)
	if perDecision > hookAuditRowBytesBudget {
		t.Errorf("a benign PreToolUse adds %.0f audit_events bytes; the budget is %d", perDecision, hookAuditRowBytesBudget)
	}

	// No native row repeats its payload in structured_json.
	var duplicated int
	if err := reader.QueryRow(`SELECT COUNT(*) FROM audit_events
		WHERE structured_json IS NOT NULL AND structured_json = payload_json
		AND event_name NOT LIKE 'legacy.audit.%'`).Scan(&duplicated); err != nil {
		t.Fatal(err)
	}
	if duplicated != 0 {
		t.Errorf("%d native audit rows store their payload twice (structured_json = payload_json)", duplicated)
	}
	// The readers still see each native row's structured fields.
	var hookDecision string
	if err := reader.QueryRow(`SELECT ` + audit.StructuredJSONReadSQL("", true, true) + `
		FROM audit_events WHERE event_name = 'hook_decision' ORDER BY rowid DESC LIMIT 1`).Scan(&hookDecision); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hookDecision, `"defenseclaw.guardrail.effective_action":"allow"`) {
		t.Errorf("hook_decision structured fields are not readable: %s", hookDecision)
	}
	events, err := fixture.store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	var listed bool
	for _, event := range events {
		if event.Action == "hook_decision" {
			listed = event.Structured["defenseclaw.hook.event"] == "PreToolUse"
			break
		}
	}
	if !listed {
		t.Error("ListEvents lost the structured fields of the hook_decision row")
	}

	// A large tool input does not make any row unbounded.
	call(10_000, "cat <<EOF > out.txt\n"+strings.Repeat("hello world line\n", 12_000)+"EOF")
	var largest int64
	if err := reader.QueryRow(`SELECT MAX(COALESCE(LENGTH(CAST(projected_record_json AS BLOB)),0)
		+ COALESCE(LENGTH(CAST(payload_json AS BLOB)),0) + COALESCE(LENGTH(CAST(structured_json AS BLOB)),0)
		+ COALESCE(LENGTH(CAST(details AS BLOB)),0)) FROM audit_events`).Scan(&largest); err != nil {
		t.Fatal(err)
	}
	if largest > hookAuditMaxRowBytes {
		t.Errorf("an audit row holds %d bytes after a 200 KB tool input; the bound is %d", largest, hookAuditMaxRowBytes)
	}
}
