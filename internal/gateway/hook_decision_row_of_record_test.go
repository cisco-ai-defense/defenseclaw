// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// exported is every record the destination got whose event name is name.
func (r *hookRemoteRecorder) exported(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, copies := range r.records {
		for _, record := range copies {
			if strings.Contains(record, `"event_name":"`+name+`"`) {
				out = append(out, record)
			}
		}
	}
	return out
}

// waitExported waits until the destination got at least want records of
// name, then a little longer so a late extra copy is seen too.
func (r *hookRemoteRecorder) waitExported(name string, want int) {
	deadline := time.Now().Add(10 * time.Second)
	for len(r.exported(name)) < want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
}

const rowOfRecordRawAllow = `"defenseclaw.guardrail.raw_action":"allow"`

// assertOnlyTheFailModeDecision checks a call whose row of record did not
// commit: no allow decision and no connector-hook record of the abandoned
// attempt is exported or stored, and exactly one decision, the fail-mode
// verdict the agent got, is exported and stored (S8 R4 review P1, P2).
func assertOnlyTheFailModeDecision(t *testing.T, f auditFailureHookFixture, remote *hookRemoteRecorder) {
	t.Helper()
	remote.waitExported("hook_decision", 1)
	decisions := remote.exported("hook_decision")
	if len(decisions) != 1 || strings.Contains(decisions[0], rowOfRecordRawAllow) {
		t.Fatalf("exported hook_decision records = %d (%.300v), want exactly the fail-mode one", len(decisions), decisions)
	}
	if got := remote.exported("legacy.audit.connector.hook"); len(got) != 0 {
		t.Fatalf("exported connector-hook records of the abandoned attempt = %d, want none", len(got))
	}
	db, err := sql.Open("sqlite", "file:"+f.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var stored, staleAllow int
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(instr(projected_record_json, ?) > 0),0)
		FROM audit_events WHERE event_name = 'hook_decision'`, rowOfRecordRawAllow).Scan(&stored, &staleAllow); err != nil {
		t.Fatal(err)
	}
	if stored != 1 || staleAllow != 0 {
		t.Fatalf("stored hook_decision rows = %d (%d allow), want one fail-mode row and no allow", stored, staleAllow)
	}
}

// A panic in the audit section after the row of record was queued and
// before the connector-hook record: the queued allow is abandoned, so the
// fail-mode block of the strict tier is the call's only decision record,
// stored and exported (S8 R4 review P1).
//
// finalize_audit_row_queued panics inside writeHookDecisionRowOfRecord, after
// the record was queued and before the audit section knows of it.
func TestRowOfRecordPanicBeforeItsFlushLeavesOnlyTheFailModeDecision(t *testing.T) {
	for _, stage := range []string{"finalize_audit_row_queued", "finalize_audit_row_of_record"} {
		t.Run(stage, func(t *testing.T) {
			injectStagePanic(t, everyCallAt(stage))
			remote := newHookRemoteRecorder()
			f := newPerUserHookFixtureExportingTo(t, remote)
			f.api.scannerCfg.Guardrail.RulePack = "strict"
			out := postRowOfRecordHook(t, f.api, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-row-panic",
				"cwd": t.TempDir(), "tool_name": "Bash", "tool_use_id": "toolu_row_panic", "tool_input": map[string]any{"command": "git status"}})
			if out["action"] != "block" {
				t.Fatalf("answer %v, want the strict fail-mode block", out)
			}
			assertOnlyTheFailModeDecision(t, f, remote)
		})
	}
}

// The store refuses the row of record when it commits: the verdict is the
// fail-mode one, the allow decision and the connector-hook record of the
// attempt are not exported, and exactly one fail-mode decision is exported
// and stored (S8 R4 review P2: CallWritesCommitted, ExportAfterCallCommit).
func TestRowOfRecordThatDidNotCommitIsNeverExported(t *testing.T) {
	remote := newHookRemoteRecorder()
	f := newPerUserHookFixtureExportingTo(t, remote)
	f.api.scannerCfg.Guardrail.RulePack = "strict"
	db, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER zz_refuse_allow_decision BEFORE INSERT ON audit_events
		WHEN NEW.action = 'hook_decision' AND instr(NEW.projected_record_json, '` + rowOfRecordRawAllow + `') > 0
		BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	out := postRowOfRecordHook(t, f.api, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-row-refused",
		"cwd": t.TempDir(), "tool_name": "Bash", "tool_use_id": "toolu_row_refused", "tool_input": map[string]any{"command": "git status"}})
	if out["action"] != "block" {
		t.Fatalf("answer %v, want the strict fail-mode block", out)
	}
	assertOnlyTheFailModeDecision(t, f, remote)
}

// With guardrail.evaluation logs off no hook_decision row is kept, so the
// call keeps its connector-hook, tool_start and requested rows locally, as
// in 1.0.9 (S8 R4 review P3-5).
func TestHookCallKeepsItsRowsWhenHookDecisionsAreNotCollected(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixtureCollectingNo(t, nil, observability.BucketGuardrailEvaluation)
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
	if api.hookDecisionRecordsKept() {
		t.Fatal("hookDecisionRecordsKept with guardrail.evaluation logs off")
	}
	postRowOfRecordHook(t, api, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-no-decisions",
		"cwd": t.TempDir(), "tool_name": "Bash", "tool_use_id": "toolu_no_decisions", "tool_input": map[string]any{"command": "git status"}})
	local := localRowsByEvent(t, fixture.path)
	if local["tool_start"] != 1 || local["tool.invocation.requested"] != 1 || local["hook_decision"] != 0 {
		t.Fatalf("local rows by event = %v, want tool_start and tool.invocation.requested kept locally", local)
	}
}

// A restart after a SessionStart, and after a PostToolUse, restores the
// cursor from the lifecycle row of that event: only a tool_start has its
// lifecycle facts in a hook_decision row, so no other event has two
// candidate rows (S8 R4 review P3-5).
func TestHookLifecycleRestoresAfterSessionStartAndPostToolUse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		calls []map[string]any
		event string
	}{
		{"session start", []map[string]any{{"hook_event_name": "SessionStart", "source": "startup"}}, "session_start"},
		{"post tool use", []map[string]any{
			{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "toolu_post_1", "tool_input": map[string]any{"command": "git status"}},
			{"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "toolu_post_1", "tool_input": map[string]any{"command": "git status"},
				"tool_response": map[string]any{"stdout": "clean"}},
		}, "tool_end"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installCorrelationHMACForTest()
			installDefaultProfileConnector(t, "claudecode")
			fixture := newSignedSidecarRuntimeFixture(t, true)
			fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
			if err != nil {
				t.Fatal(err)
			}
			logger := audit.NewLogger(fixture.store)
			logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			newAPI := func() *APIServer {
				api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
				bindHookLifecycleV8(t, api, fixture.runtime)
				return api
			}
			session := "s-restore-" + strings.ReplaceAll(tc.name, " ", "-")
			cwd := t.TempDir()
			first := newAPI()
			for _, call := range tc.calls {
				call["session_id"], call["cwd"] = session, cwd
				postRowOfRecordHook(t, first, call)
			}
			db, err := sql.Open("sqlite", "file:"+fixture.path+"?mode=ro")
			if err != nil {
				t.Fatal(err)
			}
			var recordID, agentID, raw string
			if err := db.QueryRow(`SELECT id, COALESCE(agent_id,''), json_extract(projected_record_json,'$.body') FROM audit_events
				WHERE event_name = ? AND session_id = ? ORDER BY rowid DESC LIMIT 1`, tc.event, session).Scan(&recordID, &agentID, &raw); err != nil {
				t.Fatalf("no %s lifecycle row: %v", tc.event, err)
			}
			db.Close()
			var body map[string]any
			if err := json.Unmarshal([]byte(raw), &body); err != nil {
				t.Fatal(err)
			}
			restarted := newAPI()
			history, ok := restarted.observabilityV8RuntimeEmitter().(hookLifecycleHistoryRuntime)
			if !ok {
				t.Fatal("the runtime serves no lifecycle history")
			}
			projection, found, err := history.LatestLifecycleProjection(context.Background(), audit.LifecycleProjectionQuery{
				Connector: "claudecode", SessionID: session, AgentID: agentID,
			})
			if err != nil || !found || projection.RecordID != recordID || projection.Event != tc.event ||
				projection.ExecutionID != body["defenseclaw.agent.execution.id"] {
				t.Fatalf("lifecycle history = %+v, %t, %v; want the %s row %s", projection, found, err, tc.event, recordID)
			}
		})
	}
}

// newPerUserHookFixtureExportingTo is the per-user Claude Code fixture of
// newAuditFailureHookFixture with every log also sent to remote.
func newPerUserHookFixtureExportingTo(t *testing.T, remote delivery.Adapter) auditFailureHookFixture {
	t.Helper()
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixtureExportingTo(t, nil, remote)
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
	return auditFailureHookFixture{api: api, path: fixture.path}
}

// exportedWithEvent counts the records the destination got whose event name
// is name.
func (r *hookRemoteRecorder) exportedWithEvent(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, copies := range r.records {
		for _, record := range copies {
			if strings.Contains(record, `"event_name":"`+name+`"`) {
				count++
			}
		}
	}
	return count
}

func localRowsByEvent(t *testing.T, path string) map[string]int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT COALESCE(event_name, action), COUNT(*) FROM audit_events GROUP BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			t.Fatal(err)
		}
		counts[name] = count
	}
	return counts
}

func postRowOfRecordHook(t *testing.T, api *APIServer, payload map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(recorder,
		httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %.300s", recorder.Code, recorder.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("answer %q: %v", recorder.Body.String(), err)
	}
	return out
}

// A benign per-user allow keeps one local hook row, its hook_decision row
// (the row of record), and still exports the connector-hook record, the
// requested tool call and tool_start unchanged (#1384, DESIGN 11). The local
// readers that took the connector-hook or tool_start row find the decision
// in the hook_decision row: the GAP-1060 replay check, the enterprise live
// check (tool call id and user.id) and the lifecycle restore.
func TestBenignPerUserAllowKeepsOneLocalHookRowAndExportsTheRest(t *testing.T) {
	remote := newHookRemoteRecorder()
	f := newPerUserHookFixtureExportingTo(t, remote)
	started := time.Now().UTC()
	const session, toolUseID = "s-row-of-record", "toolu_row_of_record_1"
	postRowOfRecordHook(t, f.api, map[string]any{"hook_event_name": "PreToolUse", "session_id": session, "cwd": t.TempDir(),
		"tool_name": "Bash", "tool_use_id": toolUseID, "tool_input": map[string]any{"command": "git status"}})

	exported := []string{"hook_decision", "legacy.audit.connector.hook", "tool_start", "tool.invocation.requested"}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ready := true
		for _, name := range exported {
			if remote.exportedWithEvent(name) == 0 {
				ready = false
			}
		}
		if ready || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	for _, name := range exported {
		if got := remote.exportedWithEvent(name); got != 1 {
			t.Errorf("exported %s records = %d, want 1", name, got)
		}
	}
	local := localRowsByEvent(t, f.path)
	if local["hook_decision"] != 1 || local["legacy.audit.connector.hook"] != 0 ||
		local["tool_start"] != 0 || local["tool.invocation.requested"] != 0 {
		t.Fatalf("local rows by event = %v, want one hook_decision and no connector-hook, tool_start or requested rows", local)
	}

	db, err := sql.Open("sqlite", "file:"+f.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var recordID, semantic, agentID, rawBody string
	if err := db.QueryRow(`SELECT id, json_extract(projected_record_json,'$.correlation.semantic_event_id'),
		COALESCE(agent_id,''), json_extract(projected_record_json,'$.body')
		FROM audit_events WHERE event_name = 'hook_decision'`).Scan(&recordID, &semantic, &agentID, &rawBody); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(rawBody), &body); err != nil {
		t.Fatal(err)
	}
	if bytes, _ := body["defenseclaw.hook.body_bytes"].(float64); bytes <= 0 {
		t.Errorf("hook_decision body_bytes = %v, want the request size (registry v4 field)", body["defenseclaw.hook.body_bytes"])
	}

	verdict, found, err := f.api.store.LatestHookVerdictOfEvent(t.Context(), semantic)
	if err != nil || !found || verdict.Action != "allow" {
		t.Fatalf("LatestHookVerdictOfEvent = %+v, %t, %v; want the allow of the hook_decision row", verdict, found, err)
	}
	userID, _ := body["user.id"].(string)
	evidence, err := audit.FindHookToolInvocation(t.Context(), f.path, audit.HookToolInvocationQuery{
		Connector: "claudecode", ToolCallID: toolUseID, Since: started, UserID: userID,
	})
	if err != nil || !evidence.Matched {
		t.Fatalf("live check by tool call id and user.id %q = %+v, %v; want a match", userID, evidence, err)
	}
	evidence, err = audit.FindHookToolInvocation(t.Context(), f.path, audit.HookToolInvocationQuery{
		Connector: "claudecode", ToolCallID: toolUseID, Since: started, UserID: userID + "0",
	})
	if err != nil || evidence.Matched || len(evidence.Mismatches) == 0 {
		t.Fatalf("live check for another user = %+v, %v; want a user mismatch", evidence, err)
	}
	_ = recordID
}

// After a restart the session cursor of a hook agent is restored from its
// hook_decision row, since tool_start is exported only inside a call
// (#1384): the next call continues the same execution with the next sequence.
func TestHookLifecycleRestoresFromTheHookDecisionRowAfterRestart(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSignedSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	newAPI := func() *APIServer {
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
		bindHookLifecycleV8(t, api, fixture.runtime)
		return api
	}
	const session = "s-restore-from-decision"
	cwd := t.TempDir()
	call := func(api *APIServer, toolUseID string) {
		postRowOfRecordHook(t, api, map[string]any{"hook_event_name": "PreToolUse", "session_id": session, "cwd": cwd,
			"tool_name": "Bash", "tool_use_id": toolUseID, "tool_input": map[string]any{"command": "git status"}})
	}
	newest := func() (id, execution string, sequence float64) {
		t.Helper()
		db, err := sql.Open("sqlite", "file:"+fixture.path+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var raw string
		if err := db.QueryRow(`SELECT id, json_extract(projected_record_json,'$.body') FROM audit_events
			WHERE event_name = 'hook_decision' ORDER BY rowid DESC LIMIT 1`).Scan(&id, &raw); err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			t.Fatal(err)
		}
		execution, _ = body["defenseclaw.agent.execution.id"].(string)
		sequence, _ = body["defenseclaw.agent.sequence"].(float64)
		return id, execution, sequence
	}
	call(newAPI(), "toolu_restore_1")
	if local := localRowsByEvent(t, fixture.path); local["tool_start"] != 0 {
		t.Fatalf("local rows = %v, want no tool_start row inside a hook call", local)
	}
	firstID, firstExecution, firstSequence := newest()
	if firstExecution == "" || firstSequence <= 0 {
		t.Fatalf("first hook_decision execution %q sequence %v", firstExecution, firstSequence)
	}
	restarted := newAPI()
	var agentID string
	db, err := sql.Open("sqlite", "file:"+fixture.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COALESCE(agent_id,'') FROM audit_events WHERE id = ?`, firstID).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	db.Close()
	history, ok := restarted.observabilityV8RuntimeEmitter().(hookLifecycleHistoryRuntime)
	if !ok {
		t.Fatal("the runtime serves no lifecycle history")
	}
	projection, found, err := history.LatestLifecycleProjection(context.Background(), audit.LifecycleProjectionQuery{
		Connector: "claudecode", SessionID: session, AgentID: agentID,
	})
	if err != nil || !found || projection.RecordID != firstID || projection.Event != "tool_start" ||
		projection.ExecutionID != firstExecution {
		t.Fatalf("lifecycle history = %+v, %t, %v; want the hook_decision row %s", projection, found, err, firstID)
	}
	call(restarted, "toolu_restore_2")
	_, secondExecution, secondSequence := newest()
	if secondExecution != firstExecution || secondSequence <= firstSequence {
		t.Fatalf("after restart: execution %q sequence %v, want execution %q after sequence %v",
			secondExecution, secondSequence, firstExecution, firstSequence)
	}
}

// A block keeps its connector-hook row locally beside its hook_decision row,
// as in 1.0.9: alerts, the GAP-1060 replay check and a 1.0.9 binary after a
// rollback read it.
func TestHookBlockKeepsItsConnectorHookRow(t *testing.T) {
	f := newPerUserHookFixtureExportingTo(t, nil)
	out := postRowOfRecordHook(t, f.api, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-row-block",
		"cwd": t.TempDir(), "tool_name": "Bash", "tool_use_id": "toolu_row_block",
		"tool_input": map[string]any{"command": "rm -rf /"}})
	if !strings.Contains(mustBenchJSONString(t, out), "deny") && !strings.Contains(mustBenchJSONString(t, out), "block") {
		t.Fatalf("answer %v, want a block", out)
	}
	local := localRowsByEvent(t, f.path)
	if local["legacy.audit.connector.hook"] != 1 || local["hook_decision"] != 1 {
		t.Fatalf("local rows by event = %v, want the connector-hook and hook_decision rows of the block", local)
	}
}

func mustBenchJSONString(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// hookDecisionIsRowOfRecord admits only a benign allow of a live per-user
// call in an open batch; every other call keeps the connector-hook row.
func TestHookDecisionIsRowOfRecordOnlyForBenignPerUserAllows(t *testing.T) {
	f := newPerUserHookFixtureExportingTo(t, nil)
	api := f.api
	allow := agentHookResponse{Action: "allow", RawAction: "allow"}
	okEnv := HookAuditEnvelope{Result: "ok", Action: "allow"}
	base := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", SemanticEventID: "01a1d3df-c154-74dc-812c-4a8c54440a84"}
	batch := audit.WithCallWriteBatch(t.Context(), api.store)
	cases := []struct {
		name     string
		ctx      context.Context
		req      func(agentHookRequest) agentHookRequest
		resp     agentHookResponse
		env      HookAuditEnvelope
		panicked bool
		managed  bool
		profile  string
		want     bool
	}{
		{name: "cowork", ctx: context.WithValue(batch, coworkContextKey{}, hookexec.CoworkContext{SessionID: "cowork-1"})},
		{name: "sandbox connector", ctx: sandboxauth.WithRequest(batch, sandboxauth.Binding{ID: "binding-1", Connector: "claudecode"}, nil)},
		{name: "secure client", managed: true, profile: managed.ProfileSecureClient},
		{name: "standalone journal", managed: true, profile: managed.ProfileStandalone},
		{name: "benign allow", want: true},
		{name: "no open batch", ctx: t.Context()},
		{name: "block", resp: agentHookResponse{Action: "block", RawAction: "block"}},
		{name: "alert", resp: agentHookResponse{Action: "allow", RawAction: "alert"}},
		{name: "would block", resp: agentHookResponse{Action: "allow", RawAction: "allow", WouldBlock: true}},
		{name: "unconfirmed", resp: agentHookResponse{Action: hookActionUnconfirmed, RawAction: "allow"}},
		{name: "enforced", env: HookAuditEnvelope{Result: "ok", Action: "allow", Enforced: true}},
		{name: "panic", env: HookAuditEnvelope{Result: "panic", Action: "allow"}},
		{name: "panicked", panicked: true},
		{name: "bounded prefix review", env: HookAuditEnvelope{Result: "ok", Action: "allow", Extra: map[string]string{"bounded_prefix_review": "true"}}},
		{name: "pending occurrence", req: func(r agentHookRequest) agentHookRequest { r.pendingOccurrenceID = "occ"; return r }},
		{name: "recovery", req: func(r agentHookRequest) agentHookRequest { r.pendingRecovery = true; return r }},
		{name: "sandbox receipt", req: func(r agentHookRequest) agentHookRequest { r.sandboxReceiptAcknowledgment = true; return r }},
		{name: "correlation unavailable", req: func(r agentHookRequest) agentHookRequest { r.CorrelationUnavailable = true; return r }},
		{name: "no semantic event", req: func(r agentHookRequest) agentHookRequest { r.SemanticEventID = ""; return r }},
		{name: "managed enterprise", managed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.ctx
			if ctx == nil {
				ctx = batch
			}
			req := base
			if tc.req != nil {
				req = tc.req(req)
			}
			resp := tc.resp
			if resp.Action == "" {
				resp = allow
			}
			env := tc.env
			if env.Result == "" {
				env = okEnv
			}
			previous, previousProfile := api.scannerCfg.DeploymentMode, api.scannerCfg.Enterprise.Profile
			if tc.managed {
				api.scannerCfg.DeploymentMode = "managed_enterprise"
				api.scannerCfg.Enterprise.Profile = tc.profile
			}
			defer func() { api.scannerCfg.DeploymentMode, api.scannerCfg.Enterprise.Profile = previous, previousProfile }()
			if tc.profile == managed.ProfileSecureClient && (!api.managedAIDOnly() || !api.scannerCfg.SecureClientIntegration()) {
				t.Fatal("the Secure Client case does not select the managed AID-only posture")
			}
			if tc.profile == managed.ProfileStandalone && !api.journalsHookDeliveries() {
				t.Fatal("the standalone case does not journal hook deliveries")
			}
			if tc.name == "sandbox connector" && !sandboxHookForConnector(ctx, "claudecode") {
				t.Fatal("the sandbox case is not a sandbox request")
			}
			if got := api.hookDecisionIsRowOfRecord(ctx, req, resp, env, tc.panicked); got != tc.want {
				t.Fatalf("hookDecisionIsRowOfRecord = %t, want %t", got, tc.want)
			}
		})
	}
}
