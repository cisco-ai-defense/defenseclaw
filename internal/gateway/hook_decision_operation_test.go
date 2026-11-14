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

package gateway

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func claudePreToolUseForOperationTest(session, toolUseID string) claudeCodeHookRequest {
	return claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: session, ToolName: "Bash", ToolUseID: toolUseID,
		Payload: map[string]interface{}{
			"hook_event_name": "PreToolUse", "session_id": session, "tool_name": "Bash",
			"tool_use_id": toolUseID, "tool_input": map[string]interface{}{"command": "echo ok"},
		},
	}
}

// GAP-0246: two tool calls of one session overlap. The second call's
// lifecycle transition moves the session cursor before the first call's
// decision and audit row are written. Both must still carry the first call's
// own operation, phase and sequence, never the second call's.
func TestHookDecisionAndAuditKeepTheirOwnToolOperationWhenAnotherCallStartsFirst(t *testing.T) {
	api := &APIServer{}
	const session = "s-overlapping-tool-calls"
	first := claudePreToolUseForOperationTest(session, "toolu_001730")
	second := claudePreToolUseForOperationTest(session, "toolu_001731")

	api.emitClaudeCodeHookLLMEvent(t.Context(), first, nil, nil)
	firstTransition, ok := api.hookLifecycleSnapshot("claudecode", session, "")
	if !ok || firstTransition.ToolID != first.ToolUseID || firstTransition.OperationID == "" {
		t.Fatalf("first transition = %+v, %t", firstTransition, ok)
	}
	api.emitClaudeCodeHookLLMEvent(t.Context(), second, nil, nil)
	secondTransition, ok := api.hookLifecycleSnapshot("claudecode", session, "")
	if !ok || secondTransition.OperationID == firstTransition.OperationID {
		t.Fatalf("second transition = %+v, %t; want its own operation", secondTransition, ok)
	}

	req := agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: session,
		ToolName: "Bash", ToolInvocationID: first.ToolUseID, Payload: first.Payload,
	}
	decision, _, ok := api.hookDecisionMeta(t.Context(), req)
	if !ok {
		t.Fatal("decision meta missing")
	}
	if decision.OperationID != firstTransition.OperationID || decision.Sequence != firstTransition.Sequence ||
		decision.Phase != firstTransition.Phase {
		t.Fatalf("first call decision operation=%q sequence=%d phase=%q, want its own %q %d %q (second call %q %d)",
			decision.OperationID, decision.Sequence, decision.Phase,
			firstTransition.OperationID, firstTransition.Sequence, firstTransition.Phase,
			secondTransition.OperationID, secondTransition.Sequence)
	}

	env := HookAuditEnvelope{}
	api.stampHookEnvelopeIdentity(t.Context(), "claudecode", &env, req, agentHookResponse{Action: "allow"})
	if env.AgentOperationID != firstTransition.OperationID || env.AgentSequence != firstTransition.Sequence {
		t.Fatalf("first call audit row operation=%q sequence=%d, want %q %d (second call %q)",
			env.AgentOperationID, env.AgentSequence, firstTransition.OperationID, firstTransition.Sequence,
			secondTransition.OperationID)
	}
}

// When this delivery's own transition is no longer retained, the session
// cursor may belong to another tool call. The decision then keeps its own
// operation and borrows no phase sequence from the other call.
func TestHookDeliveryPhaseSnapshotNeverBorrowsAnotherToolCallsOperation(t *testing.T) {
	api := &APIServer{}
	const session = "s-evicted-transition"
	first := claudePreToolUseForOperationTest(session, "toolu_a")
	second := claudePreToolUseForOperationTest(session, "toolu_b")
	api.emitClaudeCodeHookLLMEvent(t.Context(), first, nil, nil)
	api.emitClaudeCodeHookLLMEvent(t.Context(), second, nil, nil)
	secondTransition, _ := api.hookLifecycleSnapshot("claudecode", session, "")
	api.llmPromptMu.Lock()
	for key, state := range api.hookPhaseStates {
		if state.canonical {
			delete(api.hookPhaseStates, key)
		}
	}
	api.llmPromptMu.Unlock()

	req := agentHookRequest{
		ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: session,
		ToolName: "Bash", ToolInvocationID: first.ToolUseID, Payload: first.Payload,
	}
	decision, _, ok := api.hookDecisionMeta(t.Context(), req)
	if !ok {
		t.Fatal("decision meta missing")
	}
	want := hookOperationID(llmEventMeta{
		Source: decision.Source, SessionID: decision.SessionID, AgentID: decision.AgentID, ToolID: first.ToolUseID,
	})
	if decision.OperationID != want || decision.OperationID == secondTransition.OperationID {
		t.Fatalf("decision operation=%q, want its own %q (cursor holds %q)", decision.OperationID, want, secondTransition.OperationID)
	}
	if decision.Sequence == secondTransition.Sequence && decision.Sequence != 0 {
		t.Fatalf("decision borrowed the other call's sequence %d", decision.Sequence)
	}
}

// GAP-0246 end to end: concurrent PreToolUse hooks of one session through the
// real handler and audit store. Every connector-hook decision row links to a
// distinct operation, the one of its own tool call.
func TestConcurrentClaudeHookDecisionsLinkToTheirOwnOperations(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	remote := newHookRemoteRecorder()
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
	cwd := t.TempDir()
	const session, calls = "s-concurrent-decisions", 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan string, calls)
	for i := range calls {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]any{
				"hook_event_name": "PreToolUse", "session_id": session, "cwd": cwd, "tool_name": "Bash",
				"tool_use_id": fmt.Sprintf("toolu_%03d", i), "tool_input": map[string]any{"command": "echo ok"},
			})
			<-start
			recorder := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(recorder,
				httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
			if recorder.Code != http.StatusOK {
				errs <- fmt.Sprintf("call %d: status %d: %s", i, recorder.Code, recorder.Body.String())
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}

	db, err := sql.Open("sqlite", "file:"+fixture.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A benign per-user allow keeps one local row, its hook_decision row,
	// which names the operation of its own tool call; connector-hook and
	// tool_start are exported only (#1384).
	rows, err := db.Query(`SELECT action, `+audit.StructuredJSONReadSQL("", true, true)+`,
		COALESCE(json_extract(projected_record_json,'$.correlation.tool_invocation_id'),'')
		FROM audit_events WHERE session_id=? AND action IN ('hook_decision','connector-hook','tool_invocation')`, session)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	// A benign per-user allow stores only its hook_decision row; the tool
	// record of the same call is exported (#1384). Each decision row names
	// the operation of the requested tool record of its own tool call.
	decisions := map[string]int{}
	decisionOfTool := map[string]string{}
	decisionRows := 0
	for rows.Next() {
		var action, toolID string
		var structured sql.NullString
		if err := rows.Scan(&action, &structured, &toolID); err != nil {
			t.Fatal(err)
		}
		var doc any
		_ = json.Unmarshal([]byte(structured.String), &doc)
		switch action {
		case "hook_decision":
			decisionRows++
			id := findJSONString(doc, "defenseclaw.operation.id")
			decisions[id]++
			decisionOfTool[toolID] = id
		default:
			t.Errorf("a %s row of a benign per-user allow is stored; it is exported only", action)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	remote.waitExported(observability.TelemetryEventToolInvocationRequested, calls)
	toolOperations := map[string]string{}
	for _, record := range remote.exported(observability.TelemetryEventToolInvocationRequested) {
		var doc any
		if err := json.Unmarshal([]byte(record), &doc); err != nil {
			t.Fatalf("exported tool record is not JSON: %v", err)
		}
		toolOperations[findJSONString(doc, "tool_invocation_id")] = findJSONString(doc, "defenseclaw.operation.id")
	}
	if decisionRows != calls || len(toolOperations) != calls || len(decisions) != calls {
		t.Fatalf("decision rows=%d distinct decision operations=%d exported tool records=%d, want %d each",
			decisionRows, len(decisions), len(toolOperations), calls)
	}
	for toolID, operation := range decisionOfTool {
		if operation == "" || toolOperations[toolID] != operation {
			t.Errorf("tool call %q: decision operation %q, its tool record names %q; want its own call", toolID, operation, toolOperations[toolID])
		}
	}
}

func findJSONString(doc any, key string) string {
	switch value := doc.(type) {
	case map[string]any:
		if s, ok := value[key].(string); ok {
			return s
		}
		for _, child := range value {
			if s := findJSONString(child, key); s != "" {
				return s
			}
		}
	case []any:
		for _, child := range value {
			if s := findJSONString(child, key); s != "" {
				return s
			}
		}
	}
	return ""
}
