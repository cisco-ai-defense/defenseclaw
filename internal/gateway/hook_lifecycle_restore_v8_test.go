// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type hookLifecycleHistoryStub struct {
	sidecarRuntimeEmitter
	projection audit.LifecycleProjection
	found      bool
	err        error
	calls      int
	query      audit.LifecycleProjectionQuery
}

func (stub *hookLifecycleHistoryStub) LatestLifecycleProjection(
	_ context.Context,
	query audit.LifecycleProjectionQuery,
) (audit.LifecycleProjection, bool, error) {
	stub.calls++
	stub.query = query
	return stub.projection, stub.found, stub.err
}

func restartHookMeta(event, phase, executionID string) llmEventMeta {
	return llmEventMeta{
		Source: "codex", SessionID: "session-child", AgentID: "agent-child",
		RootAgentID: "agent-child", RootSessionID: "session-child",
		LifecycleID: "derived-lifecycle", ExecutionID: executionID,
		LifecycleEvent: event, LifecycleState: "active", LifecycleOutcome: "attempted",
		LifecycleDedupe: "current-transition", Phase: phase,
		LineageProvenance: "inferred",
	}
}

func recoveredLifecycleProjection(event, state, phase string, sequence int64) audit.LifecycleProjection {
	return audit.LifecycleProjection{
		RecordID: "history-record", RootAgentID: "agent-root", ParentAgentID: "agent-parent",
		RootSessionID: "session-root", ParentSessionID: "session-parent",
		LifecycleID: "lifecycle-child", ExecutionID: "execution-before-restart",
		Event: event, State: state, Phase: phase, LineageProvenance: "reported",
		Depth: 2, Sequence: sequence,
	}
}

func TestRestoreHookLifecycleResumesVerifiedActiveCursorOnExactMemoryMiss(t *testing.T) {
	reader := &hookLifecycleHistoryStub{
		projection: recoveredLifecycleProjection("turn_start", "active", "planning", 7), found: true,
	}
	api := &APIServer{observabilityV8: reader}
	incoming := restartHookMeta("tool_start", "tool", "execution-after-restart")

	restored := api.restoreHookSessionLifecycle(t.Context(), incoming)
	if reader.calls != 1 || reader.query != (audit.LifecycleProjectionQuery{
		Connector: "codex", SessionID: "session-child", AgentID: "agent-child",
	}) {
		t.Fatalf("history reads=%d query=%#v", reader.calls, reader.query)
	}
	if restored.RootAgentID != "agent-root" || restored.ParentAgentID != "agent-parent" ||
		restored.RootSessionID != "session-root" || restored.ParentSessionID != "session-parent" ||
		restored.LifecycleID != "lifecycle-child" || restored.ExecutionID != "execution-before-restart" ||
		restored.AgentDepth != 2 || restored.LineageProvenance != "reported" {
		t.Fatalf("restored active identity=%#v", restored)
	}
	if restored.TraceEventID != "" || restored.RequestID != "" || restored.ToolID != "" {
		t.Fatalf("recovery restored request-local handles: %#v", restored)
	}
	prepared, record := api.prepareHookLifecycleTransition(restored)
	if !record || prepared.Sequence != 8 || prepared.PreviousPhase != "planning" || prepared.Phase != "tool" {
		t.Fatalf("prepared restored transition record=%t meta=%#v", record, prepared)
	}

	second := restartHookMeta("turn_start", "planning", "different-fresh-execution")
	second = api.restoreHookSessionLifecycle(t.Context(), second)
	second = api.mergeHookSessionLifecycle(second)
	if reader.calls != 1 || second.ExecutionID != "execution-before-restart" || second.RootAgentID != "agent-root" {
		t.Fatalf("second hook reads=%d meta=%#v", reader.calls, second)
	}
}

func TestRestoreHookLifecycleKeepsLineageButStartsFreshCursorAfterTerminalHistory(t *testing.T) {
	reader := &hookLifecycleHistoryStub{
		projection: recoveredLifecycleProjection("subagent_stop", "completed", "completed", 9), found: true,
	}
	api := &APIServer{observabilityV8: reader}
	incoming := restartHookMeta("turn_start", "planning", "execution-after-restart")

	restored := api.restoreHookSessionLifecycle(t.Context(), incoming)
	if restored.RootAgentID != "agent-root" || restored.ParentAgentID != "agent-parent" ||
		restored.LifecycleID != "lifecycle-child" || restored.ExecutionID == "" ||
		restored.ExecutionID == incoming.ExecutionID || restored.ExecutionID == reader.projection.ExecutionID ||
		restored.AgentDepth != 2 {
		t.Fatalf("terminal lineage restoration=%#v", restored)
	}
	freshExecution := restored.ExecutionID
	prepared, record := api.prepareHookLifecycleTransition(restored)
	if !record || prepared.Sequence != 1 || prepared.PreviousPhase != "" || prepared.Phase != "planning" {
		t.Fatalf("fresh post-terminal transition record=%t meta=%#v", record, prepared)
	}

	second := restartHookMeta("tool_start", "tool", "another-generated-execution")
	second = api.restoreHookSessionLifecycle(t.Context(), second)
	second = api.mergeHookSessionLifecycle(second)
	if reader.calls != 1 || second.ExecutionID != freshExecution {
		t.Fatalf("post-terminal execution was not retained: reads=%d meta=%#v", reader.calls, second)
	}
}

func TestRestoreHookLifecycleBypassesExplicitStarts(t *testing.T) {
	for _, test := range []struct {
		name string
		meta llmEventMeta
	}{
		{name: "session start", meta: restartHookMeta("session_start", "session", "fresh")},
		{name: "subagent start", meta: restartHookMeta("subagent_start", "session", "fresh")},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &hookLifecycleHistoryStub{
				projection: recoveredLifecycleProjection("turn_start", "active", "planning", 7), found: true,
			}
			api := &APIServer{observabilityV8: reader}
			got := api.restoreHookSessionLifecycle(t.Context(), test.meta)
			if reader.calls != 0 || !reflect.DeepEqual(got, test.meta) {
				t.Fatalf("bypass reads=%d got=%#v want=%#v", reader.calls, got, test.meta)
			}
		})
	}
}

func TestRestoreHookLifecycleResumesCursorWithoutOverridingReportedLineage(t *testing.T) {
	projection := recoveredLifecycleProjection("turn_start", "active", "planning", 7)
	incoming := restartHookMeta("tool_start", "tool", "execution-after-restart")
	incoming.RootAgentID = projection.RootAgentID
	incoming.ParentAgentID = projection.ParentAgentID
	// Session lineage is not part of the connector's reported-topology proof;
	// these derived/missing values should still be repaired from history.
	incoming.RootSessionID = "derived-session-root"
	incoming.ParentSessionID = ""
	incoming.LifecycleID = projection.LifecycleID
	incoming.AgentDepth = projection.Depth
	incoming.LineageProvenance = "reported"
	incoming.ParentAgentReported = true

	reader := &hookLifecycleHistoryStub{projection: projection, found: true}
	api := &APIServer{observabilityV8: reader}
	restored := api.restoreHookSessionLifecycle(t.Context(), incoming)
	if reader.calls != 1 || restored.ExecutionID != projection.ExecutionID ||
		restored.RootAgentID != incoming.RootAgentID || restored.ParentAgentID != incoming.ParentAgentID ||
		restored.RootSessionID != projection.RootSessionID || restored.ParentSessionID != projection.ParentSessionID ||
		restored.AgentDepth != incoming.AgentDepth {
		t.Fatalf("matching reported lineage recovery reads=%d meta=%#v", reader.calls, restored)
	}

	conflicting := incoming
	conflicting.ParentAgentID = "new-reported-parent"
	reader = &hookLifecycleHistoryStub{projection: projection, found: true}
	api = &APIServer{observabilityV8: reader}
	if got := api.restoreHookSessionLifecycle(t.Context(), conflicting); !reflect.DeepEqual(got, conflicting) {
		t.Fatalf("conflicting reported lineage was overridden: %#v", got)
	}
}

func TestRestoreHookLifecycleLeavesIncomingFactsOnRejectedHistory(t *testing.T) {
	reader := &hookLifecycleHistoryStub{found: false}
	api := &APIServer{observabilityV8: reader}
	incoming := restartHookMeta("turn_start", "planning", "fresh")
	if got := api.restoreHookSessionLifecycle(t.Context(), incoming); !reflect.DeepEqual(got, incoming) {
		t.Fatalf("rejected history changed incoming meta: %#v", got)
	}
}

func TestRestoreHookLifecycleRepairsOnlyImmutableSelfRootAfterRestart(t *testing.T) {
	projection := recoveredLifecycleProjection("turn_start", "active", "planning", 7)
	reader := &hookLifecycleHistoryStub{projection: projection, found: true}
	placeholder := restartHookMeta("subagent_stop", "completed", "execution-current")
	placeholder.LifecycleState = "completed"
	placeholder.LifecycleOutcome = "completed"
	placeholder.Sequence = 11
	placeholder.TraceEventID = "trace-current"
	key := hookSessionStateKey(placeholder)
	api := &APIServer{
		observabilityV8: reader,
		hookSessionStates: map[string]hookSessionState{
			key: {meta: placeholder, traceEventID: placeholder.TraceEventID},
		},
		hookSessionStateOrder: []string{key},
	}
	incoming := restartHookMeta("tool_start", "tool", "execution-generated")

	restored := api.restoreHookSessionLifecycle(t.Context(), incoming)
	if reader.calls != 1 || restored.RootAgentID != projection.RootAgentID ||
		restored.ParentAgentID != projection.ParentAgentID || restored.AgentDepth != projection.Depth ||
		restored.ExecutionID != placeholder.ExecutionID {
		t.Fatalf("immutable lineage repair calls=%d restored=%#v", reader.calls, restored)
	}
	snapshot, ok := api.hookLifecycleSnapshot(placeholder.Source, placeholder.SessionID, placeholder.AgentID)
	if !ok || snapshot.RootAgentID != projection.RootAgentID || snapshot.ParentAgentID != projection.ParentAgentID ||
		snapshot.AgentDepth != projection.Depth || snapshot.ExecutionID != placeholder.ExecutionID ||
		snapshot.LifecycleEvent != "subagent_stop" || snapshot.LifecycleState != "completed" ||
		snapshot.LifecycleOutcome != "completed" || snapshot.Phase != "completed" || snapshot.Sequence != 11 ||
		snapshot.TraceEventID != placeholder.TraceEventID {
		t.Fatalf("repair downgraded live terminal cursor present=%t snapshot=%#v", ok, snapshot)
	}
}

func TestRestoreHookLifecycleRepairsFlattenedRecursiveStopsFromVerifiedRetainedLineage(t *testing.T) {
	const (
		sessionID = "shared-root-session"
		rootID    = "agent-root"
		parentID  = "agent-depth-one"
		childID   = "agent-depth-two"
		grandID   = "agent-depth-three"
	)
	for _, test := range []struct {
		name     string
		agentID  string
		parentID string
		depth    int
	}{
		{name: "depth two", agentID: childID, parentID: parentID, depth: 2},
		{name: "depth three", agentID: grandID, parentID: childID, depth: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			retained := restartHookMeta("subagent_start", "session", "execution-from-start")
			retained.SessionID = sessionID
			retained.AgentID = test.agentID
			retained.RootAgentID = rootID
			retained.ParentAgentID = test.parentID
			retained.RootSessionID = sessionID
			retained.ParentSessionID = sessionID
			retained.AgentDepth = test.depth
			retained.LineageProvenance = "inferred"
			retained.ParentLineageResolved = true
			key := hookSessionStateKey(retained)
			api := &APIServer{
				hookSessionStates:     map[string]hookSessionState{key: {meta: retained}},
				hookSessionStateOrder: []string{key},
			}

			// Codex 0.136 repeats the child UUID on SubagentStop but reports only
			// the shared root session. Normalization therefore produces this
			// internally inferred, flattened root -> child edge.
			incoming := restartHookMeta("subagent_stop", "completed", "execution-current-delivery")
			incoming.SessionID = sessionID
			incoming.AgentID = test.agentID
			incoming.RootAgentID = rootID
			incoming.ParentAgentID = rootID
			incoming.RootSessionID = sessionID
			incoming.ParentSessionID = sessionID
			incoming.AgentDepth = 1
			incoming.LifecycleState = "completed"
			incoming.LifecycleOutcome = "completed"
			incoming.PreviousPhase = "planning"
			incoming.OperationID = "operation-current"
			incoming.Sequence = 41
			incoming.TraceEventID = "trace-current"
			incoming.RequestID = "request-current"
			incoming.TurnID = "turn-current"
			incoming.ToolID = "tool-current"
			incoming.FinishReasons = []string{"stop"}

			want := restoreRetainedHookLineage(incoming, retained)
			got := api.restoreHookSessionLifecycle(t.Context(), incoming)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("restored recursive stop=%#v want=%#v", got, want)
			}
		})
	}
}

func TestRestoreHookLifecycleDoesNotReparentUnverifiedOrReportedChildren(t *testing.T) {
	retained := restartHookMeta("tool_end", "planning", "execution-retained")
	retained.RootAgentID = "agent-root"
	retained.ParentAgentID = "agent-parent"
	retained.AgentDepth = 2
	retained.LineageProvenance = "inferred"
	key := hookSessionStateKey(retained)

	flattened := restartHookMeta("subagent_stop", "completed", "execution-current")
	flattened.RootAgentID = "agent-root"
	flattened.ParentAgentID = "agent-root"
	flattened.AgentDepth = 1
	api := &APIServer{
		hookSessionStates:     map[string]hookSessionState{key: {meta: retained}},
		hookSessionStateOrder: []string{key},
	}
	if got := api.restoreHookSessionLifecycle(t.Context(), flattened); !reflect.DeepEqual(got, flattened) {
		t.Fatalf("unverified inferred history reparented child: %#v", got)
	}

	retained.ParentLineageResolved = true
	api.hookSessionStates[key] = hookSessionState{meta: retained}
	reported := flattened
	reported.ParentAgentID = "connector-parent"
	reported.ParentAgentReported = true
	if got := api.restoreHookSessionLifecycle(t.Context(), reported); !reflect.DeepEqual(got, reported) {
		t.Fatalf("connector-reported parent was overwritten: %#v", got)
	}
}

func TestCodexHookRestoresNestedLifecycleFromSignedHistoryAfterAPIRestart(t *testing.T) {
	fixture := newSignedSidecarRuntimeFixture(t, true)
	firstAPI := &APIServer{}
	bindHookLifecycleV8(t, firstAPI, fixture.runtime)
	firstAPI.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "SubagentStart", SessionID: "restart-child-session", AgentID: "restart-child",
		AgentType: "subagent", Payload: map[string]any{
			"root_agent_id": "restart-root", "parent_agent_id": "restart-parent",
			"root_session_id": "restart-root-session", "parent_session_id": "restart-parent-session",
			"agent_depth": 2,
		},
	}, nil, nil)
	firstAPI.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "UserPromptSubmit", SessionID: "restart-child-session", TurnID: "restart-turn",
		AgentID: "restart-child", AgentType: "subagent", Prompt: "continue after restart",
		Payload: map[string]any{},
	}, nil, []byte(`{"prompt":"continue after restart"}`))

	before := readStoredHookLifecycleV8(t, fixture.path)
	if len(before) != 2 {
		t.Fatalf("pre-restart lifecycle rows=%d want=2", len(before))
	}
	wantExecution, _ := before[1].body["defenseclaw.agent.execution.id"].(string)
	if wantExecution == "" {
		t.Fatalf("pre-restart execution is missing: %#v", before[1].body)
	}

	// A new API object models gateway process-local correlation caches after a
	// restart while retaining the same signed mandatory v8 history.
	restartedAPI := &APIServer{}
	bindHookLifecycleV8(t, restartedAPI, fixture.runtime)
	restartedAPI.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "PreToolUse", SessionID: "restart-child-session", TurnID: "restart-turn",
		AgentID: "restart-child", AgentType: "subagent", ToolUseID: "restart-tool",
		Payload: map[string]any{"tool_name": "shell", "tool_input": map[string]any{"command": "true"}},
	}, nil, nil)

	after := readStoredHookLifecycleV8(t, fixture.path)
	if len(after) != 3 {
		t.Fatalf("post-restart lifecycle rows=%d want=3", len(after))
	}
	got := after[2].body
	if got["defenseclaw.agent.root.id"] != "restart-root" ||
		got["defenseclaw.agent.parent.id"] != "restart-parent" ||
		got["defenseclaw.session.root.id"] != "restart-root-session" ||
		got["defenseclaw.session.parent.id"] != "restart-parent-session" ||
		got["defenseclaw.agent.execution.id"] != wantExecution ||
		got["defenseclaw.agent.depth"] != float64(2) ||
		got["defenseclaw.agent.sequence"] != float64(3) ||
		got["defenseclaw.agent.phase.previous"] != "planning" {
		t.Fatalf("post-restart lifecycle projection=%#v", got)
	}
}
