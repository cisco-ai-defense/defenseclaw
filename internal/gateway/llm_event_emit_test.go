// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	osuser "os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestHookLLMEventMetaLifecycleCorrelation(t *testing.T) {
	gatewaylog.SetProcessRunID("gateway-run-a")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })

	root := hookLLMEventMeta(
		"codex", "session-stable", "turn-1", "gpt-5", "codex", "", "", "codex",
		map[string]interface{}{
			"hook_event_name": "SessionStart",
			"source":          "resume",
			"user_id":         "user-1",
		},
	)
	if root.AgentID == "" || root.LifecycleID == "" || root.ExecutionID == "" {
		t.Fatalf("root lifecycle identity is incomplete: %+v", root)
	}
	if root.ParentAgentID != "" || root.AgentDepth != 0 || !root.SessionResumed {
		t.Fatalf("root lifecycle hierarchy/resume = %+v", root)
	}
	if root.LifecycleEvent != "session_start" || root.LifecycleState != "active" || root.UserID != "user-1" {
		t.Fatalf("root lifecycle event/state/user = %+v", root)
	}

	child := hookLLMEventMeta(
		"codex", "session-stable", "turn-1", "gpt-5", "codex", "child-7", "worker", "explore",
		map[string]interface{}{"hook_event_name": "SubagentStart", "agent_id": "child-7"},
	)
	if child.ParentAgentID != root.AgentID || child.AgentDepth != 1 || child.LifecycleID == root.LifecycleID {
		t.Fatalf("child hierarchy = %+v, root=%+v", child, root)
	}

	gatewaylog.SetProcessRunID("gateway-run-b")
	resumed := hookLLMEventMeta(
		"codex", "session-stable", "turn-2", "gpt-5", "codex", "", "", "codex",
		map[string]interface{}{"hook_event_name": "SessionStart", "source": "resume"},
	)
	if resumed.LifecycleID != root.LifecycleID {
		t.Fatalf("lifecycle id changed across gateway restart: %q != %q", resumed.LifecycleID, root.LifecycleID)
	}
	if resumed.ExecutionID == root.ExecutionID {
		t.Fatalf("execution id did not change across gateway restart: %q", resumed.ExecutionID)
	}
	api := &APIServer{hookSessionStates: map[string]hookSessionState{
		hookSessionStateKey(root): {meta: root},
	}}
	turn := hookLLMEventMeta(
		"codex", "session-stable", "turn-3", "gpt-5", "codex", "", "", "codex",
		map[string]interface{}{"hook_event_name": "Stop"},
	)
	turn = api.mergeHookSessionLifecycle(turn)
	if !turn.SessionResumed || turn.SessionSource != "resume" {
		t.Fatalf("turn did not inherit resumed session metadata: %+v", turn)
	}
}

func TestHookSessionStateSnapshotExplicitAgentMissDoesNotSelectSibling(t *testing.T) {
	t.Parallel()
	root := llmEventMeta{
		Source: "codex", SessionID: "shared-session", AgentID: "agent-root",
		RootAgentID: "agent-root", RootSessionID: "shared-session",
	}
	sibling := llmEventMeta{
		Source: "codex", SessionID: "shared-session", AgentID: "agent-sibling",
		RootAgentID: "agent-root", ParentAgentID: "agent-root", RootSessionID: "shared-session", AgentDepth: 1,
	}
	rootKey := hookSessionStateKey(root)
	siblingKey := hookSessionStateKey(sibling)
	api := &APIServer{
		hookSessionStates: map[string]hookSessionState{
			rootKey:    {meta: root},
			siblingKey: {meta: sibling},
		},
		hookSessionStateOrder: []string{rootKey, siblingKey},
	}

	if got, ok := api.hookSessionStateSnapshot("codex", "shared-session", "agent-missing"); ok {
		t.Fatalf("explicit agent miss selected unrelated state: %+v", got.meta)
	}
}

func TestHookDecisionMetaReusesLifecycleExecutionAcrossStartTurnResumeAndChild(t *testing.T) {
	api := &APIServer{}
	assertCursor := func(label string, req codexHookRequest) llmEventMeta {
		t.Helper()
		api.emitCodexHookLLMEvent(t.Context(), req, nil, nil)
		snapshot, ok := api.hookLifecycleSnapshot("codex", req.SessionID, req.AgentID)
		if !ok {
			t.Fatalf("%s lifecycle snapshot missing", label)
		}
		decision, _, ok := api.hookDecisionMeta(t.Context(), agentHookRequest{
			ConnectorName: "codex",
			AgentID:       req.AgentID,
			AgentName:     payloadString(req.Payload, "agent_name"),
			AgentType:     req.AgentType,
			HookEventName: req.HookEventName,
			SessionID:     req.SessionID,
			TurnID:        req.TurnID,
			Payload:       req.Payload,
		})
		if !ok {
			t.Fatalf("%s decision meta missing", label)
		}
		if decision.ExecutionID == "" || decision.ExecutionID != snapshot.ExecutionID {
			t.Errorf("%s decision execution=%q want retained lifecycle execution=%q", label, decision.ExecutionID, snapshot.ExecutionID)
		}
		if decision.LifecycleID != snapshot.LifecycleID || decision.OperationID != snapshot.OperationID ||
			decision.Phase != snapshot.Phase || decision.Sequence != snapshot.Sequence {
			t.Errorf("%s decision cursor=%+v want retained lifecycle cursor=%+v", label, decision, snapshot)
		}
		return snapshot
	}

	const (
		rootSession = "019f4ef9-3098-7d63-8bfe-1435139f1cce"
		rootAgent   = "agent-real-shaped-root"
	)
	start := codexHookRequest{
		HookEventName: "SessionStart", SessionID: rootSession, AgentID: rootAgent, AgentType: "codex",
		Payload: map[string]interface{}{
			"root_agent_id": rootAgent, "agent_depth": 0, "source": "startup",
		},
	}
	first := assertCursor("initial session start", start)

	turn := codexHookRequest{
		HookEventName: "UserPromptSubmit", SessionID: rootSession, TurnID: "turn-real-1",
		AgentID: rootAgent, AgentType: "codex", Prompt: "continue the same execution",
		Payload: map[string]interface{}{"root_agent_id": rootAgent, "agent_depth": 0},
	}
	active := assertCursor("following turn", turn)
	if active.ExecutionID != first.ExecutionID {
		t.Fatalf("following turn execution=%q want active start execution=%q", active.ExecutionID, first.ExecutionID)
	}

	resume := start
	resume.Payload = map[string]interface{}{
		"root_agent_id": rootAgent, "agent_depth": 0, "source": "resume",
	}
	second := assertCursor("resumed session start", resume)
	if second.ExecutionID == first.ExecutionID {
		t.Fatalf("resumed session did not rotate execution %q", first.ExecutionID)
	}

	child := codexHookRequest{
		HookEventName: "SubagentStart", SessionID: "019f4ef9-child-session", TurnID: "turn-child-1",
		AgentID: "agent-real-shaped-child", AgentType: "codex",
		Payload: map[string]interface{}{
			"root_agent_id": rootAgent, "parent_agent_id": rootAgent,
			"root_session_id": rootSession, "parent_session_id": rootSession,
			"agent_depth": 1, "task": "verify execution correlation",
		},
	}
	childSnapshot := assertCursor("subagent start", child)
	if childSnapshot.ExecutionID == second.ExecutionID {
		t.Fatalf("child reused parent execution %q", second.ExecutionID)
	}
}

func TestHookDecisionMetaKeepsExplicitUnknownParentAgent(t *testing.T) {
	root := llmEventMeta{
		Source: "geminicli", SessionID: "parent-session", AgentID: "retained-root",
		RootAgentID: "retained-root", RootSessionID: "parent-session",
		LifecycleID: "root-lifecycle", ExecutionID: "root-execution", AgentDepth: 0,
	}
	rootKey := hookSessionStateKey(root)
	api := &APIServer{
		hookSessionStates:     map[string]hookSessionState{rootKey: {meta: root}},
		hookSessionStateOrder: []string{rootKey},
	}
	req := agentHookRequest{
		ConnectorName: "geminicli", HookEventName: "BeforeTool", SessionID: "child-session",
		TurnID: "child-turn", AgentID: "child-agent", AgentName: "child", AgentType: "subagent",
		ToolName: "Bash",
		Payload: map[string]any{
			"root_agent_id": "reported-root", "parent_agent_id": "explicit-unknown",
			"parent_session_id": "parent-session", "agent_depth": 2,
			"tool_call_id": "child-call",
		},
	}

	meta, _, ok := api.hookDecisionMeta(t.Context(), req)
	if !ok {
		t.Fatal("hook decision meta was not produced")
	}
	if meta.ParentAgentID != "explicit-unknown" {
		t.Fatalf("explicit unknown parent was replaced: %+v", meta)
	}
	if meta.RootAgentID != "reported-root" {
		t.Fatalf("explicit lineage root was replaced by conversation fallback: %+v", meta)
	}
}

func TestHookDecisionMetaResolvesParentSessionWhenParentAgentIsNotReported(t *testing.T) {
	root := llmEventMeta{
		Source: "geminicli", SessionID: "parent-session", AgentID: "retained-root",
		RootAgentID: "retained-root", RootSessionID: "parent-session",
		LifecycleID: "root-lifecycle", ExecutionID: "root-execution", AgentDepth: 0,
	}
	rootKey := hookSessionStateKey(root)
	api := &APIServer{
		hookSessionStates:     map[string]hookSessionState{rootKey: {meta: root}},
		hookSessionStateOrder: []string{rootKey},
	}
	req := agentHookRequest{
		ConnectorName: "geminicli", HookEventName: "BeforeTool", SessionID: "child-session",
		TurnID: "child-turn", AgentID: "child-agent", AgentName: "child", AgentType: "subagent",
		ToolName: "Bash",
		Payload: map[string]any{
			"parent_session_id": "parent-session", "agent_depth": 1,
			"tool_call_id": "child-call",
		},
	}

	meta, _, ok := api.hookDecisionMeta(t.Context(), req)
	if !ok {
		t.Fatal("hook decision meta was not produced")
	}
	if meta.ParentAgentID != root.AgentID || meta.RootAgentID != root.RootAgentID {
		t.Fatalf("parent-session-only lineage was not reconciled: %+v", meta)
	}
}

func TestMergeHookSessionLifecyclePreservesStoredInferredLineage(t *testing.T) {
	t.Parallel()
	stored := llmEventMeta{
		Source: "codex", SessionID: "child-session", AgentID: "agent-child",
		RootAgentID: "agent-root", ParentAgentID: "agent-root", LineageProvenance: "inferred",
		RootSessionID: "root-session", ParentSessionID: "root-session", AgentDepth: 1,
		LifecycleID: "lifecycle-child", ExecutionID: "execution-child",
	}
	api := &APIServer{hookSessionStates: map[string]hookSessionState{
		hookSessionStateKey(stored): {meta: stored},
	}}
	incoming := llmEventMeta{
		Source: "codex", SessionID: "child-session", AgentID: "agent-child",
		RootAgentID: "agent-child", LineageProvenance: "inferred",
		RootSessionID: "child-session", LifecycleEvent: "tool_start",
	}

	merged := api.mergeHookSessionLifecycle(incoming)
	if merged.RootAgentID != "agent-root" || merged.ParentAgentID != "agent-root" || merged.AgentDepth != 1 {
		t.Fatalf("stored child lineage drifted on a later event: %+v", merged)
	}
	if merged.RootSessionID != "root-session" || merged.ParentSessionID != "root-session" {
		t.Fatalf("stored session lineage drifted on a later event: %+v", merged)
	}
}

func TestMergeHookSessionLifecycleTrustsLiveResolvedParentOverSelfRootPlaceholder(t *testing.T) {
	t.Parallel()
	stored := llmEventMeta{
		Source: "codex", SessionID: "child-session", AgentID: "agent-child",
		RootAgentID: "agent-child", LineageProvenance: "inferred",
		RootSessionID: "child-session", AgentDepth: 0,
		LifecycleID: "lifecycle-child", ExecutionID: "execution-child",
		LifecycleEvent: "tool_end", Sequence: 2,
	}
	api := &APIServer{hookSessionStates: map[string]hookSessionState{
		hookSessionStateKey(stored): {meta: stored},
	}}
	incoming := llmEventMeta{
		Source: "codex", SessionID: "child-session", AgentID: "agent-child",
		RootAgentID: "agent-root", ParentAgentID: "agent-root", ParentAgentReported: true,
		ParentLineageResolved: true,
		LineageProvenance:     "inferred", RootSessionID: "child-session", AgentDepth: 1,
		LifecycleID: "lifecycle-child", ExecutionID: "execution-child",
		LifecycleEvent: "subagent_stop", Sequence: 3,
	}

	merged := api.mergeHookSessionLifecycle(incoming)
	if merged.RootAgentID != "agent-root" || merged.ParentAgentID != "agent-root" || merged.AgentDepth != 1 {
		t.Fatalf("live resolved parent did not replace self-root placeholder: %+v", merged)
	}
	if merged.LineageProvenance != "inferred" {
		t.Fatalf("partially inferred lineage was mislabeled reported: %+v", merged)
	}
	if !merged.ParentLineageResolved {
		t.Fatalf("live resolved parent lost its authority marker: %+v", merged)
	}
}

func TestMergeHookSessionLifecycleTrustsFullyReportedNestedLineage(t *testing.T) {
	t.Parallel()
	stored := llmEventMeta{
		Source: "codex", SessionID: "grandchild-session", AgentID: "agent-grandchild",
		RootAgentID: "agent-root-old", ParentAgentID: "agent-parent-old", LineageProvenance: "inferred",
		RootSessionID: "root-session-old", ParentSessionID: "parent-session-old", AgentDepth: 2,
		LifecycleID: "lifecycle-grandchild", ExecutionID: "execution-grandchild",
	}
	api := &APIServer{hookSessionStates: map[string]hookSessionState{
		hookSessionStateKey(stored): {meta: stored},
	}}
	incoming := llmEventMeta{
		Source: "codex", SessionID: "grandchild-session", AgentID: "agent-grandchild",
		RootAgentID: "agent-root-new", ParentAgentID: "agent-parent-new", ParentAgentReported: true,
		LineageProvenance: "reported", RootSessionID: "root-session-new",
		ParentSessionID: "parent-session-new", AgentDepth: 3,
		LifecycleID: "lifecycle-grandchild", ExecutionID: "execution-grandchild",
	}

	merged := api.mergeHookSessionLifecycle(incoming)
	if merged.RootAgentID != "agent-root-new" || merged.ParentAgentID != "agent-parent-new" || merged.AgentDepth != 3 {
		t.Fatalf("fully reported nested lineage was replaced by snapshot: %+v", merged)
	}
	if merged.RootSessionID != "root-session-new" || merged.ParentSessionID != "parent-session-new" {
		t.Fatalf("fully reported nested sessions were replaced by snapshot: %+v", merged)
	}
}

func TestMergeHookSessionLifecycleTrustsExplicitParentOverUnverifiedDepthOneFallback(t *testing.T) {
	t.Parallel()
	stored := llmEventMeta{
		Source: "codex", SessionID: "child-session", AgentID: "agent-child",
		RootAgentID: "fallback-root", ParentAgentID: "fallback-root", LineageProvenance: "inferred",
		RootSessionID: "child-session", ParentSessionID: "child-session", AgentDepth: 1,
		LifecycleID: "lifecycle-child", ExecutionID: "execution-child",
	}
	api := &APIServer{hookSessionStates: map[string]hookSessionState{
		hookSessionStateKey(stored): {meta: stored},
	}}
	incoming := llmEventMeta{
		Source: "codex", SessionID: "child-session", AgentID: "agent-child",
		RootAgentID: "reported-parent", ParentAgentID: "reported-parent", ParentAgentReported: true,
		ParentLineageResolved: true, LineageProvenance: "inferred",
		RootSessionID: "reported-session", ParentSessionID: "reported-session", AgentDepth: 1,
		LifecycleID: "lifecycle-child", ExecutionID: "execution-child",
	}

	merged := api.mergeHookSessionLifecycle(incoming)
	if merged.RootAgentID != incoming.RootAgentID || merged.ParentAgentID != incoming.ParentAgentID ||
		merged.RootSessionID != incoming.RootSessionID || merged.ParentSessionID != incoming.ParentSessionID ||
		merged.AgentDepth != incoming.AgentDepth {
		t.Fatalf("unverified fallback outranked explicit parent: %+v", merged)
	}
}

func TestMergeHookSessionLifecyclePreservesNestedRootForUnresolvedParentOnlyEvent(t *testing.T) {
	t.Parallel()
	stored := llmEventMeta{
		Source: "codex", SessionID: "grandchild-session", AgentID: "agent-grandchild",
		RootAgentID: "agent-root", ParentAgentID: "agent-parent-old", LineageProvenance: "inferred",
		ParentLineageResolved: true,
		RootSessionID:         "root-session", ParentSessionID: "parent-session", AgentDepth: 2,
		LifecycleID: "lifecycle-grandchild", ExecutionID: "execution-grandchild",
	}
	api := &APIServer{hookSessionStates: map[string]hookSessionState{
		hookSessionStateKey(stored): {meta: stored},
	}}
	incoming := llmEventMeta{
		Source: "codex", SessionID: "grandchild-session", AgentID: "agent-grandchild",
		RootAgentID: "agent-parent-new", ParentAgentID: "agent-parent-new", ParentAgentReported: true,
		LineageProvenance: "inferred", RootSessionID: "grandchild-session", AgentDepth: 1,
		LifecycleID: "lifecycle-grandchild", ExecutionID: "execution-grandchild",
		LifecycleEvent: "tool_end",
	}

	merged := api.mergeHookSessionLifecycle(incoming)
	if merged.RootAgentID != "agent-root" || merged.AgentDepth != 2 {
		t.Fatalf("unresolved parent-only event replaced canonical root/depth: %+v", merged)
	}
	if merged.ParentAgentID != "agent-parent-new" {
		t.Fatalf("explicit parent was not overlaid on canonical lineage: %+v", merged)
	}
	if merged.RootSessionID != "root-session" || merged.ParentSessionID != "parent-session" {
		t.Fatalf("unresolved parent-only event replaced canonical sessions: %+v", merged)
	}
}

func TestRememberHookSessionStateDoesNotCorruptExistingParentFromChildFallback(t *testing.T) {
	t.Parallel()
	api := &APIServer{}
	root := llmEventMeta{
		Source: "codex", SessionID: "shared-session", AgentID: "agent-root",
		RootAgentID: "agent-root", LineageProvenance: "inferred", RootSessionID: "shared-session",
		LifecycleID: "lifecycle-root", ExecutionID: "execution-root", LifecycleEvent: "session_start",
	}
	api.rememberHookSessionState(context.Background(), root)
	childWithBadFallback := llmEventMeta{
		Source: "codex", SessionID: "shared-session", AgentID: "agent-child",
		RootAgentID: "agent-child", ParentAgentID: "agent-root", LineageProvenance: "inferred",
		RootSessionID: "shared-session", AgentDepth: 1,
		LifecycleID: "lifecycle-child", ExecutionID: "execution-child", LifecycleEvent: "subagent_start",
	}
	api.rememberHookSessionState(context.Background(), childWithBadFallback)

	stored, ok := api.hookSessionStateSnapshot("codex", "shared-session", "agent-root")
	if !ok {
		t.Fatal("root state was lost")
	}
	if stored.meta.RootAgentID != "agent-root" || stored.meta.ParentAgentID != "" || stored.meta.AgentDepth != 0 {
		t.Fatalf("child fallback corrupted the existing root: %+v", stored.meta)
	}
}

func TestNormalizeAgentHookRequestLabelsLifecycleEvents(t *testing.T) {
	for _, tc := range []struct {
		event string
		want  string
	}{
		{event: "SubagentStart", want: "subagent"},
		{event: "SubagentStop", want: "subagent"},
		{event: "session.created", want: "session"},
		{event: "session.updated", want: "session"},
		{event: "session.status", want: "session"},
		{event: "session.idle", want: "session"},
		{event: "session.compacted", want: "session"},
		{event: "session.error", want: "session"},
		{event: "session.deleted", want: "session"},
	} {
		t.Run(tc.event, func(t *testing.T) {
			req := normalizeAgentHookRequest("opencode", map[string]interface{}{
				"hook_event_name": tc.event,
				"session_id":      "session-1",
			})
			if req.ToolName != tc.want {
				t.Fatalf("ToolName=%q want %q", req.ToolName, tc.want)
			}
		})
	}
}

func TestStampEventCorrelationBackfillsStableLifecycleIDsIndependently(t *testing.T) {
	gatewaylog.SetProcessRunID("run-1")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })
	first := gatewaylog.Event{SessionID: "session-1", AgentID: "agent-1", Connector: "codex", AgentType: "codex"}
	stampEventCorrelation(&first, context.Background())
	if first.AgentLifecycleID == "" || first.AgentExecutionID == "" {
		t.Fatalf("missing derived IDs: %+v", first)
	}
	second := gatewaylog.Event{
		SessionID: "session-1", AgentID: "agent-1", Connector: "codex", AgentType: "subagent",
		AgentLifecycleID: first.AgentLifecycleID,
	}
	stampEventCorrelation(&second, context.Background())
	if second.AgentLifecycleID != first.AgentLifecycleID || second.AgentExecutionID != first.AgentExecutionID {
		t.Fatalf("inconsistent derived IDs: first=%+v second=%+v", first, second)
	}
}

func TestHookExecutionRotatesWithinGatewayProcess(t *testing.T) {
	gatewaylog.SetProcessRunID("gateway-run-stable")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })
	api := &APIServer{}
	base := hookLLMEventMeta(
		"codex", "session-resumed", "", "gpt-5", "codex", "", "", "codex",
		map[string]interface{}{"hook_event_name": "SessionStart", "source": "resume"},
	)
	first := api.beginHookExecution(base)
	second := api.beginHookExecution(base)
	if first.LifecycleID != second.LifecycleID {
		t.Fatalf("stable lifecycle changed: %q != %q", first.LifecycleID, second.LifecycleID)
	}
	if first.ExecutionID == second.ExecutionID {
		t.Fatalf("resume attempts reused execution id %q", first.ExecutionID)
	}
}

func TestHookPhaseSequenceIsOrderedAndDirected(t *testing.T) {
	t.Parallel()
	api := &APIServer{}
	base := llmEventMeta{
		Source: "codex", SessionID: "phase-session", AgentID: "phase-agent",
		LifecycleID: "phase-lifecycle", ExecutionID: "phase-execution",
	}
	planning := base
	planning.LifecycleEvent = "turn_start"
	planning.LifecycleState = "active"
	planning.Phase = "planning"
	planning = api.enrichHookPhase(planning)
	// First phase has no predecessor: PreviousPhase must be empty so the
	// gateway-event schema serializes agent_previous_phase as null (the enum
	// rejects the "unknown" sentinel, which would drop the event).
	if planning.Sequence != 1 || planning.PreviousPhase != "" {
		t.Fatalf("first phase = %+v", planning)
	}
	tool := base
	tool.LifecycleEvent = "tool_start"
	tool.LifecycleState = "active"
	tool.Phase = "tool"
	tool = api.enrichHookPhase(tool)
	if tool.Sequence != 2 || tool.PreviousPhase != "planning" || tool.OperationID == "" {
		t.Fatalf("second phase = %+v", tool)
	}
	responding := base
	responding.LifecycleEvent = "turn_end"
	responding.LifecycleState = "completed"
	responding.Phase = "responding"
	responding = api.enrichHookPhase(responding)
	if responding.Sequence != 3 || responding.PreviousPhase != "tool" {
		t.Fatalf("third phase = %+v", responding)
	}
}

func TestHookPhaseSequenceSurvivesCanonicalCachePressure(t *testing.T) {
	api := &APIServer{}
	base := llmEventMeta{
		Source: "codex", SessionID: "long-session", AgentID: "long-agent",
		LifecycleID: "long-lifecycle", ExecutionID: "long-execution",
		LifecycleEvent: "turn_start", LifecycleState: "active", Phase: "planning",
	}
	var last llmEventMeta
	for i := 0; i < hookPromptCacheMaxEntries+2; i++ {
		meta := base
		meta.LifecycleDedupe = "transition-" + strconv.Itoa(i)
		if i%2 == 1 {
			meta.Phase = "model"
		}
		var record bool
		last, record = api.prepareHookLifecycleTransition(meta)
		if !record {
			t.Fatalf("unique transition %d was treated as replay", i)
		}
	}
	if want := int64(hookPromptCacheMaxEntries + 2); last.Sequence != want {
		t.Fatalf("sequence after cache pressure=%d want=%d", last.Sequence, want)
	}
	if len(api.hookPhaseStates) > hookPromptCacheMaxEntries || len(api.hookPhaseStateOrder) > hookPromptCacheMaxEntries {
		t.Fatalf("phase cache exceeded bound: states=%d order=%d", len(api.hookPhaseStates), len(api.hookPhaseStateOrder))
	}
}

func TestHookOperationIDPairsToolStartAndEndWithoutCollapsingTurn(t *testing.T) {
	t.Parallel()
	base := llmEventMeta{
		Source: "codex", SessionID: "operation-session", AgentID: "operation-agent",
		TurnID: "shared-turn", ToolName: "Bash",
	}
	firstStart := base
	firstStart.ToolID = "tool-call-1"
	firstStart = applyHookEventMeta(firstStart, "PreToolUse", map[string]interface{}{})
	firstEnd := base
	firstEnd.ToolID = "tool-call-1"
	firstEnd = applyHookEventMeta(firstEnd, "PostToolUse", map[string]interface{}{})
	secondStart := base
	secondStart.ToolID = "tool-call-2"
	secondStart = applyHookEventMeta(secondStart, "PreToolUse", map[string]interface{}{})
	if firstStart.OperationID == "" || firstStart.OperationID != firstEnd.OperationID {
		t.Fatalf("tool pair operation IDs differ: start=%q end=%q", firstStart.OperationID, firstEnd.OperationID)
	}
	if firstStart.OperationID == secondStart.OperationID {
		t.Fatalf("distinct tool calls in one turn collapsed to %q", firstStart.OperationID)
	}
}

func TestHermesNestedSubagentIdentityNormalizesChildSession(t *testing.T) {
	payload := map[string]interface{}{
		"hook_event_name": "subagent_start",
		"session_id":      "parent-hermes-session",
		"extra": map[string]interface{}{
			"parent_session_id": "parent-hermes-session",
			"child_session_id":  "child-hermes-session",
			"child_subagent_id": "child-hermes-id",
			"child_role":        "leaf",
		},
	}
	req := normalizeAgentHookRequest("hermes", payload)
	if req.SessionID != "child-hermes-session" || req.AgentID != "child-hermes-id" || req.AgentName != "leaf" {
		t.Fatalf("normalized child identity=%+v", req)
	}
	meta := applyHookEventMeta(
		hookLLMEventMeta("hermes", req.SessionID, req.TurnID, "", "hermes", req.AgentID, req.AgentName, req.AgentType, req.Payload),
		req.HookEventName, req.Payload,
	)
	if meta.ParentSessionID != "parent-hermes-session" || meta.ParentAgentID == "" || meta.AgentDepth != 1 {
		t.Fatalf("normalized child hierarchy=%+v", meta)
	}
}

func TestAllHookConnectorsNormalizeStableLifecycle(t *testing.T) {
	tests := []struct {
		connector string
		start     string
		end       string
		startWant string
		endWant   string
	}{
		{"codex", "SessionStart", "Stop", "session_start", "turn_end"},
		{"claudecode", "SessionStart", "SessionEnd", "session_start", "session_end"},
		{"hermes", "on_session_start", "on_session_end", "session_start", "session_end"},
		{"cursor", "sessionStart", "sessionEnd", "session_start", "session_end"},
		{"windsurf", "pre_user_prompt", "post_cascade_response", "turn_start", "turn_end"},
		{"geminicli", "SessionStart", "SessionEnd", "session_start", "session_end"},
		{"copilot", "sessionStart", "sessionEnd", "session_start", "session_end"},
		{"antigravity", "PreInvocation", "Stop", "turn_start", "turn_end"},
		{"openhands", "session_start", "session_end", "session_start", "session_end"},
		{"opencode", "session.created", "session.deleted", "session_start", "session_end"},
	}
	for _, tt := range tests {
		t.Run(tt.connector, func(t *testing.T) {
			base := llmEventMeta{
				Source: tt.connector, SessionID: "stable-session",
				AgentID: stableLLMEventID("agent", tt.connector, "stable-session", "root"),
			}
			base.LifecycleID = stableLLMEventID("lifecycle", tt.connector, base.SessionID, base.AgentID)
			start := applyHookEventMeta(base, tt.start, map[string]interface{}{})
			end := applyHookEventMeta(base, tt.end, map[string]interface{}{})
			if start.LifecycleEvent != tt.startWant || end.LifecycleEvent != tt.endWant {
				t.Fatalf("events start=%q end=%q", start.LifecycleEvent, end.LifecycleEvent)
			}
			if start.LifecycleID != end.LifecycleID {
				t.Fatalf("lifecycle changed: %q != %q", start.LifecycleID, end.LifecycleID)
			}
		})
	}
}

func TestExplicitSubagentConnectorsKeepStableChildIdentity(t *testing.T) {
	for _, connector := range []string{"codex", "claudecode", "cursor", "copilot", "hermes"} {
		t.Run(connector, func(t *testing.T) {
			startPayload := map[string]interface{}{
				"hook_event_name": "SubagentStart",
				"session_id":      "parent-session",
				"agent_name":      "researcher",
			}
			if connector == "hermes" {
				startPayload["hook_event_name"] = "subagent_start"
				startPayload["extra"] = map[string]interface{}{
					"child_subagent_id": "native-child", "child_role": "researcher",
				}
			} else {
				startPayload["agent_id"] = "native-child"
			}
			startReq := normalizeAgentHookRequest(connector, startPayload)
			start := applyHookEventMeta(
				hookLLMEventMeta(connector, startReq.SessionID, "", "", connector, startReq.AgentID, startReq.AgentName, startReq.AgentType, startReq.Payload),
				startReq.HookEventName, startReq.Payload,
			)
			stopPayload := map[string]interface{}{}
			for key, value := range startPayload {
				stopPayload[key] = value
			}
			if connector == "hermes" {
				stopPayload["hook_event_name"] = "subagent_stop"
			} else {
				stopPayload["hook_event_name"] = "SubagentStop"
			}
			stopReq := normalizeAgentHookRequest(connector, stopPayload)
			stop := applyHookEventMeta(
				hookLLMEventMeta(connector, stopReq.SessionID, "", "", connector, stopReq.AgentID, stopReq.AgentName, stopReq.AgentType, stopReq.Payload),
				stopReq.HookEventName, stopReq.Payload,
			)
			if start.AgentID != stop.AgentID || start.LifecycleID != stop.LifecycleID ||
				start.ParentAgentID == "" || stop.ParentAgentID == "" {
				t.Fatalf("child lifecycle start=%+v stop=%+v", start, stop)
			}
		})
	}
}

func TestHookLLMEventMetaFallsBackToLocalUser(t *testing.T) {
	current, err := osuser.Current()
	if err != nil || current == nil {
		t.Skipf("os/user current unavailable: %v", err)
	}

	meta := hookLLMEventMeta("codex", "sess", "turn", "gpt-5.5", "openai", "", "codex", "ide", map[string]interface{}{})
	if meta.UserID == "" && meta.UserName == "" {
		t.Fatalf("expected local user fallback, got user_id=%q user_name=%q", meta.UserID, meta.UserName)
	}
}

func TestHookUserEmailIsPseudonymized(t *testing.T) {
	userID, userName := userFromHookPayload(map[string]interface{}{"user_email": "Alice@Example.COM"})
	if userID == "" || strings.Contains(strings.ToLower(userID), "alice@example.com") {
		t.Fatalf("user email was not pseudonymized: %q", userID)
	}
	if strings.Contains(strings.ToLower(userName), "alice@example.com") {
		t.Fatalf("user name leaked email: %q", userName)
	}
}

func TestHookToolDestinationApp(t *testing.T) {
	cases := []struct {
		name       string
		serverName string
		toolName   string
		want       string
	}{
		{name: "explicit server", serverName: "github", toolName: "Bash", want: "mcp:github"},
		{name: "mcp tool name", toolName: "mcp__filesystem__read_file", want: "mcp:filesystem"},
		{name: "builtin tool", toolName: "apply_patch", want: "builtin"},
		{name: "empty tool", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hookToolDestinationApp(tc.serverName, tc.toolName); got != tc.want {
				t.Fatalf("hookToolDestinationApp(%q, %q) = %q, want %q", tc.serverName, tc.toolName, got, tc.want)
			}
		})
	}
}

func TestHookLifecycleTransitionDedupeCollapsesEquivalentTurnAndToolEvents(t *testing.T) {
	api := &APIServer{}

	turn := llmEventMeta{
		Source: "codex", SessionID: "session-1", TurnID: "turn-1", AgentID: "Agent/One",
		LifecycleID: "lifecycle-1", LifecycleEvent: "turn_end",
	}
	turn.LifecycleDedupe = hookLifecycleDedupeKey(turn, map[string]interface{}{"response_id": "response-1"})
	if !api.shouldRecordHookLifecycleTransition(turn) {
		t.Fatal("first turn_end transition was dropped")
	}
	afterModel := turn
	afterModel.LifecycleDedupe = hookLifecycleDedupeKey(afterModel, map[string]interface{}{"response_id": "response-1"})
	if api.shouldRecordHookLifecycleTransition(afterModel) {
		t.Fatal("duplicate model/stop transition was counted twice")
	}

	tool := llmEventMeta{
		Source: "codex", SessionID: "session-1", AgentID: "Agent/One",
		LifecycleID: "lifecycle-1", LifecycleEvent: "tool_start",
	}
	tool.LifecycleDedupe = hookLifecycleDedupeKey(tool, map[string]interface{}{"tool_call_id": "call-1"})
	if !api.shouldRecordHookLifecycleTransition(tool) {
		t.Fatal("first tool_start transition was dropped")
	}
	permission := tool
	permission.LifecycleDedupe = hookLifecycleDedupeKey(permission, map[string]interface{}{"tool_call_id": "call-1"})
	if api.shouldRecordHookLifecycleTransition(permission) {
		t.Fatal("duplicate permission/pre-tool transition was counted twice")
	}
}

func TestNormalizeHookReportedCostAccumulatesIncrementalPerCallCost(t *testing.T) {
	api := &APIServer{}
	meta := llmEventMeta{
		Source: "codex", SessionID: "session-1", AgentID: "agent-1", LifecycleID: "lifecycle-1",
		ReportedCost: true, ReportedCostUSD: 0.25,
	}
	first := api.normalizeHookReportedCost(meta)
	if first.ReportedCostUSD != 0.25 || !first.ReportedCostSum {
		t.Fatalf("first incremental cost = %+v, want cumulative 0.25", first)
	}
	meta.ReportedCostUSD = 0.50
	second := api.normalizeHookReportedCost(meta)
	if second.ReportedCostUSD != 0.75 || !second.ReportedCostSum {
		t.Fatalf("second incremental cost = %+v, want cumulative 0.75", second)
	}
	cumulative := meta
	cumulative.ReportedCostUSD = 1.25
	cumulative.ReportedCostSum = true
	if got := api.normalizeHookReportedCost(cumulative); got.ReportedCostUSD != 1.25 {
		t.Fatalf("cumulative reported cost changed: %+v", got)
	}
}

func TestHookLLMSpanPromptCacheIsBoundedAndCorrelatesOverlappingTurns(t *testing.T) {
	api := &APIServer{}
	for i := 0; i < hookPromptCacheMaxEntries+10; i++ {
		api.rememberHookLLMSpanPrompt(llmEventMeta{
			Source: "codex", SessionID: "session-" + strconv.Itoa(i), TurnID: "turn",
			PromptID: "prompt-" + strconv.Itoa(i),
		}, "prompt")
	}
	if got := len(api.hookLLMSpanPrompts); got > hookPromptCacheMaxEntries {
		t.Fatalf("prompt cache size=%d exceeds %d", got, hookPromptCacheMaxEntries)
	}
	if got := len(api.hookLLMSpanPromptOrder); got > hookPromptCacheMaxEntries {
		t.Fatalf("prompt cache order size=%d exceeds %d", got, hookPromptCacheMaxEntries)
	}

	overlap := &APIServer{}
	turn1 := llmEventMeta{Source: "codex", SessionID: "shared", TurnID: "1", PromptID: "p1"}
	turn2 := llmEventMeta{Source: "codex", SessionID: "shared", TurnID: "2", PromptID: "p2"}
	overlap.rememberHookLLMSpanPrompt(turn1, "first")
	overlap.rememberHookLLMSpanPrompt(turn2, "second")
	first, ok := overlap.takeHookLLMSpanPrompt(turn1, "response one")
	if !ok || first.content != "first" {
		t.Fatalf("first turn snapshot=%+v emit=%v", first, ok)
	}
	second, ok := overlap.takeHookLLMSpanPrompt(turn2, "response two")
	if !ok || second.content != "second" {
		t.Fatalf("second turn snapshot=%+v emit=%v", second, ok)
	}
}

func TestHookLLMSpanPromptCacheIsExecutionScoped(t *testing.T) {
	api := &APIServer{}
	executionA := llmEventMeta{
		Source: "codex", SessionID: "shared", AgentID: "agent", TurnID: "turn",
		PromptID: "prompt", ExecutionID: "execution-a",
	}
	executionB := executionA
	executionB.ExecutionID = "execution-b"

	api.rememberHookLLMSpanPrompt(executionA, "prompt from execution A")
	api.rememberHookLLMSpanPrompt(executionB, "prompt from execution B")

	first, ok := api.takeHookLLMSpanPrompt(executionA, "response from execution A")
	if !ok || first.content != "prompt from execution A" {
		t.Fatalf("execution A snapshot=%+v emit=%v", first, ok)
	}
	second, ok := api.takeHookLLMSpanPrompt(executionB, "response from execution B")
	if !ok || second.content != "prompt from execution B" {
		t.Fatalf("execution B snapshot=%+v emit=%v", second, ok)
	}
}

func TestHookLLMSpanUsageCacheIsExecutionScoped(t *testing.T) {
	api := &APIServer{}
	executionA := llmEventMeta{
		Source: "codex", SessionID: "shared", AgentID: "agent", TurnID: "turn",
		ExecutionID: "execution-a",
	}
	executionB := executionA
	executionB.ExecutionID = "execution-b"

	api.rememberHookLLMSpanUsage(executionA, hookTokenUsage{PromptTokens: 11, CompletionTokens: 12})
	api.rememberHookLLMSpanUsage(executionB, hookTokenUsage{PromptTokens: 21, CompletionTokens: 22})

	usageA := api.takeHookLLMSpanUsage(executionA)
	usageB := api.takeHookLLMSpanUsage(executionB)
	if usageA.promptTokens != 11 || usageA.completionTokens != 12 {
		t.Fatalf("execution A usage=%+v", usageA)
	}
	if usageB.promptTokens != 21 || usageB.completionTokens != 22 {
		t.Fatalf("execution B usage=%+v", usageB)
	}
}

func TestHookLLMSpanCompletionDedupeIsExecutionAndAgentScoped(t *testing.T) {
	t.Run("execution", func(t *testing.T) {
		api := &APIServer{}
		executionA := llmEventMeta{
			Source: "codex", SessionID: "shared", AgentID: "agent", TurnID: "turn",
			PromptID: "prompt", ExecutionID: "execution-a",
		}
		executionB := executionA
		executionB.ExecutionID = "execution-b"

		if _, ok := api.takeHookLLMSpanPrompt(executionA, "same response"); !ok {
			t.Fatal("first execution completion was suppressed")
		}
		if _, ok := api.takeHookLLMSpanPrompt(executionA, "same response"); ok {
			t.Fatal("exact replay inside one execution was not deduped")
		}
		if _, ok := api.takeHookLLMSpanPrompt(executionB, "same response"); !ok {
			t.Fatal("second execution completion was suppressed by the first")
		}
	})

	t.Run("agent", func(t *testing.T) {
		api := &APIServer{}
		agentA := llmEventMeta{
			Source: "codex", SessionID: "shared", AgentID: "agent-a", TurnID: "turn",
			PromptID: "prompt", ExecutionID: "execution",
		}
		agentB := agentA
		agentB.AgentID = "agent-b"

		if _, ok := api.takeHookLLMSpanPrompt(agentA, "same response"); !ok {
			t.Fatal("first agent completion was suppressed")
		}
		if _, ok := api.takeHookLLMSpanPrompt(agentB, "same response"); !ok {
			t.Fatal("second agent completion was suppressed by the first")
		}
	})
}

func TestBoundedHookLLMSpanContent(t *testing.T) {
	content := strings.Repeat("x", hookLLMSpanMaxContentBytes+100)
	if got := len(boundedHookLLMSpanContent(content)); got != hookLLMSpanMaxContentBytes {
		t.Fatalf("bounded content length=%d want %d", got, hookLLMSpanMaxContentBytes)
	}
}

func TestHookToolInvocationQueuePreservesRepeatedSameToolCalls(t *testing.T) {
	api := &APIServer{}
	meta := llmEventMeta{
		Source: "geminicli", SessionID: "session", AgentID: "agent", TurnID: "turn",
	}
	api.rememberHookToolInvocation(meta, "Bash", `{"command":"first"}`)
	api.rememberHookToolInvocation(meta, "Bash", `{"command":"second"}`)

	first, ok := api.takeHookToolInvocation(meta, "Bash", "first-result")
	if !ok || first.arguments != `{"command":"first"}` {
		t.Fatalf("first queued invocation=%+v ok=%v", first, ok)
	}
	second, ok := api.takeHookToolInvocation(meta, "Bash", "second-result")
	if !ok || second.arguments != `{"command":"second"}` {
		t.Fatalf("second queued invocation=%+v ok=%v", second, ok)
	}
	if len(api.hookToolInvocations) != 0 || len(api.hookToolInvocationOrder) != 0 {
		t.Fatalf("tool queue not drained: %#v %#v", api.hookToolInvocations, api.hookToolInvocationOrder)
	}
}

func TestHookToolInvocationCacheAndCompletionDedupeAreExecutionScoped(t *testing.T) {
	executionA := llmEventMeta{
		Source: "geminicli", SessionID: "session", AgentID: "agent", TurnID: "turn",
		ExecutionID: "execution-a",
	}
	executionB := executionA
	executionB.ExecutionID = "execution-b"

	t.Run("invocation cache", func(t *testing.T) {
		api := &APIServer{}
		api.rememberHookToolInvocation(executionA, "Bash", `{"command":"execution-a"}`)
		api.rememberHookToolInvocation(executionB, "Bash", `{"command":"execution-b"}`)

		second, ok := api.takeHookToolInvocation(executionB, "Bash", "same result")
		if !ok || second.arguments != `{"command":"execution-b"}` {
			t.Fatalf("execution B invocation=%+v emit=%v", second, ok)
		}
		first, ok := api.takeHookToolInvocation(executionA, "Bash", "same result")
		if !ok || first.arguments != `{"command":"execution-a"}` {
			t.Fatalf("execution A invocation=%+v emit=%v", first, ok)
		}
	})

	t.Run("completion dedupe", func(t *testing.T) {
		api := &APIServer{}
		if _, ok := api.takeHookToolInvocation(executionA, "Bash", "same result"); !ok {
			t.Fatal("first execution completion was suppressed")
		}
		if _, ok := api.takeHookToolInvocation(executionA, "Bash", "same result"); ok {
			t.Fatal("exact replay inside one execution was not deduped")
		}
		if _, ok := api.takeHookToolInvocation(executionB, "Bash", "same result"); !ok {
			t.Fatal("second execution completion was suppressed by the first")
		}
	})
}

func TestHookToolInvocationExactDeliveryDoesNotQueueTwice(t *testing.T) {
	api := &APIServer{}
	meta := llmEventMeta{
		Source: "geminicli", SessionID: "session", AgentID: "agent", TurnID: "turn",
		ExecutionID: "execution", ToolID: "tool-call",
	}
	arguments := `{"command":"printf ok"}`
	api.rememberHookToolInvocation(meta, "Bash", arguments)
	api.rememberHookToolInvocation(meta, "Bash", arguments)

	if _, ok := api.takeHookToolInvocation(meta, "Bash", "same result"); !ok {
		t.Fatal("first completion was suppressed")
	}
	if _, ok := api.takeHookToolInvocation(meta, "Bash", "same result"); ok {
		t.Fatal("exact completion replay consumed a duplicate queued delivery")
	}
	if len(api.hookToolInvocations) != 0 || len(api.hookToolInvocationOrder) != 0 {
		t.Fatalf("duplicate delivery left queued state: %#v %#v", api.hookToolInvocations, api.hookToolInvocationOrder)
	}
}

func TestHookToolInvocationNativeIDReplacesPendingArguments(t *testing.T) {
	api := &APIServer{}
	meta := llmEventMeta{
		Source: "geminicli", SessionID: "session", AgentID: "agent", TurnID: "turn",
		ExecutionID: "execution", ToolID: "tool-call",
	}
	api.rememberHookToolInvocation(meta, "Bash", `{"command":"printf old"}`)
	api.rememberHookToolInvocation(meta, "Bash", `{"command": "printf new"}`)

	if got := len(api.hookToolInvocations[hookToolInvocationKey(meta, "Bash")]); got != 1 {
		t.Fatalf("native tool ID queued %d pending invocations want=1", got)
	}
	if got := len(api.hookToolInvocationOrder); got != 1 {
		t.Fatalf("native tool ID queue order entries=%d want=1", got)
	}
	snapshot, ok := api.takeHookToolInvocation(meta, "Bash", "same result")
	if !ok || snapshot.arguments != `{"command": "printf new"}` {
		t.Fatalf("native tool ID completion snapshot=%+v emit=%v", snapshot, ok)
	}
	if _, ok := api.takeHookToolInvocation(meta, "Bash", "same result"); ok {
		t.Fatal("native tool ID completion replay was not deduped")
	}
}

func TestHookToolCompletionIdentityUsesNativeIDOrPendingInvocation(t *testing.T) {
	t.Run("native ID", func(t *testing.T) {
		api := &APIServer{}
		meta := llmEventMeta{
			Source: "geminicli", SessionID: "session", AgentID: "agent", TurnID: "turn",
			ExecutionID: "execution", ToolID: "tool-call",
		}
		if _, ok := api.takeHookToolInvocation(meta, "Bash", `{"output":"first"}`); !ok {
			t.Fatal("first native tool completion was suppressed")
		}
		if _, ok := api.takeHookToolInvocation(meta, "Bash", `{"output": "second"}`); ok {
			t.Fatal("native tool ID emitted a second completion after result serialization changed")
		}
		api.rememberHookToolInvocation(meta, "Bash", `{"command":"late replay"}`)
		if got := len(api.hookToolInvocations[hookToolInvocationKey(meta, "Bash")]); got != 0 {
			t.Fatalf("completed native tool ID requeued %d pending invocations", got)
		}
	})

	t.Run("no ID repeated calls", func(t *testing.T) {
		api := &APIServer{}
		meta := llmEventMeta{
			Source: "geminicli", SessionID: "session", AgentID: "agent", TurnID: "turn",
			ExecutionID: "execution",
		}
		api.rememberHookToolInvocation(meta, "Bash", `{"command":"first"}`)
		api.rememberHookToolInvocation(meta, "Bash", `{"command":"second"}`)
		first, firstOK := api.takeHookToolInvocation(meta, "Bash", "same result")
		second, secondOK := api.takeHookToolInvocation(meta, "Bash", "same result")
		if !firstOK || !secondOK || first.id == "" || second.id == "" || first.id == second.id {
			t.Fatalf("no-ID repeated completions first=%+v/%v second=%+v/%v", first, firstOK, second, secondOK)
		}
	})
}

func TestBeforeToolSelectionHasBoundedToolLifecycle(t *testing.T) {
	if got := canonicalHookLifecycleEvent("BeforeToolSelection"); got != "tool_start" {
		t.Fatalf("lifecycle=%q want tool_start", got)
	}
	if got := hookLifecyclePhase("BeforeToolSelection", "tool_start", "active"); got != "tool" {
		t.Fatalf("phase=%q want tool", got)
	}
}
