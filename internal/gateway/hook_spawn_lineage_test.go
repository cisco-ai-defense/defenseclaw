// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

func hookSpawnTestParent(source, sessionID, agentID, rootID string, depth int, toolID string) llmEventMeta {
	return llmEventMeta{
		Source: source, SessionID: sessionID, AgentID: agentID, AgentName: agentID,
		AgentType: "subagent", RootAgentID: rootID, RootSessionID: sessionID,
		LifecycleID: "lifecycle-" + agentID, ExecutionID: "execution-" + agentID,
		LifecycleEvent: "tool_end", LifecycleState: "active", LifecycleOutcome: "completed",
		AgentDepth: depth, ToolID: toolID, ToolName: "collaboration.spawn_agent",
	}
}

func hookSpawnTestChild(source, sessionID, agentID string) llmEventMeta {
	return llmEventMeta{
		Source: source, SessionID: sessionID, AgentID: agentID, AgentName: "subagent",
		AgentType: "subagent", RootAgentID: "flattened-root", ParentAgentID: "flattened-root",
		RootSessionID: sessionID, LifecycleID: "lifecycle-" + agentID,
		ExecutionID: "execution-" + agentID, LifecycleEvent: "subagent_start",
		LifecycleState: "active", LifecycleOutcome: "attempted", AgentDepth: 1,
		LineageProvenance: "inferred",
	}
}

func hookSpawnIntentCount(api *APIServer) int {
	api.llmPromptMu.Lock()
	defer api.llmPromptMu.Unlock()
	return len(api.hookSpawnIntents)
}

func TestCodexSpawnIntentBuildsFourLevelLineageFromRealHookOwnership(t *testing.T) {
	api := &APIServer{}
	const sessionID = "codex-nested-spawn-session"
	const rootID = "019f4d74-root-agent"
	api.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
		HookEventName: "SessionStart", SessionID: sessionID, AgentID: rootID, AgentType: "codex",
		Payload: map[string]any{"root_agent_id": rootID, "agent_depth": 0, "source": "startup"},
	}, nil, nil)

	levels := []struct {
		parentID string
		childID  string
		short    string
		full     string
	}{
		{rootID, "agent-phase1", "phase1_port_audit", "/root/upgrade_fail_safe/phase1_port_audit"},
		{"agent-phase1", "agent-review", "review_fail_safe", "/root/upgrade_fail_safe/phase1_port_audit/review_fail_safe"},
		{"agent-review", "agent-leaf", "verify_rollback", "/root/upgrade_fail_safe/phase1_port_audit/review_fail_safe/verify_rollback"},
	}
	for index, level := range levels {
		toolID := "spawn-call-" + strconv.Itoa(index+1)
		turnID := "turn-" + strconv.Itoa(index+1)
		request := codexHookRequest{
			HookEventName: "PreToolUse", SessionID: sessionID, TurnID: turnID,
			AgentID: level.parentID, AgentType: "subagent", ToolName: "collaboration.spawn_agent",
			ToolUseID: toolID, ToolInput: map[string]any{"task_name": level.short}, Payload: map[string]any{},
		}
		api.emitCodexHookLLMEvent(t.Context(), request, nil, nil)
		request.HookEventName = "PostToolUse"
		request.ToolResponse = map[string]any{"task_name": level.full, "status": "accepted"}
		api.emitCodexHookLLMEvent(t.Context(), request, nil, nil)
		api.emitCodexHookLLMEvent(t.Context(), codexHookRequest{
			HookEventName: "SubagentStart", SessionID: sessionID, TurnID: turnID,
			AgentID: level.childID, AgentType: "subagent",
			Payload: map[string]any{"task_name": level.full},
		}, nil, nil)

		child, ok := api.hookLifecycleSnapshot("codex", sessionID, level.childID)
		if !ok {
			t.Fatalf("level %d child %q was not retained", index+1, level.childID)
		}
		if child.ParentAgentID != level.parentID || child.RootAgentID != rootID ||
			child.AgentDepth != index+1 || child.LineageProvenance != "inferred" {
			t.Fatalf("level %d lineage=%+v", index+1, child)
		}
	}
	if got := hookSpawnIntentCount(api); got != 0 {
		t.Fatalf("consumed nested spawn intents=%d want=0", got)
	}
}

func TestClaudeAndGenericSpawnHooksUseOwningParent(t *testing.T) {
	t.Run("claude", func(t *testing.T) {
		api := &APIServer{}
		const sessionID = "claude-spawn-session"
		api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
			HookEventName: "SessionStart", SessionID: sessionID, AgentID: "claude-root", AgentType: "claudecode",
			Payload: map[string]any{"root_agent_id": "claude-root", "agent_depth": 0},
		}, nil, nil)
		request := claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: sessionID, AgentID: "claude-root", AgentType: "claudecode",
			ToolName: "collaboration.spawn_agent", ToolUseID: "claude-spawn-call",
			ToolInput: map[string]any{"task_name": "claude_child"}, Payload: map[string]any{},
		}
		api.emitClaudeCodeHookLLMEvent(t.Context(), request, nil, nil)
		request.HookEventName = "PostToolUse"
		request.ToolResponse = map[string]any{"task_name": "/root/claude_child"}
		api.emitClaudeCodeHookLLMEvent(t.Context(), request, nil, nil)
		api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
			HookEventName: "SubagentStart", SessionID: sessionID, AgentID: "claude-child", AgentType: "subagent",
			Payload: map[string]any{"task_name": "/root/claude_child"},
		}, nil, nil)
		child, ok := api.hookLifecycleSnapshot("claudecode", sessionID, "claude-child")
		if !ok || child.ParentAgentID != "claude-root" || child.RootAgentID != "claude-root" || child.AgentDepth != 1 {
			t.Fatalf("Claude child lineage=%+v retained=%v", child, ok)
		}
	})

	t.Run("generic", func(t *testing.T) {
		api := &APIServer{}
		const sessionID = "cursor-spawn-session"
		api.emitAgentHookLLMEvent(t.Context(), agentHookRequest{
			ConnectorName: "cursor", HookEventName: "SessionStart", SessionID: sessionID,
			AgentID: "cursor-root", AgentName: "cursor", AgentType: "cursor",
			Payload: map[string]any{"root_agent_id": "cursor-root", "agent_depth": 0},
		}, nil)
		args := json.RawMessage(`{"task_name":"cursor_child"}`)
		request := agentHookRequest{
			ConnectorName: "cursor", HookEventName: "PreToolUse", SessionID: sessionID,
			AgentID: "cursor-root", AgentName: "cursor", AgentType: "cursor",
			ToolName: "collaboration.spawn_agent", ToolArgs: args,
			Payload: map[string]any{"tool_call_id": "cursor-spawn-call"},
		}
		api.emitAgentHookLLMEvent(t.Context(), request, nil)
		request.HookEventName = "PostToolUse"
		request.Content = `{"task_name":"/root/cursor_child"}`
		api.emitAgentHookLLMEvent(t.Context(), request, nil)
		api.emitAgentHookLLMEvent(t.Context(), agentHookRequest{
			ConnectorName: "cursor", HookEventName: "SubagentStart", SessionID: sessionID,
			AgentID: "cursor-child", AgentName: "cursor_child", AgentType: "subagent",
			Payload: map[string]any{"task_name": "/root/cursor_child"},
		}, nil)
		child, ok := api.hookLifecycleSnapshot("cursor", sessionID, "cursor-child")
		if !ok || child.ParentAgentID != "cursor-root" || child.RootAgentID != "cursor-root" || child.AgentDepth != 1 {
			t.Fatalf("generic child lineage=%+v retained=%v", child, ok)
		}
	})
}

func TestHookSpawnIntentRejectsAmbiguousMismatchedAndCrossSessionJoins(t *testing.T) {
	api := &APIServer{}
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	parent := hookSpawnTestParent("codex", "session-a", "root-a", "root-a", 0, "spawn-alpha")
	api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentCompleted, now, `{"task_name":"alpha"}`)
	parent.ToolID = "spawn-beta"
	api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentCompleted, now, `{"task_name":"beta"}`)

	for name, test := range map[string]struct {
		child      llmEventMeta
		wantParent string
		wantDepth  int
	}{
		"missing identity": {hookSpawnTestChild("codex", "session-a", "child-no-name"), "", 0},
		"mismatch":         {hookSpawnTestChild("codex", "session-a", "child-gamma"), "", 0},
		"cross session":    {hookSpawnTestChild("codex", "session-b", "child-alpha"), "flattened-root", 1},
	} {
		payload := map[string]any{}
		if name == "mismatch" {
			payload["task_name"] = "gamma"
		}
		if name == "cross session" {
			payload["task_name"] = "alpha"
		}
		got := api.applyHookSpawnIntentLineageAt(test.child, payload, now)
		if got.ParentAgentID != test.wantParent || got.AgentDepth != test.wantDepth {
			t.Fatalf("%s false join=%+v", name, got)
		}
		if test.wantParent == "" && (got.RootAgentID != got.AgentID || got.LineageProvenance != "") {
			t.Fatalf("%s retained a false root edge/provenance: %+v", name, got)
		}
	}
	if got := hookSpawnIntentCount(api); got != 2 {
		t.Fatalf("nonmatches consumed intents=%d want=2", got)
	}

	matched := api.applyHookSpawnIntentLineageAt(
		hookSpawnTestChild("codex", "session-a", "child-alpha"),
		map[string]any{"task_name": "/root/work/alpha"}, now,
	)
	if matched.ParentAgentID != "root-a" || matched.AgentDepth != 1 {
		t.Fatalf("unique alias did not match owning parent: %+v", matched)
	}
	if got := hookSpawnIntentCount(api); got != 1 {
		t.Fatalf("unique match remaining intents=%d want=1", got)
	}
}

func TestHookSpawnIntentRejectsAmbiguousOwnersAndToolIDCollisions(t *testing.T) {
	t.Run("same alias different owners", func(t *testing.T) {
		api := &APIServer{}
		now := time.Now().UTC()
		for index, owner := range []string{"parent-a", "parent-b"} {
			parent := hookSpawnTestParent("codex", "shared", owner, "root", 1, "spawn-"+strconv.Itoa(index))
			api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentCompleted, now, `{"task_name":"same"}`)
		}
		child := api.applyHookSpawnIntentLineageAt(
			hookSpawnTestChild("codex", "shared", "child"), map[string]any{"task_name": "same"}, now,
		)
		if child.ParentAgentID != "" || child.RootAgentID != child.AgentID || child.AgentDepth != 0 ||
			child.LineageProvenance != "" || hookSpawnIntentCount(api) != 2 {
			t.Fatalf("ambiguous owners joined child=%+v intents=%d", child, hookSpawnIntentCount(api))
		}
	})

	t.Run("reused tool id different owners", func(t *testing.T) {
		api := &APIServer{}
		now := time.Now().UTC()
		parentA := hookSpawnTestParent("codex", "shared", "parent-a", "root", 1, "same-call")
		parentB := hookSpawnTestParent("codex", "shared", "parent-b", "root", 1, "same-call")
		api.rememberHookSpawnIntentAt(parentA, parentA.ToolName, hookSpawnIntentRequested, now, `{"task_name":"same"}`)
		api.rememberHookSpawnIntentAt(parentB, parentB.ToolName, hookSpawnIntentCompleted, now, `{"task_name":"same"}`)
		child := api.applyHookSpawnIntentLineageAt(
			hookSpawnTestChild("codex", "shared", "child"), map[string]any{"task_name": "same"}, now,
		)
		if child.ParentAgentID != "" || child.RootAgentID != child.AgentID || child.AgentDepth != 0 ||
			child.LineageProvenance != "" || hookSpawnIntentCount(api) != 1 {
			t.Fatalf("colliding tool id joined child=%+v intents=%d", child, hookSpawnIntentCount(api))
		}
	})
}

func TestHookSpawnIntentFirstEventFallbackRequiresOneCompletedIntent(t *testing.T) {
	api := &APIServer{}
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	parent := hookSpawnTestParent("codex", "shared", "parent", "root", 1, "spawn-a")
	api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentCompleted, now, `{"task_name":"a"}`)
	parent.ToolID = "spawn-b"
	api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentCompleted, now, `{"task_name":"b"}`)
	explicit := api.applyHookSpawnIntentLineageAt(
		hookSpawnTestChild("codex", "shared", "explicit-child"), nil, now,
	)
	if explicit.ParentAgentID != "" || explicit.RootAgentID != explicit.AgentID || explicit.AgentDepth != 0 ||
		explicit.LineageProvenance != "" {
		t.Fatalf("ambiguous explicit start retained flattened root edge: %+v", explicit)
	}

	child := hookSpawnTestChild("codex", "shared", "new-child")
	child.RootAgentID = child.AgentID
	child.ParentAgentID = ""
	child.AgentDepth = 0
	child.LifecycleEvent = "tool_start"
	child.LifecycleState = "active"
	child.LifecycleOutcome = "attempted"
	got, start, inferred := api.inferHookSpawnFromFirstEventAt(child, now)
	if inferred || start.AgentID != "" || got.ParentAgentID != "" || got.RootAgentID != child.AgentID {
		t.Fatalf("two completed intents inferred child got=%+v start=%+v inferred=%t", got, start, inferred)
	}
	got = api.clearUnresolvedHookSpawnFallbackAt(got, now)
	if got.ParentAgentID != "" || got.RootAgentID != got.AgentID || got.AgentDepth != 0 || got.LineageProvenance != "" {
		t.Fatalf("ambiguous first tool retained flattened root edge/provenance: %+v", got)
	}
	if count := hookSpawnIntentCount(api); count != 2 {
		t.Fatalf("ambiguous fallback consumed intents=%d want=2", count)
	}

	// Once one candidate is explicitly failed, the sole completed intent owns
	// the previously unseen child and yields one canonical synthetic start.
	api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentFailed, now, `{"task_name":"b"}`)
	got, start, inferred = api.inferHookSpawnFromFirstEventAt(child, now)
	if !inferred || got.ParentAgentID != "parent" || got.RootAgentID != "root" || got.AgentDepth != 2 ||
		got.LineageProvenance != "inferred" || start.LifecycleEvent != "subagent_start" ||
		start.AgentID != child.AgentID || start.ToolID != "" || start.ToolName != "" {
		t.Fatalf("unique fallback lineage got=%+v start=%+v inferred=%t", got, start, inferred)
	}
	if count := hookSpawnIntentCount(api); count != 0 {
		t.Fatalf("unique fallback remaining intents=%d want=0", count)
	}
}

func TestHookSpawnIntentFailureCancelsPendingOwnership(t *testing.T) {
	api := &APIServer{}
	now := time.Now().UTC()
	parent := hookSpawnTestParent("claudecode", "failed-spawn", "root", "root", 0, "failed-call")
	api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentRequested, now, `{"task_name":"never_started"}`)
	api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentFailed, now, `{"task_name":"never_started"}`)
	child := api.applyHookSpawnIntentLineageAt(
		hookSpawnTestChild("claudecode", "failed-spawn", "unrelated-child"),
		map[string]any{"task_name": "never_started"}, now,
	)
	if child.ParentAgentID != "flattened-root" || hookSpawnIntentCount(api) != 0 {
		t.Fatalf("failed spawn retained false ownership child=%+v intents=%d", child, hookSpawnIntentCount(api))
	}
}

func TestHookSpawnIntentExpiresAndEvictsWithinBound(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		api := &APIServer{}
		now := time.Now().UTC()
		parent := hookSpawnTestParent("codex", "stale-session", "root", "root", 0, "stale-call")
		api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentCompleted, now, `{"task_name":"stale"}`)
		child := api.applyHookSpawnIntentLineageAt(
			hookSpawnTestChild("codex", "stale-session", "child"), map[string]any{"task_name": "stale"},
			now.Add(hookSpawnIntentTTL+time.Nanosecond),
		)
		if child.ParentAgentID != "flattened-root" || hookSpawnIntentCount(api) != 0 {
			t.Fatalf("stale intent joined child=%+v intents=%d", child, hookSpawnIntentCount(api))
		}
	})

	t.Run("bounded", func(t *testing.T) {
		api := &APIServer{}
		now := time.Now().UTC()
		for index := 0; index < hookSpawnIntentMaxEntries+17; index++ {
			parent := hookSpawnTestParent(
				"codex", "bounded-session", "root", "root", 0, fmt.Sprintf("spawn-%04d", index),
			)
			api.rememberHookSpawnIntentAt(
				parent, parent.ToolName, hookSpawnIntentRequested, now,
				fmt.Sprintf(`{"task_name":"task-%04d"}`, index),
			)
		}
		api.llmPromptMu.Lock()
		defer api.llmPromptMu.Unlock()
		if len(api.hookSpawnIntents) != hookSpawnIntentMaxEntries ||
			len(api.hookSpawnIntentOrder) != hookSpawnIntentMaxEntries {
			t.Fatalf("bounded cache sizes map=%d order=%d", len(api.hookSpawnIntents), len(api.hookSpawnIntentOrder))
		}
		oldest := hookSpawnIntentToolKey(hookSpawnTestParent("codex", "bounded-session", "root", "root", 0, "spawn-0000"))
		newest := hookSpawnIntentToolKey(hookSpawnTestParent(
			"codex", "bounded-session", "root", "root", 0,
			fmt.Sprintf("spawn-%04d", hookSpawnIntentMaxEntries+16),
		))
		if _, present := api.hookSpawnIntents[oldest]; present {
			t.Fatal("oldest spawn intent was not evicted")
		}
		if _, present := api.hookSpawnIntents[newest]; !present {
			t.Fatal("newest spawn intent was evicted")
		}
	})
}

func TestHookSpawnIntentPreservesReportedLineagePrecedence(t *testing.T) {
	api := &APIServer{}
	now := time.Now().UTC()
	parent := hookSpawnTestParent("codex", "reported-session", "inferred-owner", "inferred-root", 2, "spawn-call")
	api.rememberHookSpawnIntentAt(parent, parent.ToolName, hookSpawnIntentCompleted, now, `{"task_name":"reported"}`)
	reported := hookSpawnTestChild("codex", "reported-session", "reported-child")
	reported.ParentAgentID = "reported-parent"
	reported.RootAgentID = "reported-root"
	reported.AgentDepth = 4
	reported.LineageProvenance = "reported"
	reported.ParentAgentReported = true
	got := api.applyHookSpawnIntentLineageAt(reported, map[string]any{"task_name": "reported"}, now)
	if got.ParentAgentID != "reported-parent" || got.RootAgentID != "reported-root" ||
		got.AgentDepth != 4 || got.LineageProvenance != "reported" {
		t.Fatalf("reported lineage was overwritten: %+v", got)
	}
	if hookSpawnIntentCount(api) != 1 {
		t.Fatal("reported child consumed an unrelated inferred intent")
	}
}

func TestHookSpawnIntentCacheIsConcurrencySafe(t *testing.T) {
	api := &APIServer{}
	now := time.Now().UTC()
	const workers = 32
	var writers sync.WaitGroup
	for index := 0; index < workers; index++ {
		index := index
		writers.Add(1)
		go func() {
			defer writers.Done()
			parent := hookSpawnTestParent(
				"codex", "race-session", fmt.Sprintf("parent-%02d", index), "race-root", 1,
				fmt.Sprintf("spawn-%02d", index),
			)
			api.rememberHookSpawnIntentAt(
				parent, parent.ToolName, hookSpawnIntentCompleted, now,
				fmt.Sprintf(`{"task_name":"task-%02d"}`, index),
			)
		}()
	}
	writers.Wait()

	type result struct {
		index int
		meta  llmEventMeta
	}
	results := make(chan result, workers)
	var readers sync.WaitGroup
	for index := 0; index < workers; index++ {
		index := index
		readers.Add(1)
		go func() {
			defer readers.Done()
			child := hookSpawnTestChild("codex", "race-session", fmt.Sprintf("child-%02d", index))
			child = api.applyHookSpawnIntentLineageAt(
				child, map[string]any{"task_name": fmt.Sprintf("task-%02d", index)}, now,
			)
			results <- result{index: index, meta: child}
		}()
	}
	readers.Wait()
	close(results)
	for observed := range results {
		wantParent := fmt.Sprintf("parent-%02d", observed.index)
		if observed.meta.ParentAgentID != wantParent || observed.meta.RootAgentID != "race-root" ||
			observed.meta.AgentDepth != 2 {
			t.Errorf("worker %d lineage=%+v want parent=%s", observed.index, observed.meta, wantParent)
		}
	}
	if got := hookSpawnIntentCount(api); got != 0 {
		t.Fatalf("concurrent cache remaining intents=%d", got)
	}
}

func TestHookSpawnFirstEventEmitterSynthesizesOneStartConcurrently(t *testing.T) {
	api := &APIServer{}
	parent := hookSpawnTestParent("codex", "concurrent-first-event", "parent", "root", 1, "spawn-call")
	api.rememberHookSessionState(t.Context(), parent)
	api.rememberHookSpawnIntentAt(
		parent, parent.ToolName, hookSpawnIntentCompleted, time.Now().UTC(), `{"task_name":"child"}`,
	)
	child := hookSpawnTestChild("codex", parent.SessionID, "child")
	child.RootAgentID = child.AgentID
	child.ParentAgentID = ""
	child.AgentDepth = 0
	child.LifecycleEvent = "tool_start"
	child.LifecycleState = "active"
	child.LifecycleOutcome = "attempted"

	const workers = 16
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			api.inferAndEmitHookSpawnStart(t.Context(), child)
		}()
	}
	group.Wait()

	snapshot, ok := api.hookLifecycleSnapshot(child.Source, child.SessionID, child.AgentID)
	if !ok || snapshot.LifecycleEvent != "subagent_start" || snapshot.ParentAgentID != parent.AgentID ||
		snapshot.RootAgentID != parent.RootAgentID || snapshot.AgentDepth != 2 || snapshot.Sequence != 1 {
		t.Fatalf("concurrent inferred start present=%t snapshot=%+v", ok, snapshot)
	}
	if count := hookSpawnIntentCount(api); count != 0 {
		t.Fatalf("concurrent inferred start intents=%d want=0", count)
	}
	if transitions := len(api.hookLifecycleTransitions); transitions != 1 {
		t.Fatalf("concurrent inferred lifecycle transitions=%d want=1", transitions)
	}
}
