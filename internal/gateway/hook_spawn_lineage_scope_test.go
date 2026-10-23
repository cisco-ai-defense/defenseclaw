// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-1198: a chat that starts while a create_thread call is in flight is a
// chat of its own, before and after the call returns. Only the thread the
// call returns is the caller's child, also when it hooked before the result.
func TestCodexThreadSpawnLinksOnlyTheReturnedThread(t *testing.T) {
	api := &APIServer{}
	const identity = "agt-00000000000004ae"
	const parentSession = "01a20000-0000-7000-8000-0000000004ae"
	const chat = "01a20001-0000-7000-8000-0000000004ae"
	const thread = "01a20002-0000-7000-8000-0000000004ae"
	ctx := ContextWithAgentIdentity(t.Context(), AgentIdentity{IdentityID: identity})
	parentAgent := agentNodeID(identity, "codex", parentSession, "root")
	emit := func(session, event, tool string, response any) {
		if event == "SessionStart" { // the hook path counts a session it has not seen
			sharedAgentIdentities.observe(agentIdentityFacts{ID: identity, UserID: "4798", Connector: "codex"}, session, true)
		}
		api.emitCodexHookLLMEvent(ctx, codexHookRequest{
			HookEventName: event, SessionID: session, ToolName: tool, ToolUseID: "call-" + session + event,
			ToolInput: map[string]any{"prompt": "run it"}, ToolResponse: response,
			Payload: map[string]any{"source": "startup"},
		}, nil, nil)
	}
	lineage := func(session string) llmEventMeta {
		t.Helper()
		got, ok := api.hookLifecycleSnapshot("codex", session, agentNodeID(identity, "codex", session, "root"))
		if !ok {
			t.Fatalf("session %s not retained", session)
		}
		return got
	}

	emit(parentSession, "SessionStart", "", nil)
	emit(parentSession, "PreToolUse", "mcp__codex_tui__create_thread", nil)
	emit(chat, "SessionStart", "", nil)
	emit(thread, "SessionStart", "", nil)
	if got := lineage(chat); got.AgentDepth != 0 || got.ParentAgentID != "" || got.ParentSessionID != "" {
		t.Fatalf("a chat started while the call was in flight = %+v, want a root", got)
	}
	emit(parentSession, "PostToolUse", "mcp__codex_tui__create_thread",
		map[string]any{"content": `{"threadId":"` + thread + `"}`})
	emit(chat, "PreToolUse", "Bash", nil)
	emit(thread, "PreToolUse", "Bash", nil)
	if got := lineage(chat); got.AgentDepth != 0 || got.ParentAgentID != "" || got.ParentSessionID != "" {
		t.Fatalf("the chat after the call returned = %+v, want a root", got)
	}
	if got := lineage(thread); got.AgentDepth != 1 || got.ParentAgentID != parentAgent || got.ParentSessionID != parentSession {
		t.Fatalf("the returned thread = %+v, want depth 1 under %s", got, parentAgent)
	}
	if pending, _, _ := sharedAgentIdentities.snapshot(); pending[identity].SessionsSeen != 2 {
		t.Fatalf("agent identity counted %+v, want the parent and the chat, not the thread", pending[identity])
	}
}

// GAP-1237: the parent of a spawn call is the caller's own retained state.
// Session and agent ids are caller-supplied, so a retained agent of another
// agent identity, or of another user, under the same ids is not taken.
func TestCanonicalHookSpawnParentTakesOnlyTheCallersOwnState(t *testing.T) {
	api := &APIServer{}
	api.rememberHookSessionState(t.Context(), llmEventMeta{
		Source: "codex", SessionID: "shared-session", AgentID: "agent-shared",
		RootAgentID: "root-a", RootSessionID: "root-session-a", ParentAgentID: "parent-a",
		AgentDepth: 2, AgentIdentityID: "agt-a", UserID: "1001", ExecutionID: "execution-a",
		ParentLineageResolved: true,
	})
	caller := llmEventMeta{
		Source: "codex", SessionID: "shared-session", AgentID: "agent-shared", RootAgentID: "agent-shared",
		AgentIdentityID: "agt-b", UserID: "1002", ToolID: "call-b",
	}
	for _, other := range []struct{ identity, user string }{{"agt-b", "1002"}, {"agt-a", "1002"}} {
		caller.AgentIdentityID, caller.UserID = other.identity, other.user
		if got := api.canonicalHookSpawnParent(caller); got.RootAgentID != "agent-shared" || got.AgentDepth != 0 ||
			got.ExecutionID != "" || got.UserID != other.user {
			t.Fatalf("%s/%s took another account's retained agent as the parent: %+v", other.identity, other.user, got)
		}
	}
	caller.AgentIdentityID, caller.UserID = "agt-a", "1001"
	if got := api.canonicalHookSpawnParent(caller); got.RootAgentID != "root-a" || got.AgentDepth != 2 ||
		got.ExecutionID != "execution-a" || got.ToolID != "call-b" {
		t.Fatalf("the caller's own retained agent was not the parent: %+v", got)
	}
}

type copilotHistoryStub struct {
	sidecarRuntimeEmitter
	sessions map[string]bool
}

func (stub *copilotHistoryStub) LatestLifecycleProjection(
	_ context.Context,
	query audit.LifecycleProjectionQuery,
) (audit.LifecycleProjection, bool, error) {
	return audit.LifecycleProjection{}, stub.sessions[query.SessionID], nil
}

// GAP-1066: after a gateway restart a chat that was already open is new to
// the gateway. Its first hook is not the sub-agent of a pending start: the
// audit history holds the chat. The new child session is linked.
func TestCopilotSubagentStartSkipsAChatOpenBeforeARestart(t *testing.T) {
	const identity = "agt-000000000000042a"
	const parentSession = "6b5c0000-0000-4000-8000-00000000042a"
	const openChat = "6b5c0001-0000-4000-8000-00000000042a"
	const childSession = "6b5c0002-0000-4000-8000-00000000042a"
	api := &APIServer{observabilityV8: &copilotHistoryStub{sessions: map[string]bool{openChat: true}}}
	ctx := t.Context()
	meta := func(session, event string) llmEventMeta {
		return llmEventMeta{
			Source: "copilot", SessionID: session, AgentIdentityID: identity, UserID: "1066",
			AgentID: agentNodeID(identity, "copilot", session, "root"), LifecycleEvent: event,
		}
	}
	api.rememberHookSessionState(ctx, meta(parentSession, "session_start"))
	api.applyCopilotSubagentLineage(ctx, meta(parentSession, "subagent_start"), map[string]any{})
	parentAgent := agentNodeID(identity, "copilot", parentSession, "root")
	if got := api.applyCopilotSubagentLineage(ctx, meta(openChat, "tool_start"), map[string]any{}); got.ParentAgentID != "" ||
		got.AgentDepth != 0 || got.ParentSessionID != "" {
		t.Fatalf("a chat open before the restart was linked as the sub-agent: %+v", got)
	}
	if got := api.applyCopilotSubagentLineage(ctx, meta(childSession, "tool_start"), map[string]any{}); got.ParentAgentID != parentAgent ||
		got.AgentDepth != 1 || got.ParentSessionID != parentSession {
		t.Fatalf("the new child session = %+v, want depth 1 under %s", got, parentAgent)
	}
}

// GAP-1131: Hermes 0.21.5 sends transform_terminal_output with no session and
// no task. While one chat of the agent identity makes tool calls, the output
// takes that chat's session; with two chats it is not known which one ran
// the command, and the output takes no session.
func TestHermesBareTerminalOutputOfTwoChatsHasNoSession(t *testing.T) {
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	var tasks hermesTaskSessions
	call := func(session string) {
		req := agentHookRequest{ConnectorName: "hermes", AgentIdentityID: "agt-1", SessionID: session,
			HookEventName: "pre_tool_call", Payload: map[string]interface{}{}}
		tasks.fill(&req)
	}
	output := func() string {
		req := agentHookRequest{ConnectorName: "hermes", AgentIdentityID: "agt-1",
			HookEventName: "transform_terminal_output", Payload: map[string]interface{}{}}
		tasks.fill(&req)
		return req.SessionID
	}
	call("chat-a")
	if got := output(); got != "chat-a" {
		t.Fatalf("the output of one chat took session %q, want chat-a", got)
	}
	call("chat-b")
	call("chat-a")
	if got := output(); got != "" {
		t.Fatalf("the output of two chats took session %q, want none", got)
	}
	// Once the other chat made no call for the TTL, the one chat's output has
	// its session again.
	tasks.mu.Lock()
	last := tasks.lastCall["agt-1"]
	last.sharedAt = time.Now().Add(-hermesLastToolCallTTL - time.Second)
	tasks.lastCall["agt-1"] = last
	tasks.mu.Unlock()
	call("chat-a")
	if got := output(); got != "chat-a" {
		t.Fatalf("the output of the one chat left took session %q, want chat-a", got)
	}
}
