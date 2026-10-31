// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0721: Copilot CLI 1.0.105 can stamp agent ids on its hooks.
// subagentStart, subagentStop and the hooks of the sub-agent then report
// agentId (the child's session UUID) and parentAgentId (the parent's session
// UUID). The stamped payloads below are the hook inputs a real Copilot CLI
// 1.0.105 TUI explore sub-agent recorded on the managed RHEL host (cell
// L-erhel-J5-012); the unstamped ones are what the same release sent on
// dc-rhel and dc-float2. Either way the child's tool rows, its
// subagent_start, its subagent_stop and the stop's decision row name the
// child agent, the main agent as parent and root, and depth 1.
func TestCopilotSubagentRowsShareTheChildLineageWithOrWithoutReportedAgentIDs(t *testing.T) {
	for _, tc := range []struct {
		name, identity, parent, child string
		stamped                       bool
	}{
		{"agent ids stamped", "agt-0000000000000721", "48da5b55-2b7b-4863-ade2-20cd57c599d6", "c70f6d26-64af-44cc-8200-da5bd53cbf38", true},
		{"no agent ids", "agt-0000000000000722", "f93fea3b-0518-4c73-a3c3-f5d775c3af68", "9366dc66-1ff2-4b5d-aa44-ea068b35ef1c", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &APIServer{}
			ctx := ContextWithAgentIdentity(t.Context(), AgentIdentity{IdentityID: tc.identity})
			mainAgent := agentNodeID(tc.identity, "copilot", tc.parent, "root")
			childAgent := agentNodeID(tc.identity, "copilot", tc.child, "root")
			stamp := func(payload map[string]any, agentID string) map[string]any {
				if tc.stamped {
					payload["agentId"], payload["agentType"], payload["parentAgentId"] = agentID, "explore", tc.parent
				}
				return payload
			}
			emit := func(event string, payload map[string]any) agentHookRequest {
				t.Helper()
				payload["timestamp"], payload["cwd"] = 1793430536064, "/home/u/s12proj"
				req := normalizeAgentHookRequestWithCorrelationEvent("copilot", payload, connector.DefaultCorrelationSpec("copilot"), event, tc.identity)
				api.emitAgentHookLLMEvent(ctx, req, nil)
				return req
			}
			want := func(what string, got llmEventMeta, ok bool) {
				t.Helper()
				if !ok || got.AgentID != childAgent || got.AgentDepth != 1 || got.ParentAgentID != mainAgent || got.RootAgentID != mainAgent {
					t.Fatalf("%s = agent %s depth %d parent %s root %s (retained %v), want agent %s depth 1 parent = root = %s (%+v)",
						what, got.AgentID, got.AgentDepth, got.ParentAgentID, got.RootAgentID, ok, childAgent, mainAgent, got)
				}
			}

			emit("sessionStart", map[string]any{"source": "new", "initialPrompt": "use the task tool", "sessionId": tc.parent})
			emit("userPromptSubmitted", map[string]any{"sessionId": tc.parent, "prompt": "use the task tool"})
			emit("preToolUse", map[string]any{"sessionId": tc.parent, "toolName": "task", "toolArgs": `{"agent_type":"explore"}`})
			startReq := emit("subagentStart", stamp(map[string]any{"sessionId": tc.parent, "agentName": "explore",
				"transcriptPath": "/home/u/.copilot/session-state/" + tc.parent + "/events.jsonl"}, tc.child))
			// rel-1-0-6:GAP-0223: the start row, which comes before any row
			// of the child, is the child's at depth 1 under the main agent.
			// A start that names no child (Copilot 1.0.90) keeps the agent id
			// the gateway gives it; one that names it has the child's.
			startAgent := childAgent
			if !tc.stamped {
				startAgent = startReq.AgentID
			}
			start, ok := api.hookLifecycleSnapshot("copilot", tc.parent, startAgent)
			if !ok || start.LifecycleEvent != "subagent_start" || startAgent == "" || startAgent == mainAgent ||
				start.AgentDepth != 1 || start.ParentAgentID != mainAgent || start.RootAgentID != mainAgent {
				t.Fatalf("subagent_start = agent %s event %s depth %d parent %s root %s (retained %v), want depth 1 parent = root = %s",
					start.AgentID, start.LifecycleEvent, start.AgentDepth, start.ParentAgentID, start.RootAgentID, ok, mainAgent)
			}
			if startDecision, _, ok := api.hookDecisionMeta(ctx, startReq); !ok || startDecision.AgentID != startAgent ||
				startDecision.AgentDepth != 1 || startDecision.ParentAgentID != mainAgent || startDecision.RootAgentID != mainAgent {
				t.Fatalf("subagent_start decision row = %+v (ok %v), want agent %s depth 1 parent = root = %s", startDecision, ok, startAgent, mainAgent)
			}
			emit("userPromptSubmitted", stamp(map[string]any{"sessionId": tc.child, "prompt": "read hello.txt"}, tc.child))
			emit("preToolUse", map[string]any{"sessionId": tc.child, "toolName": "view", "toolArgs": `{"path":"hello.txt"}`})
			tool, ok := api.hookLifecycleSnapshot("copilot", tc.child, childAgent)
			want("child tool row", tool, ok)
			emit("postToolUse", map[string]any{"sessionId": tc.child, "toolName": "view", "toolArgs": `{"path":"hello.txt"}`,
				"toolResult": `{"resultType":"success"}`})
			emit("agentStop", stamp(map[string]any{"sessionId": tc.child, "stopReason": "end_turn"}, tc.child))
			tool, ok = api.hookLifecycleSnapshot("copilot", tc.child, childAgent)
			want("child tool result row", tool, ok)

			stopReq := emit("subagentStop", stamp(map[string]any{"sessionId": tc.parent, "agentName": "explore", "agentType": "explore",
				"agentId": tc.child, "stopReason": "end_turn", "response": "hello"}, tc.child))
			stop, ok := api.hookLifecycleSnapshot("copilot", tc.child, childAgent)
			if stop.LifecycleEvent != "subagent_stop" {
				t.Fatalf("child lifecycle = %s, want subagent_stop", stop.LifecycleEvent)
			}
			want("subagent_stop", stop, ok)
			if stop.ParentSessionID != tc.parent || stop.RootSessionID != tc.parent {
				t.Fatalf("subagent_stop sessions parent %s root %s, want %s", stop.ParentSessionID, stop.RootSessionID, tc.parent)
			}
			decision, _, ok := api.hookDecisionMeta(ctx, stopReq)
			want("subagent_stop decision row", decision, ok)

			main, ok := api.hookLifecycleSnapshot("copilot", tc.parent, mainAgent)
			if !ok || main.AgentDepth != 0 || main.ParentAgentID != "" || main.RootAgentID != mainAgent {
				t.Fatalf("main agent = %+v (retained %v), want the root", main, ok)
			}
		})
	}
}
