// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// The measured session's hooks through the Claude Code emitter: every
// subagent, the two parallel ones included, has the main agent as its
// parent at depth 1, and no spawn intent is left once each subagent
// started. Parallel Agent calls used to tie, leaving the second subagent
// without a parent, and each Agent result left a completed intent behind
// that later subagents tied on.
func TestClaudeCodeMeasuredSubagentsHaveTheMainAgentAsParent(t *testing.T) {
	api := &APIServer{}
	events := readClaudeCodeAgentToolFixture(t)
	sessionID := fmt.Sprint(events[0]["session_id"])
	mainAgent := stableLLMEventID("agent", "claudecode", sessionID, "root")
	subagents := 0
	for i, payload := range events {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		api.emitClaudeCodeHookLLMEvent(t.Context(), decodeClaudeCodeRequestFromBytes(raw, payload), nil, raw)
		id, ok := payload["agent_id"].(string)
		if !ok {
			continue
		}
		// The lineage each of the subagent's hooks is recorded with, not
		// one a later SubagentStop repairs.
		snapshot, ok := api.hookLifecycleSnapshot("claudecode", sessionID, id)
		if !ok || snapshot.ParentAgentID != mainAgent || snapshot.RootAgentID != mainAgent || snapshot.AgentDepth != 1 {
			t.Errorf("fixture line %d (%v): subagent %s lineage=%+v retained=%v", i+1, payload["hook_event_name"], id, snapshot, ok)
		}
		if payload["hook_event_name"] == "SubagentStart" {
			subagents++
		}
	}
	if subagents != 7 {
		t.Fatalf("subagents = %d, want 7 (fixture changed?)", subagents)
	}
	if got := hookSpawnIntentCount(api); got != 0 {
		t.Fatalf("spawn intents left after every subagent started = %d", got)
	}
}

// Only Claude Code's own Agent tool names the subagent it ran; another
// tool's response is that tool's output.
func TestClaudeCodeSpawnedAgentID(t *testing.T) {
	response := map[string]interface{}{"agentId": "a68b3f56907fa1ebc", "status": "completed"}
	for _, tc := range []struct {
		name string
		req  claudeCodeHookRequest
		want string
	}{
		{"agent result", claudeCodeHookRequest{HookEventName: "PostToolUse", ToolName: "Agent", ToolResponse: response}, "a68b3f56907fa1ebc"},
		{"failure", claudeCodeHookRequest{HookEventName: "PostToolUseFailure", ToolName: "Agent", ToolResponse: response}, ""},
		{"other tool", claudeCodeHookRequest{HookEventName: "PostToolUse", ToolName: "Bash", ToolResponse: response}, ""},
		{"mcp tool", claudeCodeHookRequest{HookEventName: "PostToolUse", ToolName: "Agent", MCPServerName: "evil", ToolResponse: response}, ""},
		{"string response", claudeCodeHookRequest{HookEventName: "PostToolUse", ToolName: "Agent", ToolResponse: "agentId: x"}, ""},
	} {
		if got := claudeCodeSpawnedAgentID(tc.req); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if !isAgentSpawnerTool(claudeCodeAgentTool) {
		t.Fatal("isAgentSpawnerTool does not know Claude Code's Agent tool")
	}
}

type claudeCodeReplayRow struct {
	bucket, event string
	body          map[string]any
}

func (r claudeCodeReplayRow) field(key string) string {
	if value, ok := r.body[key]; ok && value != nil {
		return fmt.Sprint(value)
	}
	return ""
}

// replayClaudeCodeAgentToolFixture sends every fixture hook through the
// Claude Code hook handler, as the hook script would, and returns the API
// and the store the handler wrote.
func replayClaudeCodeAgentToolFixture(t *testing.T) (*APIServer, string, []map[string]interface{}) {
	t.Helper()
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
	handler := api.handleAgentHook("claudecode")
	events := readClaudeCodeAgentToolFixture(t)
	for _, event := range events {
		callAgentHookForTest(t, handler, event)
	}
	return api, fixture.path, events
}

func readClaudeCodeReplayRows(t *testing.T, path string) []claudeCodeReplayRow {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT bucket, event_name, projected_record_json FROM audit_events
		WHERE bucket IN ('tool.activity','agent.lifecycle','guardrail.evaluation') ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []claudeCodeReplayRow
	for rows.Next() {
		var row claudeCodeReplayRow
		var raw string
		if err := rows.Scan(&row.bucket, &row.event, &raw); err != nil {
			t.Fatal(err)
		}
		var projected map[string]any
		if err := json.Unmarshal([]byte(raw), &projected); err != nil {
			t.Fatal(err)
		}
		row.body, _ = projected["body"].(map[string]any)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Claude Code 2.1.156 sends PostToolUse (or PostToolUseFailure) for its Agent
// tool once the subagent is done, after the subagent's own hooks. The main
// agent's hooks carry no agent_id while the subagent's cursor is still active
// (#957: the call's result then lost its correlation, so DefenseClaw
// exported no decision and no tool_end for it, and the only result on record
// was the PostToolBatch, labelled ClaudeCodeTool). Every hook of the measured
// session is now exported, each Agent call ends under its own name and ID,
// every subagent's calls carry the subagent and its parent, the main agent
// keeps one identity, and each finished Agent call is linked to the subagent
// it ran.
func TestClaudeCodeAgentToolReplayLabelsSubagentCalls(t *testing.T) {
	api, path, events := replayClaudeCodeAgentToolFixture(t)
	rows := readClaudeCodeReplayRows(t, path)
	sessionID := fmt.Sprint(events[0]["session_id"])
	mainAgent := stableLLMEventID("agent", "claudecode", sessionID, "root")

	decisions := 0
	decisionAgents := map[string]bool{}
	subagents := map[string]bool{}
	for _, event := range events {
		if id, ok := event["agent_id"].(string); ok {
			subagents[id] = true
		}
	}
	for _, row := range rows {
		if row.event != "hook_decision" {
			continue
		}
		decisions++
		if agent := row.field("gen_ai.agent.id"); !subagents[agent] {
			decisionAgents[agent] = true
		}
	}
	if decisions != len(events) {
		t.Fatalf("hook_decision rows = %d, want one per hook (%d): a hook lost its correlation", decisions, len(events))
	}
	if len(decisionAgents) != 1 {
		t.Fatalf("the main agent's decisions carry %d agent IDs, want one: %v", len(decisionAgents), decisionAgents)
	}

	ends := map[string]claudeCodeReplayRow{}
	for _, row := range rows {
		if row.bucket != "tool.activity" {
			continue
		}
		agent := row.field("gen_ai.agent.id")
		switch {
		case subagents[agent]:
			if row.field("defenseclaw.agent.parent.id") != mainAgent || row.field("defenseclaw.agent.depth") != "1" {
				t.Errorf("subagent call not labelled with its parent: %s %s %s", row.event, row.field("gen_ai.tool.name"), replayRowJSON(row.body))
			}
		case agent == mainAgent:
			if row.field("defenseclaw.agent.depth") != "0" {
				t.Errorf("main agent call at depth %s: %s", row.field("defenseclaw.agent.depth"), row.event)
			}
		default:
			t.Errorf("tool row of an unknown agent %q: %s", agent, row.event)
		}
		if row.field("gen_ai.tool.name") == "ClaudeCodeTool" {
			t.Errorf("tool row without a tool name: %s %s", row.event, replayRowJSON(row.body))
		}
		if row.event == "tool_end" {
			ends[row.field("gen_ai.tool.call.id")] = row
		}
	}
	for i, event := range events {
		name, _ := event["hook_event_name"].(string)
		if name != "PostToolUse" && name != "PostToolUseFailure" {
			continue
		}
		id, tool := fmt.Sprint(event["tool_use_id"]), fmt.Sprint(event["tool_name"])
		end, ok := ends[id]
		if !ok || end.field("gen_ai.tool.name") != tool {
			t.Errorf("fixture line %d: %s of %s %s has no tool_end under its name (got %q)", i+1, name, tool, id, end.field("gen_ai.tool.name"))
		}
	}

	// A PostToolBatch is a tool_batch record listing its calls, never a
	// second result of one of them.
	batches := 0
	for _, row := range rows {
		if row.bucket == "tool.activity" && row.event == "tool_end" && row.field("gen_ai.tool.name") == claudeCodeToolBatchName {
			batches++
		}
	}
	wantBatches := 0
	for _, event := range events {
		if event["hook_event_name"] == "PostToolBatch" {
			wantBatches++
		}
	}
	if batches != wantBatches {
		t.Fatalf("tool_batch ends = %d, want %d (one per PostToolBatch)", batches, wantBatches)
	}

	if got := hookSpawnIntentCount(api); got != 0 {
		t.Fatalf("spawn intents left after every subagent started = %d", got)
	}
	assertClaudeCodeSpawnedAgentLinks(t, path, events)
}

// Each PostToolUse of an Agent call names the subagent it ran
// (tool_response.agentId); the ledger records that subagent as caused by
// the call, and nothing else as caused by a call.
func assertClaudeCodeSpawnedAgentLinks(t *testing.T, path string, events []map[string]interface{}) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	links := 0
	for _, event := range events {
		response, _ := event["tool_response"].(map[string]interface{})
		child, _ := response["agentId"].(string)
		if event["hook_event_name"] != "PostToolUse" || event["tool_name"] != "Agent" || child == "" {
			continue
		}
		links++
		var caused int
		if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
			WHERE from_kind='agent' AND from_id=? AND to_kind='tool_invocation' AND to_id=?
			AND relationship_type='caused_by' AND method='reported' AND rule_id='spawned-agent-tool-result'`,
			child, event["tool_use_id"]).Scan(&caused); err != nil {
			t.Fatal(err)
		}
		if caused != 1 {
			t.Errorf("subagent %s: caused_by %s = %d, want 1", child, event["tool_use_id"], caused)
		}
	}
	if links != 6 {
		t.Fatalf("Agent PostToolUse events with an agentId = %d, want 6 (fixture changed?)", links)
	}
	var total int
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE rule_id='spawned-agent-tool-result'`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != links {
		t.Fatalf("spawned-agent-tool-result relationships = %d, want %d", total, links)
	}
}

func replayRowJSON(v any) string {
	body, _ := json.Marshal(v)
	return string(body)
}

// A PostToolBatch names no tool: it is recorded as a tool_batch whose input
// lists its calls, under an ID derived from theirs and distinct from each.
func TestClaudeCodeToolBatchLabel(t *testing.T) {
	batch := func(calls ...map[string]interface{}) claudeCodeHookRequest {
		items := make([]interface{}, 0, len(calls))
		for _, call := range calls {
			items = append(items, call)
		}
		return claudeCodeHookRequest{HookEventName: "PostToolBatch", SessionID: "s1", ToolCalls: items}
	}
	agent := map[string]interface{}{"tool_name": "Agent", "tool_use_id": "toolu_agent", "tool_input": map[string]interface{}{"prompt": "p"}, "tool_response": []interface{}{}}
	bash := map[string]interface{}{"tool_name": "Bash", "tool_use_id": "toolu_bash", "tool_response": "ok"}

	calls, name, id := claudeCodeToolBatch(batch(agent))
	if name != claudeCodeToolBatchName || len(calls) != 1 || calls[0] != (claudeCodeBatchCall{ToolName: "Agent", ToolUseID: "toolu_agent"}) {
		t.Fatalf("one call: %q %+v", name, calls)
	}
	if id == "" || id == "toolu_agent" {
		t.Fatalf("one-call batch ID %q: want one derived from, and distinct from, its call's", id)
	}
	_, _, again := claudeCodeToolBatch(batch(agent))
	_, _, other := claudeCodeToolBatch(batch(agent, bash))
	if again != id || other == id {
		t.Fatalf("batch IDs: same calls %q vs %q, other calls %q", id, again, other)
	}
	if got := claudeCodeToolBatchArguments(calls); got != `{"tool_calls":[{"tool_name":"Agent","tool_use_id":"toolu_agent"}]}` {
		t.Fatalf("arguments = %s", got)
	}
	if calls, name, id := claudeCodeToolBatch(batch()); calls != nil || name != claudeCodeToolBatchName || id != "" {
		t.Fatalf("empty batch: %+v %q %q", calls, name, id)
	}
	if got := claudeCodeToolBatchArguments(nil); got != "{}" {
		t.Fatalf("empty arguments = %s", got)
	}
}
