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

// Tests for the Go-gateway runtime enforcement of an MCP-server block
// (`defenseclaw mcp block <server>`, global or --connector scoped). Until this
// gate existed, an `mcp` block was honored only by the Python CLI / admission
// gate; the blocked server's tools could still be invoked at Go runtime
// (fail-open). These tests prove the block is now enforced on BOTH runtime
// lanes — the hook lane (inspectToolPolicy) and the sidecar lane
// (handleToolCall) — for both global and per-connector scopes.

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// ---------------------------------------------------------------------------
// Hook lane (inspectToolPolicy)
// ---------------------------------------------------------------------------

func TestInspectTool_GlobalMCPBlock_RejectsToolsEverywhere(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	pe := enforce.NewPolicyEngine(store)
	// Bare/global block of the "jira" MCP server.
	if err := pe.Block("mcp", "jira", "global"); err != nil {
		t.Fatalf("Block mcp: %v", err)
	}

	// A blocked MCP server's tool is rejected at the Go gateway, on every
	// connector and globally — not just at the Python CLI.
	for _, conn := range []string{"codex", "claudecode", ""} {
		body := `{"tool":"mcp__jira__createIssue","connector":"` + conn + `","args":{}}`
		_, v := postInspect(t, api, body)
		if v.Action != "block" {
			t.Errorf("connector %q: action = %q, want block (global mcp block must hit all)", conn, v.Action)
		}
		if !hasFinding(v.Findings, "MCP-BLOCK") {
			t.Errorf("connector %q: findings = %v, want MCP-BLOCK", conn, v.Findings)
		}
	}

	// A tool belonging to a different (unblocked) MCP server is untouched.
	_, v := postInspect(t, api, `{"tool":"mcp__github__listRepos","connector":"codex","args":{}}`)
	if v.Action == "block" {
		t.Errorf("unblocked server: action = block, want non-block (block leaked across servers)")
	}
}

func TestInspectTool_ConnectorScopedMCPBlock_Isolated(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	pe := enforce.NewPolicyEngine(store)
	// Block the "jira" MCP server only for codex.
	if err := pe.BlockForConnector("mcp", "jira", "codex", "scoped"); err != nil {
		t.Fatalf("BlockForConnector mcp: %v", err)
	}

	// Rejected for codex…
	_, v := postInspect(t, api, `{"tool":"mcp__jira__createIssue","connector":"codex","args":{}}`)
	if v.Action != "block" {
		t.Errorf("codex: action = %q, want block", v.Action)
	}
	// …but allowed for a different connector…
	_, v = postInspect(t, api, `{"tool":"mcp__jira__createIssue","connector":"claudecode","args":{}}`)
	if v.Action == "block" {
		t.Errorf("claudecode: action = block, want non-block (connector-scoped mcp block leaked)")
	}
	// …and not as a global block.
	_, v = postInspect(t, api, `{"tool":"mcp__jira__createIssue","args":{}}`)
	if v.Action == "block" {
		t.Errorf("global: action = block, want non-block (connector-scoped mcp block must not apply globally)")
	}
}

func TestInspectTool_MCPServerBlock_WinsOverToolAllow(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	pe := enforce.NewPolicyEngine(store)
	// Operator allow-lists the specific tool but blocks the whole MCP server.
	if err := pe.AllowToolForConnector("mcp__jira__createIssue", "", "vetted tool"); err != nil {
		t.Fatalf("AllowToolForConnector: %v", err)
	}
	if err := pe.Block("mcp", "jira", "server-wide block"); err != nil {
		t.Fatalf("Block mcp: %v", err)
	}

	// The server-level block must win over the tool-level allow.
	_, v := postInspect(t, api, `{"tool":"mcp__jira__createIssue","connector":"codex","args":{}}`)
	if v.Action != "block" {
		t.Errorf("action = %q, want block (mcp-server block must override a tool-level allow)", v.Action)
	}
}

// ---------------------------------------------------------------------------
// Sidecar lane (handleToolCall)
// ---------------------------------------------------------------------------

func TestHandleToolCall_GlobalMCPBlock(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	if err := enforce.NewPolicyEngine(store).Block("mcp", "jira", "global"); err != nil {
		t.Fatalf("Block mcp: %v", err)
	}

	r := NewEventRouter(nil, store, logger, false)
	payload, _ := json.Marshal(ToolCallPayload{Tool: "mcp__jira__createIssue", Args: json.RawMessage(`{}`), Status: "running"})
	r.Route(EventFrame{Type: "event", Event: "tool_call", Payload: payload})
	if !hasAction(t, store, "gateway-tool-call-blocked") {
		t.Error("global mcp block: expected a blocked event for the blocked MCP server's tool")
	}
}

func TestHandleToolCall_ConnectorScopedMCPBlock(t *testing.T) {
	// Blocked for codex.
	storeA, loggerA := testStoreAndLogger(t)
	if err := enforce.NewPolicyEngine(storeA).BlockForConnector("mcp", "jira", "codex", "scoped"); err != nil {
		t.Fatalf("BlockForConnector mcp: %v", err)
	}
	rCodex := NewEventRouter(nil, storeA, loggerA, false)
	rCodex.SetGuardrailConfig(&config.GuardrailConfig{Connector: "codex"})
	payload, _ := json.Marshal(ToolCallPayload{Tool: "mcp__jira__createIssue", Args: json.RawMessage(`{}`), Status: "running"})
	rCodex.Route(EventFrame{Type: "event", Event: "tool_call", Payload: payload})
	if !hasAction(t, storeA, "gateway-tool-call-blocked") {
		t.Error("codex router: expected a blocked event for the connector-scoped mcp block")
	}

	// Same block must NOT fire for a different connector.
	storeB, loggerB := testStoreAndLogger(t)
	if err := enforce.NewPolicyEngine(storeB).BlockForConnector("mcp", "jira", "codex", "scoped"); err != nil {
		t.Fatalf("BlockForConnector mcp: %v", err)
	}
	rOther := NewEventRouter(nil, storeB, loggerB, false)
	rOther.SetGuardrailConfig(&config.GuardrailConfig{Connector: "claudecode"})
	rOther.Route(EventFrame{Type: "event", Event: "tool_call", Payload: payload})
	if hasAction(t, storeB, "gateway-tool-call-blocked") {
		t.Error("claudecode router: connector-scoped mcp block leaked to a different connector")
	}
}

// ---------------------------------------------------------------------------
// Helper-level: non-MCP tools and unblocked servers are no-ops.
// ---------------------------------------------------------------------------

func TestMCPServerRuntimeBlock_NonMCPAndUnblocked(t *testing.T) {
	store, _ := testStoreAndLogger(t)
	pe := enforce.NewPolicyEngine(store)
	if err := pe.Block("mcp", "jira", "global"); err != nil {
		t.Fatalf("Block mcp: %v", err)
	}

	// Plain (non-MCP) tool name: never an MCP-server decision.
	if deny, _, _ := mcpServerRuntimeBlock(pe, "shell", "", ""); deny {
		t.Error("plain tool name: deny = true, want false")
	}
	// MCP tool for an unblocked server.
	if deny, _, _ := mcpServerRuntimeBlock(pe, "mcp__github__listRepos", "", ""); deny {
		t.Error("unblocked mcp server: deny = true, want false")
	}
	// MCP tool for the blocked server.
	if deny, server, _ := mcpServerRuntimeBlock(pe, "mcp__jira__createIssue", "", ""); !deny || server != "jira" {
		t.Errorf("blocked mcp server: deny=%v server=%q, want deny=true server=jira", deny, server)
	}
}

func TestInspectTool_MCPServerBlock_UsesExplicitServerName(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	pe := enforce.NewPolicyEngine(store)
	if err := pe.BlockForConnector("mcp", "jira", "codex", "scoped"); err != nil {
		t.Fatalf("BlockForConnector mcp: %v", err)
	}

	_, v := postInspect(t, api, `{"tool":"createIssue","mcp_server_name":"jira","connector":"codex","args":{}}`)
	if v.Action != "block" {
		t.Errorf("explicit mcp_server_name: action = %q, want block", v.Action)
	}
	if !hasFinding(v.Findings, "MCP-BLOCK") {
		t.Errorf("findings = %v, want MCP-BLOCK", v.Findings)
	}
}

func hasFinding(findings []string, want string) bool {
	for _, f := range findings {
		if f == want {
			return true
		}
	}
	return false
}
