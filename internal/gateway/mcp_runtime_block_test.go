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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ---------------------------------------------------------------------------
// Hook lane (inspectToolPolicy)
// ---------------------------------------------------------------------------

func TestInspectTool_GlobalMCPBlock_RejectsToolsEverywhere(t *testing.T) {
	api, _ := toolPolicyAPI(t, "action")
	// Bare/global block of the "jira" MCP server.
	denyAsset(api.scannerCfg, "mcp", "jira", "", "global")

	// A blocked MCP server's tool is rejected at the Go gateway, on every
	// connector and globally — not just at the Python CLI.
	for _, conn := range []string{"codex", "claudecode", ""} {
		body := `{"tool":"mcp__jira__createIssue","connector":"` + conn + `","args":{}}`
		_, v := postInspectForConnector(t, api, conn, body)
		if v.Action != "block" {
			t.Errorf("connector %q: action = %q, want block (global mcp block must hit all)", conn, v.Action)
		}
		if !hasFinding(v.Findings, "MCP-BLOCK") {
			t.Errorf("connector %q: findings = %v, want MCP-BLOCK", conn, v.Findings)
		}
	}

	// A tool belonging to a different (unblocked) MCP server is untouched.
	_, v := postInspectForConnector(t, api, "codex", `{"tool":"mcp__github__listRepos","connector":"codex","args":{}}`)
	if v.Action == "block" {
		t.Errorf("unblocked server: action = block, want non-block (block leaked across servers)")
	}
}

func TestInspectTool_ConnectorScopedMCPBlock_Isolated(t *testing.T) {
	api, _ := toolPolicyAPI(t, "action")
	// Block the "jira" MCP server only for codex.
	denyAsset(api.scannerCfg, "mcp", "jira", "codex", "scoped")

	// Rejected for codex…
	_, v := postInspectForConnector(t, api, "codex", `{"tool":"mcp__jira__createIssue","connector":"codex","args":{}}`)
	if v.Action != "block" {
		t.Errorf("codex: action = %q, want block", v.Action)
	}
	// …but allowed for a different connector…
	_, v = postInspectForConnector(t, api, "claudecode", `{"tool":"mcp__jira__createIssue","connector":"claudecode","args":{}}`)
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
	api, _ := toolPolicyAPI(t, "action")
	// Operator allow-lists the specific tool but blocks the whole MCP server.
	allowTool(api.scannerCfg, "mcp__jira__createIssue", "", "vetted tool")
	denyAsset(api.scannerCfg, "mcp", "jira", "", "server-wide block")

	// The server-level block must win over the tool-level allow.
	_, v := postInspectForConnector(t, api, "codex", `{"tool":"mcp__jira__createIssue","connector":"codex","args":{}}`)
	if v.Action != "block" {
		t.Errorf("action = %q, want block (mcp-server block must override a tool-level allow)", v.Action)
	}
}

// ---------------------------------------------------------------------------
// Sidecar lane (handleToolCall)
// ---------------------------------------------------------------------------

func TestHandleToolCall_GlobalMCPBlock(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	denyAsset(cfg, "mcp", "jira", "", "global")

	r := NewEventRouter(nil, store, logger, false)
	r.policy = configPolicy(store, cfg)
	payload, _ := json.Marshal(ToolCallPayload{Tool: "mcp__jira__createIssue", Args: json.RawMessage(`{}`), Status: "running"})
	r.Route(EventFrame{Type: "event", Event: "tool_call", Payload: payload})
	if !hasAction(t, store, "gateway-tool-call-blocked") {
		t.Error("global mcp block: expected a blocked event for the blocked MCP server's tool")
	}
}

func TestHandleToolCall_ConnectorScopedMCPBlock(t *testing.T) {
	// Blocked for codex.
	storeA, loggerA := testStoreAndLogger(t)
	cfg := &config.Config{}
	denyAsset(cfg, "mcp", "jira", "codex", "scoped")
	rCodex := NewEventRouter(nil, storeA, loggerA, false)
	rCodex.policy = configPolicy(storeA, cfg)
	rCodex.SetGuardrailConfig(&config.GuardrailConfig{Connector: "codex"})
	payload, _ := json.Marshal(ToolCallPayload{Tool: "mcp__jira__createIssue", Args: json.RawMessage(`{}`), Status: "running"})
	rCodex.Route(EventFrame{Type: "event", Event: "tool_call", Payload: payload})
	if !hasAction(t, storeA, "gateway-tool-call-blocked") {
		t.Error("codex router: expected a blocked event for the connector-scoped mcp block")
	}

	// Same block must NOT fire for a different connector.
	storeB, loggerB := testStoreAndLogger(t)
	rOther := NewEventRouter(nil, storeB, loggerB, false)
	rOther.policy = configPolicy(storeB, cfg)
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
	cfg := &config.Config{}
	denyAsset(cfg, "mcp", "jira", "", "global")
	pe := configPolicy(store, cfg)

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
	// GAP-0963: a server its install admission disabled says so, with the
	// journal's reason, so it is not read as an asset_policy decision.
	if err := store.SetActionFieldForConnector("mcp", "wiki-rogue", "claudecode", "runtime", "disable", "scanner failure (fail-closed): loopback"); err != nil {
		t.Fatal(err)
	}
	if deny, _, reason := mcpServerRuntimeBlock(pe, "mcp__wiki-rogue__count_words", "claudecode", ""); !deny ||
		!strings.Contains(reason, "install admission rejected it (scanner failure (fail-closed): loopback)") {
		t.Errorf("disabled mcp server: deny=%v reason=%q, want the admission verdict named", deny, reason)
	}
	// Codex passes the configured name its hook resolved (GAP-0939).
	if err := store.SetActionFieldForConnector("mcp", "wiki-rogue", "codex", "runtime", "disable", "scanner failure (fail-closed): loopback"); err != nil {
		t.Fatal(err)
	}
	if deny, server, _ := mcpServerRuntimeBlock(pe, "mcp__wiki_rogue__count_words", "codex", "wiki-rogue"); !deny || server != "wiki-rogue" {
		t.Errorf("codex disabled mcp server: deny=%v server=%q, want it refused as in Claude Code", deny, server)
	}
}

func TestInspectTool_MCPServerBlock_UsesExplicitServerName(t *testing.T) {
	api, _ := toolPolicyAPI(t, "action")
	denyAsset(api.scannerCfg, "mcp", "jira", "codex", "scoped")

	_, v := postInspectForConnector(t, api, "codex", `{"tool":"createIssue","mcp_server_name":"jira","connector":"codex","args":{}}`)
	if v.Action != "block" {
		t.Errorf("explicit mcp_server_name: action = %q, want block", v.Action)
	}
	if !hasFinding(v.Findings, "MCP-BLOCK") {
		t.Errorf("findings = %v, want MCP-BLOCK", v.Findings)
	}
}

func TestOpenCodeHook_ConnectorScopedMCPBlockUsesMappedServerIdentity(t *testing.T) {
	store, err := audit.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	denyAsset(cfg, "mcp", "jira.prod", "opencode", "scoped")
	policy := configPolicy(store, cfg)
	deny, server, _ := mcpServerRuntimeBlock(policy, "jira_prod_createIssue", "opencode", "jira.prod")
	if !deny || server != "jira.prod" {
		t.Fatalf("opencode mapped identity: deny=%v server=%q, want scoped deny for jira.prod", deny, server)
	}
	if deny, _, _ := mcpServerRuntimeBlock(policy, "jira_prod_createIssue", "codex", "jira.prod"); deny {
		t.Fatal("OpenCode-scoped mapped identity leaked to another connector")
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

// A URL block entered by the CLI must follow the configured server name into
// the tool hook; the hook never supplies the endpoint itself.
func TestMCPServerRuntimeBlock_URLRule(t *testing.T) {
	store, _ := testStoreAndLogger(t)
	path := filepath.Join(t.TempDir(), "openclaw.json")
	if err := os.WriteFile(path, []byte(`{"mcp":{"servers":{"filesystem":{"url":"https://server.example/mcp"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Claw.ConfigFile = path
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "https://server.example/mcp"}}
	pe := configPolicy(store, cfg)
	if deny, _, _ := mcpServerRuntimeBlock(pe, "mcp__filesystem__read", "", ""); !deny {
		t.Fatal("URL block did not deny the configured server tool")
	}
}

// A reload between the MCP and tool checks must not combine permissions
// from two policy generations into an allow.
func TestInspectToolPolicyUsesOneConfigAcrossMCPAndToolChecks(t *testing.T) {
	api, _ := toolPolicyAPI(t, "action")
	old := api.scannerCfg
	denyTool(old, "mcp__jira__createIssue", "codex", "old tool block")
	newCfg := &config.Config{}
	denyAsset(newCfg, "mcp", "jira", "codex", "new server block")
	reads := 0
	api.configSnapshot = func() *config.Config {
		reads++
		if reads <= 2 {
			return old
		}
		return newCfg
	}
	ctx := withPinnedGeneration(context.Background(), &Generation{Config: old, N: 1})
	verdict := api.inspectTrustedToolPolicyCtx(ctx, &ToolInspectRequest{
		Tool: "mcp__jira__createIssue", Connector: "codex", Args: json.RawMessage(`{}`),
	}, trustedActionRequest{})
	if verdict.Action != "block" || !hasFinding(verdict.Findings, "STATIC-BLOCK") {
		t.Fatalf("mixed-generation verdict = %+v, want the pinned tool block", verdict)
	}
}
