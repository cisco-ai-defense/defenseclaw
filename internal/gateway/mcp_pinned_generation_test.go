// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0873: a hook call about an MCP tool decides with the generation it was
// pinned to. A reload that publishes a config without the deny while the
// call runs (here, while the admission-pending check answers) does not turn
// the pinned generation's block into an allow.
func TestMCPHookDecisionKeepsThePinnedGenerationAcrossAReload(t *testing.T) {
	denying := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	denying.Guardrail.Mode = "action"
	denying.Guardrail.Connector = "claudecode"
	denying.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "gb05-decoy"}}
	reloaded := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	reloaded.Guardrail.Mode = "action"
	reloaded.Guardrail.Connector = "claudecode"

	live := denying
	api := &APIServer{scannerCfg: reloaded}
	api.SetConfigRuntime(nil, func() *config.Config { return live })
	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) {
		live = reloaded // the reload lands mid-request
		return server, false
	})
	call := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__gb05-decoy__ping",
		ToolInput: map[string]interface{}{}, CWD: t.TempDir()}

	pinned := withPinnedGeneration(context.Background(), &Generation{Config: denying, N: 1})
	if resp := api.evaluateClaudeCodeHook(pinned, call); resp.Action != "block" {
		t.Fatalf("pinned request: action=%q reason=%q, want the pinned generation's block", resp.Action, resp.Reason)
	}
	// The runtime asset decision itself, after the reload published the
	// config without the deny: the pinned request keeps its generation's
	// block list.
	live = reloaded
	probe := mcpRuntimeProbe{ServerName: "gb05-decoy", ToolName: "mcp__gb05-decoy__ping", Surface: "hook", Matched: true}
	if decision, matched := api.evaluateRuntimeMCPAssetPolicy(pinned, "claudecode", "PreToolUse", probe); !matched || decision.RawAction != "block" {
		t.Fatalf("pinned runtime decision after the reload = %+v (matched %v), want the pinned generation's block", decision, matched)
	}
	// Without a pinned generation the call reads the live config, which no
	// longer denies the server.
	if resp := api.evaluateClaudeCodeHook(context.Background(), call); resp.Action == "block" {
		t.Fatalf("unpinned request after the reload: action=%q reason=%q, want the live config's allow", resp.Action, resp.Reason)
	}
}

// GAP-0873: the admission-pending refusal reads the pinned generation too.
// The live snapshot is gone mid-request (nil while a reload swaps it), the
// pinned generation still decides, and the pending server is refused.
func TestMCPAdmissionPendingReadsThePinnedGeneration(t *testing.T) {
	pinnedCfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	pinnedCfg.Guardrail.Mode = "action"
	pinnedCfg.Guardrail.Connector = "claudecode"
	api := &APIServer{}
	api.SetConfigRuntime(nil, func() *config.Config { return nil })
	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { return server, true })
	probe := mcpRuntimeProbe{ServerName: "gb05-decoy", ToolName: "mcp__gb05-decoy__ping", Surface: "hook", Matched: true}

	pinned := withPinnedGeneration(context.Background(), &Generation{Config: pinnedCfg, N: 1})
	if _, refused := api.mcpAdmissionPendingDecision(pinned, "claudecode", "PreToolUse", probe); !refused {
		t.Fatal("pinned request with a pending server was not refused")
	}
	if _, refused := api.mcpAdmissionPendingDecision(context.Background(), "claudecode", "PreToolUse", probe); refused {
		t.Fatal("unpinned request without any config was refused")
	}
}
