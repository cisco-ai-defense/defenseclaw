// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0686: a CODEX_HOME set only for the session is not in the account
// environment the hook enumerator reads, so the server it defines has no
// install admission and no scan verdict. A managed Windows gateway refuses
// the call until the published record holds the same definition; the default
// file, a persistent CODEX_HOME (both published) and a tool result are not
// refused.
func TestGAP0686SessionOnlyCodexHomeIsRefusedUntilPublished(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	api := &APIServer{scannerCfg: cfg}
	published, asked := false, 0
	api.SetMCPDefinitionPublished(func(connector, server, home, _ string, def config.MCPServerEntry) bool {
		asked++
		if connector != "codex" || server != "notes" || home == "" || def.URL != gap0686OtherURL {
			t.Errorf("asked about %q %q %q %+v", connector, server, home, def)
		}
		return published
	})
	home := t.TempDir()
	call := func(event string, relocated bool) (config.AssetPolicyDecision, bool) {
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
		ctx = gap0686Facts(ctx, t, gap0686OtherURL, relocated)
		return api.codexMCPAssetDecision(ctx, codexHookRequest{
			HookEventName: event, ToolName: "mcp__notes__count_words", ToolInput: map[string]interface{}{}, CWD: home,
		})
	}
	decision, refused := call("PreToolUse", true)
	if !refused || decision.Action != "block" || decision.Source != "mcp-source-unpublished" {
		t.Fatalf("unpublished session-only server: refused=%v decision=%+v, want a block", refused, decision)
	}
	published = true
	if decision, _ := call("PreToolUse", true); decision.Source == "mcp-source-unpublished" || decision.Action == "block" {
		t.Fatalf("published definition: %+v, want it allowed", decision)
	}
	published = false
	asked = 0
	if decision, _ := call("PreToolUse", false); decision.Source == "mcp-source-unpublished" || decision.Action == "block" || asked != 0 {
		t.Fatalf("ordinary server from the default config: %+v after %d questions, want it allowed unasked", decision, asked)
	}
	if decision, _ := call("PostToolUse", true); decision.Source == "mcp-source-unpublished" || asked != 0 {
		t.Fatalf("tool result: %+v after %d questions, want it left alone", decision, asked)
	}
}
