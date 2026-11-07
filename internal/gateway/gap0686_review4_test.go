// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0686 review 4: a project definition whose URL does not fit the hook
// fact reaches the gateway as a name and a digest. An explicit denied URL must
// still be refused for it (the rule cannot be checked against the digest), in
// every asset-policy mode, and an ordinary long URL with no endpoint rule must
// stay allowed.
func TestGAP0686LongProjectURLStillMeetsAnExplicitDeny(t *testing.T) {
	home := t.TempDir()
	url := "https://example.invalid/mcp?key=" + strings.Repeat("a", 1100)
	entry := config.MCPServerEntry{Name: "notes", URL: url}
	for _, mode := range []string{"policy off", "observe"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			if mode == "observe" {
				cfg.AssetPolicy.Enabled = true
				cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
			}
			// Twin first: no endpoint rule, the long project server stays allowed.
			api := &APIServer{scannerCfg: cfg}
			gap0686Publish(api, cfg)
			if decision, matched := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(entry, false)); matched && decision.Action == "block" {
				t.Fatalf("ordinary long project URL refused with no endpoint rule: %+v", decision)
			}
			cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: url}}
			decision, matched := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(entry, false))
			if !matched || decision.Action != "block" {
				t.Fatalf("explicit project URL deny was bypassed: matched=%v decision=%+v", matched, decision)
			}
		})
	}
}

// A connector override to action mode is the mode that counts: an unscanned
// project server must not run under Codex when its own mode is action.
func TestGAP0686ProjectServerFollowsTheConnectorAssetMode(t *testing.T) {
	home := t.TempDir()
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
	api := &APIServer{scannerCfg: cfg}
	gap0686Publish(api, cfg)
	project := config.MCPServerEntry{Name: "notes", URL: "https://project.example.invalid/mcp"}
	if decision, matched := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(project, false)); matched && decision.Action == "block" {
		t.Fatalf("observe mode refused a project server: %+v", decision)
	}
	cfg.AssetPolicy.Connectors = map[string]config.PerConnectorAssetPolicy{"codex": {Mode: config.AssetPolicyModeAction}}
	decision, matched := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(project, false))
	if !matched || decision.Action != "block" {
		t.Fatalf("Codex action override let an unscanned project server run: matched=%v decision=%+v", matched, decision)
	}
}

// An untrusted project file is not what Codex runs, so it must not make the
// ordinary published user server a refusal. The hook sends no project claim
// for it (see cli TestHookAssetFactsMarkTheRelocatedCodexConfig).
func TestGAP0686UntrustedProjectFileDoesNotRefusePublishedUserServer(t *testing.T) {
	home := t.TempDir()
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	api := &APIServer{scannerCfg: cfg}
	user := config.MCPServerEntry{Name: "notes", URL: "https://ordinary.example.invalid/mcp", Connector: "codex", Home: home}
	gap0686Publish(api, cfg, user)
	project := config.MCPServerEntry{Name: "notes", URL: "https://project.example.invalid/mcp", SourceScope: "project", TrustRequired: true}
	if decision, matched := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(project, false)); matched && decision.Action == "block" {
		t.Fatalf("ordinary published user server refused because an untrusted project file exists: %+v", decision)
	}
	// Protected twin: the same project file, trusted, still overrides the
	// published server and is refused until it is published.
	project.TrustRequired = false
	decision, matched := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(project, false))
	if !matched || decision.Action != "block" {
		t.Fatalf("trusted project override of a published server: matched=%v decision=%+v, want a block", matched, decision)
	}
}
