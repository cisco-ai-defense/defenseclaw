// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

const replacementMCPURL = "https://replacement.example.test/mcp"

func wantRevokedAdmissionVerdict(t *testing.T, tc mcpTierCase, decision config.AssetPolicyDecision, matched bool) {
	t.Helper()
	if !matched || decision.Source != "mcp-admission-failed" {
		t.Fatalf("matched=%v decision=%+v, want the failed-admission verdict of the earlier definition", matched, decision)
	}
	if want := map[bool]string{true: "block", false: "allow"}[tc.failsClosed]; decision.Action != want {
		t.Fatalf("action %q, want %q (fail closed %v): %+v", decision.Action, want, tc.failsClosed, decision)
	}
}

// The hook names the server, not the connection. When the watcher says the
// admission of an earlier definition the agent may still run is revoked, an
// allow written for the definition the agent config lists now does not
// answer it: strict and managed refuse the call, default and permissive
// allow it with the visible failed-admission warning (GAP-0920).
func TestAllowForTheListedReplacementDoesNotReleaseARevokedEarlierDefinition(t *testing.T) {
	revoked := watcher.MCPAdmissionStatus{Name: "wiki", Failed: true, Revoked: true, ScanIssue: watcher.MCPScanIssueAddress}
	for _, tc := range mcpTierCases {
		t.Run(tc.name+"/claudecode", func(t *testing.T) {
			api := tc.api(config.AssetPolicyRule{Name: "wiki", URL: replacementMCPURL})
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			api.SetMCPAdmissionStatus(func(_, _, _, _ string) watcher.MCPAdmissionStatus { return revoked })
			writeClaudeServers(t, home, project, `{"wiki":{"type":"http","url":"`+replacementMCPURL+`"}}`)
			decision, matched := claudeMCPCall(api, ctx, project, "live", "mcp__wiki__ping")
			wantRevokedAdmissionVerdict(t, tc, decision, matched)
		})
		t.Run(tc.name+"/codex", func(t *testing.T) {
			api := tc.api(config.AssetPolicyRule{Name: "wiki", URL: replacementMCPURL})
			api.scannerCfg.Guardrail.Connector = "codex"
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			api.SetMCPAdmissionStatus(func(_, _, _, _ string) watcher.MCPAdmissionStatus { return revoked })
			path := filepath.Join(home, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("[mcp_servers.wiki]\nurl = \""+replacementMCPURL+"\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			decision, matched := api.codexMCPAssetDecision(ctx, codexHookRequest{
				HookEventName: "PreToolUse", SessionID: "live", ToolName: "mcp__wiki__ping", CWD: project,
			})
			wantRevokedAdmissionVerdict(t, tc, decision, matched)
		})
	}
}

// Benign twin: the same failed status without the revoked mark is the failure
// of the listed definition itself, and the allow written for that definition
// still decides it in every tier (GAP-0775, GAP-0778).
func TestAllowForTheListedDefinitionStillReleasesItsOwnFailedAdmission(t *testing.T) {
	listedFailed := watcher.MCPAdmissionStatus{Name: "wiki", Failed: true, ScanIssue: watcher.MCPScanIssueAddress}
	probe := mcpRuntimeProbe{ServerName: "wiki", ToolName: "mcp__wiki__ping", URL: replacementMCPURL, Surface: "hook", Matched: true}
	for _, tc := range mcpTierCases {
		t.Run(tc.name, func(t *testing.T) {
			api := tc.api(config.AssetPolicyRule{Name: "wiki", URL: replacementMCPURL})
			decision, refused := api.mcpAdmissionStatusDecision(context.Background(), api.scannerCfg,
				"claudecode", "PreToolUse", probe, listedFailed)
			if refused {
				t.Fatalf("an administrator-allowed listed definition still got an admission decision: %+v", decision)
			}
		})
	}
}
