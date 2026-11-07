// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

type mcpTierCase struct {
	name, pack, deployment, profile string
	failsClosed                     bool
}

var mcpTierCases = []mcpTierCase{
	{"default", "default", "", "", false},
	{"permissive", "permissive", "", "", false},
	{"strict", "strict", "", "", true},
	{"managed", "default", "managed_enterprise", "standalone", true},
}

func (tc mcpTierCase) api(allowed ...config.AssetPolicyRule) *APIServer {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: tc.deployment,
		Enterprise: config.EnterpriseConfig{Profile: tc.profile}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = tc.pack
	cfg.AssetPolicy.MCP.Allowed = allowed
	return &APIServer{scannerCfg: cfg}
}

// GAP-0775: the administrator's allow rule for a server (by name and URL, as
// the loopback endpoint of a local agent gateway is allowed, or by name) beats
// the block of a scan that could not complete in the strict tier and every
// managed profile. The benign twins: the same server without a rule, or with
// a rule for another endpoint, stays blocked there.
func TestAdminAllowBeatsAnUnscannableServerBlockInEveryTier(t *testing.T) {
	const loopback = "http://127.0.0.1:18795/mcp"
	failed := watcher.MCPAdmissionStatus{Name: "gas", Failed: true, ScanIssue: watcher.MCPScanIssueAddress}
	probe := mcpRuntimeProbe{ServerName: "gas", ToolName: "mcp__gas__ping", URL: loopback, Surface: "hook", Matched: true}
	for _, tc := range mcpTierCases {
		for _, rc := range []struct {
			name      string
			allowed   []config.AssetPolicyRule
			wantAllow bool
		}{
			{"name and url", []config.AssetPolicyRule{{Name: "gas", URL: loopback}}, true},
			{"name", []config.AssetPolicyRule{{Name: "gas"}}, true},
			{"no rule", nil, false},
			{"another endpoint", []config.AssetPolicyRule{{Name: "gas", URL: "http://127.0.0.1:9999/mcp"}}, false},
			{"another server", []config.AssetPolicyRule{{Name: "other", URL: loopback}}, false},
		} {
			t.Run(tc.name+"/"+rc.name, func(t *testing.T) {
				api := tc.api(rc.allowed...)
				decision, refused := api.mcpAdmissionStatusDecision(context.Background(), api.scannerCfg,
					"claudecode", "PreToolUse", probe, failed)
				admitted := !refused || decision.Action == "allow"
				if want := !tc.failsClosed || rc.wantAllow; admitted != want {
					t.Fatalf("decision %+v (admission decision %v), admitted=%v, want %v", decision, refused, admitted, want)
				}
				if rc.wantAllow && refused {
					t.Fatalf("an administrator-allowed server still got an admission decision: %+v", decision)
				}
			})
		}
	}
}

// The same through the hook, for a rule by name: the call of an allowed
// server is allowed and the agent is not told to run any allow command.
func TestAdminAllowedServerCallIsAllowedByTheHookOnAFailedScan(t *testing.T) {
	for _, tc := range mcpTierCases {
		t.Run(tc.name, func(t *testing.T) {
			api := tc.api(config.AssetPolicyRule{Name: "notes"})
			api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
				return watcher.MCPAdmissionStatus{Name: server, Failed: true, ScanIssue: watcher.MCPScanIssueLauncher}
			})
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "mcp__notes__lookup", ToolInput: map[string]interface{}{}, CWD: t.TempDir(),
			})
			if resp.Action != "allow" || resp.WouldBlock || strings.Contains(resp.Reason+resp.AdditionalContext, "mcp allow") {
				t.Fatalf("allowed server: %+v", resp)
			}
		})
	}
}

// GAP-0776: a server whose configured name the reason cannot carry (spaces)
// still gets its cause and a next step, in the block and in the warning; the
// name is never put into a command line, and a managed device is sent to the
// administrator's policy because its CLI refuses an allow.
func TestFailedAdmissionTextKeepsCauseAndNextStepWithoutAShowableName(t *testing.T) {
	for _, tc := range mcpTierCases {
		for _, nc := range []struct {
			configured string
			wantAllow  bool
		}{
			{"notes", true},
			{"my notes", false},
			{"caf\u00e9", false},
		} {
			t.Run(tc.name+"/"+nc.configured, func(t *testing.T) {
				api := tc.api()
				api.SetMCPAdmissionStatus(func(_, _, _, _ string) watcher.MCPAdmissionStatus {
					return watcher.MCPAdmissionStatus{Name: nc.configured, Failed: true, ScanIssue: watcher.MCPScanIssueLauncher}
				})
				resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
					HookEventName: "PreToolUse", ToolName: "mcp__my_notes__lookup", ToolInput: map[string]interface{}{}, CWD: t.TempDir(),
				})
				text := resp.Reason + " " + resp.AdditionalContext
				wants := []string{"launcher is not npx or uvx", "public URL"}
				if tc.failsClosed {
					wants = append(wants, "failed admission scan")
				} else {
					wants = append(wants, "could not scan MCP server")
				}
				switch {
				case tc.deployment != "":
					wants = append(wants, "ask your administrator")
				case !nc.wantAllow:
					wants = append(wants, "defenseclaw mcp list")
				}
				for _, want := range wants {
					if !strings.Contains(text, want) {
						t.Errorf("agent text %q lacks %q", text, want)
					}
				}
				command := "defenseclaw mcp allow"
				switch {
				case tc.deployment != "" && strings.Contains(text, command):
					t.Errorf("managed text %q names the allow command its CLI refuses", text)
				case tc.deployment == "" && nc.wantAllow && !strings.Contains(text, command+" "+nc.configured):
					t.Errorf("text %q lacks the allow command for %q", text, nc.configured)
				case tc.deployment == "" && !nc.wantAllow && strings.Contains(text, command):
					t.Errorf("text %q puts the name %q into an allow command", text, nc.configured)
				}
				if strings.Contains(text, "redacted") || strings.Contains(text, "ASSET-POLICY") {
					t.Errorf("agent text %q is the redacted reason", text)
				}
			})
		}
	}
}
