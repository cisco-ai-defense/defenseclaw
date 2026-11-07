// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// GAP-0112: a project MCP server Claude Code started before the install
// watcher admitted it answered its first tool calls, a decoy a scan rejects
// included. In the strict tier, the hook refuses a call of a server whose
// admission is pending and leaves results and other servers as they were.
func TestHookRefusesMCPToolOfServerWithoutAdmission(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = "strict"
	api := &APIServer{scannerCfg: cfg}
	type ask struct{ connector, server, cwd string }
	var asked []ask
	api.SetMCPAdmissionPending(func(connector, server, _ /*home*/, cwd string) (string, bool) {
		asked = append(asked, ask{connector, server, cwd})
		return server, server == "gb05-decoy"
	})

	call := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__gb05-decoy__ping",
		ToolInput: map[string]interface{}{}, CWD: "/work/decoy"}
	if resp := api.evaluateClaudeCodeHook(context.Background(), call); resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("pending server: action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if len(asked) == 0 || asked[0] != (ask{"claudecode", "gb05-decoy", "/work/decoy"}) {
		t.Fatalf("asked %+v, want the decoy of claudecode in its project", asked)
	}
	admitted := call
	admitted.ToolName = "mcp__gb05-benign__ping"
	if resp := api.evaluateClaudeCodeHook(context.Background(), admitted); resp.Action == "block" {
		t.Fatalf("admitted server: action=%q, want it allowed", resp.Action)
	}
	result := call
	result.HookEventName = "PostToolUse"
	asked = nil
	api.evaluateClaudeCodeHook(context.Background(), result)
	if len(asked) != 0 {
		t.Fatalf("a tool result asked about admission: %+v", asked)
	}

	codexCfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	codexCfg.Guardrail.Mode = "action"
	codexCfg.Guardrail.Connector = "codex"
	codexCfg.Guardrail.RulePack = "strict"
	codex := &APIServer{scannerCfg: codexCfg}
	codex.SetMCPAdmissionPending(func(connector, server, _, _ string) (string, bool) {
		return server, connector == "codex" && server == "gb05-decoy"
	})
	resp := codex.evaluateCodexHook(context.Background(), codexHookRequest{HookEventName: "PreToolUse",
		ToolName: "mcp__gb05-decoy__ping", ToolInput: map[string]interface{}{}, CWD: "/work/decoy"})
	if resp.Action != "block" {
		t.Fatalf("codex pending server: action=%q, want block", resp.Action)
	}
}

// Secure Client keeps the hook of main (issue #1092).
func TestHookAdmissionPendingIsNotCheckedOnSecureClient(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.DeploymentMode = "managed_enterprise"
	if !cfg.SecureClientIntegration() {
		t.Fatal("fixture is not a Secure Client configuration")
	}
	api := &APIServer{scannerCfg: cfg}
	called := false
	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { called = true; return server, true })
	if _, refused := api.mcpAdmissionPendingDecision(context.Background(), "claudecode", "PreToolUse",
		mcpRuntimeProbe{ServerName: "gb05-decoy", ToolName: "mcp__gb05-decoy__ping", Surface: "hook", Matched: true}); refused || called {
		t.Fatalf("refused=%v called=%v on Secure Client, want neither", refused, called)
	}
}

// GAP-0210: the refusal of a call whose server admission is pending reaches
// the agent as a wait with retry guidance, not as the redacted registry
// fields of the decision ("registry_status=unknown registry_configured=false")
// or the final "Do not retry" block sentence. Standalone enterprise reads the
// same sentence.
func TestHookAdmissionPendingTellsTheAgentWhenToRetry(t *testing.T) {
	t.Cleanup(func() { setStandaloneEnterpriseActive(false) })
	for _, standalone := range []bool{false, true} {
		setStandaloneEnterpriseActive(standalone)
		cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		cfg.Guardrail.RulePack = "strict"
		api := &APIServer{scannerCfg: cfg}
		api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) { return server, true })
		resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{HookEventName: "PreToolUse",
			ToolName: "mcp__gb05-decoy__ping", ToolInput: map[string]interface{}{}, CWD: "/work/decoy"})
		if resp.Action != "block" {
			t.Fatalf("standalone=%v: action=%q, want block", standalone, resp.Action)
		}
		want := "DefenseClaw is still scanning the new MCP server gb05-decoy; retry in about 60 s. " +
			"Its tools stay blocked until the scan finishes. If the scan rejects the server, its calls stay blocked."
		if resp.Reason != want {
			t.Errorf("standalone=%v: reason %q, want %q", standalone, resp.Reason, want)
		}
		for _, leaked := range []string{"registry_status", "registry_configured", "Do not retry", "redacted"} {
			if strings.Contains(resp.Reason, leaked) {
				t.Errorf("standalone=%v: reason %q carries %q", standalone, resp.Reason, leaked)
			}
		}
	}
	// The OS notification names the state too.
	source := assetPolicyResponseReason(runtimeAssetDisableBlockDecision("mcp", "gb05-decoy", "claudecode", "hook", "x", "mcp-admission-pending"))
	if got := agentAssetPolicySubject(source); got != "MCP server gb05-decoy is not scanned yet; try the call again in about a minute" {
		t.Errorf("subject %q", got)
	}
	// Another source keeps its own wording.
	if got := agentMCPAdmissionPendingSentence(strings.Replace(source, "mcp-admission-pending", "runtime-disable", 2)); got != "" {
		t.Errorf("a runtime disable read as pending: %q", got)
	}
}

func TestGAP0034PendingAdmissionTiers(t *testing.T) {
	for _, tc := range []struct {
		name, pack, deployment, profile, action string
	}{
		{"default", "default", "", "", "allow"},
		{"permissive", "permissive", "", "", "allow"},
		{"strict", "strict", "", "", "block"},
		{"managed", "default", "managed_enterprise", "standalone", "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: tc.deployment,
				Enterprise: config.EnterpriseConfig{Profile: tc.profile}}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePack = tc.pack
			api := &APIServer{scannerCfg: cfg}
			if tc.name == "default" {
				store, logger := testStoreAndLogger(t)
				api.store, api.logger = store, logger
			}
			api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
				return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: 137 * time.Second}
			})
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "mcp__notes__lookup", ToolInput: map[string]interface{}{}, CWD: t.TempDir(),
			})
			if resp.Action != tc.action || resp.RawAction != "block" || resp.WouldBlock != (tc.action == "allow") {
				t.Fatalf("action=%q raw=%q would_block=%v, want %q/block", resp.Action, resp.RawAction, resp.WouldBlock, tc.action)
			}
			if !strings.Contains(resp.Reason, "notes") || !strings.Contains(resp.Reason, "scanning") ||
				!strings.Contains(resp.AdditionalContext, "notes") {
				t.Fatalf("pending warning or retry text missing: reason=%q context=%q", resp.Reason, resp.AdditionalContext)
			}
			if tc.action == "block" {
				if !strings.Contains(resp.Reason, "about 137 s") {
					t.Fatalf("retry time was not based on the scan timeout: %q", resp.Reason)
				}
			} else {
				if !strings.Contains(resp.AdditionalContext, "allowed while admission is pending") {
					t.Fatalf("allowed call has no visible pending warning: %+v", resp)
				}
				if _, ok := resp.ClaudeCodeOutput["systemMessage"]; !ok {
					t.Fatalf("Claude Code did not receive a warning: %+v", resp.ClaudeCodeOutput)
				}
			}
			if tc.name == "default" {
				events, err := api.store.ListEvents(50)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, event := range events {
					if event.Action == string(audit.ActionAssetPolicy) && strings.Contains(event.Details, "action=allow") &&
						strings.Contains(event.Details, "would_block=true") && strings.Contains(event.Details, "mcp-admission-pending") {
						found = true
					}
				}
				if !found {
					t.Fatalf("pending allow audit row missing: %+v", events)
				}
			}
		})
	}
}

// This fixture also runs on the 1.0.9 release base: only the pending call
// changes, while an admitted server remains available.
func TestGAP0034ReleaseBasePendingAllowAndBenignTwin(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	api.SetMCPAdmissionPending(func(_, server, _, _ string) (string, bool) {
		return server, server == "notes"
	})
	for _, tc := range []struct{ name, want string }{
		{"notes", "allow"}, {"admitted", "allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "mcp__" + tc.name + "__lookup",
				ToolInput: map[string]interface{}{}, CWD: t.TempDir(),
			})
			if response.Action != tc.want {
				t.Fatalf("action=%q, want %q", response.Action, tc.want)
			}
		})
	}
}

// A server DefenseClaw could not scan is not a malicious one (lead ruling
// 2026-11-06, GAP-0775): the OSS default and permissive tiers allow its calls
// with a visible warning and an audit row naming the cause and the next
// step; the strict tier and managed profiles stay blocked (fail closed). The
// first call after the server appears (pending) and every later one (failed)
// get the same decision, so no window of a different answer exists. This
// replaces TestGAP0034CompletedScanFailureBlocksEveryTier, whose default and
// permissive cells expected a block.
func TestCompletedScanFailureFollowsTierAndMatchesPending(t *testing.T) {
	for _, tc := range []struct {
		name, pack, deployment, profile, action string
	}{
		{"default", "default", "", "", "allow"}, {"permissive", "permissive", "", "", "allow"},
		{"strict", "strict", "", "", "block"}, {"managed", "default", "managed_enterprise", "standalone", "block"},
	} {
		for _, status := range []watcher.MCPAdmissionStatus{
			{Name: "notes", Pending: true, RetryAfter: time.Minute},
			{Name: "notes", Failed: true},
			{Name: "notes", Failed: true, ScanIssue: watcher.MCPScanIssueLauncher},
		} {
			t.Run(tc.name+fmt.Sprintf("/pending=%v/issue=%s", status.Pending, status.ScanIssue), func(t *testing.T) {
				cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: tc.deployment,
					Enterprise: config.EnterpriseConfig{Profile: tc.profile}}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = "claudecode"
				cfg.Guardrail.RulePack = tc.pack
				api := &APIServer{scannerCfg: cfg}
				api.SetMCPAdmissionStatus(func(_, _, _, _ string) watcher.MCPAdmissionStatus { return status })
				resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
					HookEventName: "PreToolUse", ToolName: "mcp__notes__lookup", ToolInput: map[string]interface{}{}, CWD: t.TempDir(),
				})
				if resp.Action != tc.action || resp.RawAction != "block" || resp.WouldBlock != (tc.action == "allow") {
					t.Fatalf("action=%q raw=%q would_block=%v, want %q/block: %+v", resp.Action, resp.RawAction, resp.WouldBlock, tc.action, resp)
				}
				if status.Failed && tc.action == "allow" {
					if _, ok := resp.ClaudeCodeOutput["systemMessage"]; !ok ||
						!strings.Contains(resp.AdditionalContext, "defenseclaw mcp allow notes") {
						t.Fatalf("allowed failed server has no warning with a next step: %+v", resp)
					}
				}
			})
		}
	}
}

// GAP-0776: the text the agent reads names why a server could not be scanned
// and the one next step, in the block (strict) and in the warning (default).
func TestFailedAdmissionTextNamesReasonAndNextStep(t *testing.T) {
	for _, tc := range []struct {
		issue string
		pack  string
		wants []string
	}{
		{watcher.MCPScanIssueLauncher, "strict", []string{"failed admission scan", "launcher is not npx or uvx", "defenseclaw mcp allow notes", "public URL"}},
		{watcher.MCPScanIssueAddress, "strict", []string{"failed admission scan", "loopback, private or link-local", "defenseclaw mcp allow notes", "public URL"}},
		{"", "strict", []string{"failed admission scan", "defenseclaw mcp list", "defenseclaw mcp allow notes"}},
		{watcher.MCPScanIssueLauncher, "default", []string{"could not scan MCP server notes", "launcher is not npx or uvx", "defenseclaw mcp allow notes"}},
		{watcher.MCPScanIssueAddress, "default", []string{"could not scan MCP server notes", "loopback, private or link-local", "defenseclaw mcp allow notes"}},
	} {
		t.Run(tc.pack+"/"+tc.issue, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePack = tc.pack
			api := &APIServer{scannerCfg: cfg}
			api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
				return watcher.MCPAdmissionStatus{Name: server, Failed: true, ScanIssue: tc.issue}
			})
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "mcp__notes__lookup", ToolInput: map[string]interface{}{}, CWD: t.TempDir(),
			})
			text := resp.Reason + " " + resp.AdditionalContext
			for _, want := range tc.wants {
				if !strings.Contains(text, want) {
					t.Errorf("agent text %q lacks %q", text, want)
				}
			}
		})
	}
}

func TestGAP0034DeniedServerAndAdmittedTwin(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "denied"}}
	api := &APIServer{scannerCfg: cfg}
	api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
		if server == "denied" {
			return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: time.Minute}
		}
		return watcher.MCPAdmissionStatus{}
	})
	for _, tc := range []struct{ server, action string }{{"denied", "block"}, {"notes", "allow"}} {
		resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "mcp__" + tc.server + "__lookup", ToolInput: map[string]interface{}{}, CWD: t.TempDir(),
		})
		if resp.Action != tc.action {
			t.Errorf("server %q: action=%q, want %q", tc.server, resp.Action, tc.action)
		}
	}
}

func TestGAP0034CodexPendingCallWarns(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	api := &APIServer{scannerCfg: cfg}
	api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
		return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: time.Minute}
	})
	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PreToolUse", ToolName: "mcp__notes__lookup", ToolInput: map[string]interface{}{}, CWD: t.TempDir(),
	})
	if resp.Action != "allow" || !resp.WouldBlock || !strings.Contains(resp.AdditionalContext, "allowed while admission is pending") {
		t.Fatalf("Codex pending warning: %+v", resp)
	}
	if _, ok := resp.CodexOutput["systemMessage"]; !ok {
		t.Fatalf("Codex did not receive a warning: %+v", resp.CodexOutput)
	}
}

func TestGAP0034AdmissionRefreshOutageFollowsTier(t *testing.T) {
	for _, tc := range []struct{ name, pack, deployment, profile, action string }{
		{"default", "default", "", "", "allow"},
		{"permissive", "permissive", "", "", "allow"},
		{"strict", "strict", "", "", "block"},
		{"managed", "default", "managed_enterprise", "standalone", "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: tc.deployment,
				Enterprise: config.EnterpriseConfig{Profile: tc.profile}}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePack = tc.pack
			api := &APIServer{scannerCfg: cfg}
			api.SetMCPRefreshBeforeCall(func(context.Context, string) error { return errors.New("timed out") })
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "mcp__notes__lookup", ToolInput: map[string]interface{}{}, CWD: t.TempDir(),
			})
			if resp.Action != tc.action || !strings.Contains(resp.Reason, "notes") ||
				!strings.Contains(resp.AdditionalContext, "notes") {
				t.Fatalf("refresh outage: %+v", resp)
			}
			if tc.action == "allow" && (!resp.WouldBlock || !strings.Contains(resp.AdditionalContext, "allowed with a warning")) {
				t.Fatalf("OSS outage warning: %+v", resp)
			}
		})
	}
}
