// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// nativeControlShape is a native output with its free text blanked, so two
// renderings of the same control compare equal whatever their wording.
func nativeControlShape(t *testing.T, output map[string]interface{}) interface{} {
	t.Helper()
	raw, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	var blank func(interface{}) interface{}
	blank = func(value interface{}) interface{} {
		switch item := value.(type) {
		case map[string]interface{}:
			out := map[string]interface{}{}
			for key, nested := range item {
				lower := strings.ToLower(key)
				if strings.Contains(lower, "reason") || strings.Contains(lower, "message") || strings.Contains(lower, "context") {
					out[key] = "<text>"
					continue
				}
				out[key] = blank(nested)
			}
			return out
		case []interface{}:
			out := make([]interface{}, len(item))
			for i := range item {
				out[i] = blank(item[i])
			}
			return out
		}
		return value
	}
	return blank(decoded)
}

// Review of Port-0440 loop round 2 (P2): when a connector's response renderer
// panicked again while rendering a failed check, the callback-free fallback
// answered a block without the event's native denial: nothing for Claude Code
// PermissionRequest (or any Claude Code and Codex event), the Copilot CLI shape
// for a VS Code Local PreToolUse, nothing for its prompt, and no VS Code Local
// decision for the Copilot CLI hook file answering a VS Code Local tool. Every
// registered connector, the VS Code Local surface and every event: the
// fallback carries the control the healthy answer carries, and an allow never
// carries a denial or a lifecycle veto.
func TestFailedCheckFallbackCarriesTheHealthyNativeControl(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	api := &APIServer{}
	profiles := panicTestProfiles(t, api)
	profiles["copilot/vscode-local"] = connector.CopilotVSCodeLocalProfile(profiles["copilot"])
	const plain = "DefenseClaw could not complete its hook check because of an internal evaluator error."
	covered := map[string]bool{}
	for key, profile := range profiles {
		name, _, _ := strings.Cut(key, "/")
		for _, event := range profile.SupportedEvents {
			lifecycle := hookexec.LifecycleEvent(name, event)
			tools := []string{""}
			if name == "copilot" {
				tools = append(tools, "run_in_terminal")
			}
			for _, tool := range tools {
				req := agentHookRequest{ConnectorName: name, HookEventName: event, ToolName: tool}
				actions := []string{"allow"}
				if action, _ := failedCheckNativeAction(t.Context(), profile, name, req, true); !lifecycle && action != "allow" {
					actions = append(actions, action)
				}
				for _, action := range actions {
					t.Run(key+"/"+event+"/"+tool+"/"+action, func(t *testing.T) {
						resp := agentHookResponse{Action: action, RawAction: "block", Severity: "WARN", Mode: "action", WouldBlock: action == "allow"}
						healthy := api.renderSandboxVerdict(t.Context(), profile, req, nil, nil, resp, plain)
						additional := healthy.AdditionalContext
						if lifecycle {
							// A lifecycle allow is the neutral answer, rendered
							// without the would-block context
							// (neutralLifecycleHookOutput).
							additional = ""
						}
						fallback := failedCheckFallbackOutput(profile, req, action, "block", plain, additional)
						if action == "allow" {
							if panicWireDenies(fallback) || (lifecycle && lifecycleAnswerRepeats(fallback)) {
								t.Fatalf("fallback allow=%v carries a denial or a veto", fallback)
							}
							return
						}
						covered[key+"/"+event+"/"+tool] = true
						if got, want := nativeControlShape(t, fallback), nativeControlShape(t, healthy.HookOutput); !reflect.DeepEqual(got, want) {
							t.Fatalf("fallback %s output=%v, want the healthy native control %v", action, got, want)
						}
					})
				}
			}
		}
	}
	for _, cell := range []string{
		"claudecode/PermissionRequest/", "claudecode/PreToolUse/", "claudecode/Elicitation/", "claudecode/PostToolBatch/",
		"codex/PermissionRequest/", "copilot/vscode-local/PreToolUse/", "copilot/vscode-local/UserPromptSubmit/",
		"copilot/preToolUse/run_in_terminal", "copilot/permissionRequest/", "hermes/pre_verify/",
		"cursor/beforeShellExecution/", "antigravity/PreToolUse/",
	} {
		if !covered[cell] {
			t.Errorf("fallback cell %s was not covered; covered=%d", cell, len(covered))
		}
	}
}

// The scenario of the review: on a standalone managed host whose
// administrator chose fail mode open for outages, a connector's responder
// panics during the evaluation and again while the panic answer is rendered.
// The answer is an enforced block, and its native output is the denial the
// healthy renderer gives, so the agent does not run the call the audit
// records as blocked.
func TestManagedOpenResponderPanicKeepsTheNativeDenial(t *testing.T) {
	for _, tc := range []struct{ connector, event, tool string }{
		{"copilot", "preToolUse", "run_in_terminal"},
		{"copilot", "preToolUse", "bash"},
		{"copilot", "permissionRequest", ""},
		{"cursor", "beforeShellExecution", ""},
		{"cursor", "beforeSubmitPrompt", ""},
		{"antigravity", "PreToolUse", ""},
		{"devin", "PreToolUse", ""},
		{"kiro", "PreToolUse", ""},
		{"opencode", "tool.execute.before", ""},
		{"hermes", "pre_tool_call", ""},
	} {
		t.Run(tc.connector+"/"+tc.event+"/"+tc.tool, func(t *testing.T) {
			original, ok := sharedDefaultRegistry().Get(tc.connector)
			if !ok {
				t.Fatalf("missing registered %s connector", tc.connector)
			}
			provider, ok := original.(connector.HookProfileProvider)
			if !ok {
				t.Fatalf("%s has no hook profile", tc.connector)
			}
			panicked := false
			registry := connector.NewRegistry()
			registry.RegisterBuiltin(panickingResponderConnector{Connector: original, provider: provider, panicked: &panicked})
			cfg := config.DefaultConfig()
			cfg.DeploymentMode, cfg.Enterprise.Profile = managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone
			cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode = "action", "open"
			api := &APIServer{scannerCfg: cfg, connectorRegistry: registry}
			req := agentHookRequest{ConnectorName: tc.connector, HookEventName: tc.event, ToolName: tc.tool}
			resp := api.hookPanicResponse(t.Context(), tc.connector, req, nil, nil)
			if !panicked || resp.Action != "block" || resp.WouldBlock || resp.Mode != "action" {
				t.Fatalf("responder panic response=%+v panicked=%t, want an enforced block", resp, panicked)
			}
			healthyAPI := &APIServer{scannerCfg: cfg}
			healthy := healthyAPI.renderSandboxVerdict(t.Context(), healthyAPI.hookProfileForConnector(tc.connector), req, nil, nil,
				agentHookResponse{Action: "block", RawAction: "block", Severity: "WARN", Mode: "action"}, resp.Reason)
			if got, want := nativeControlShape(t, resp.HookOutput), nativeControlShape(t, healthy.HookOutput); !reflect.DeepEqual(got, want) {
				t.Fatalf("responder panic native output=%v, want the healthy denial %v", got, want)
			}
		})
	}
}
