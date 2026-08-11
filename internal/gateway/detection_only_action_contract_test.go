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

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestBuildVerdict_AllDetectionOnlyAllows(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.RulePackDir = "/profiles/strict"
	finding := RuleFinding{
		RuleID: "ACTION-PARSER-UNCERTAINTY", Title: "parser uncertainty",
		Severity: "LOW", enforcement: findingEnforcementDetectionOnly,
	}
	verdict := buildVerdictWithConfig([]RuleFinding{finding}, "tool_call", cfg, true)
	if verdict.Action != guardrailActionAllow || verdict.Severity != "LOW" ||
		len(verdict.DetailedFindings) != 1 ||
		verdict.DetailedFindings[0].contributesToEnforcement() {
		t.Fatalf("verdict = %+v, want retained LOW detection-only allow", verdict)
	}
}

func TestInspectTrustedToolPolicy_AllDetectionOnlyAllows(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.RulePackDir = "/profiles/strict"
	api := &APIServer{scannerCfg: cfg}

	command := "cat =(rm -rf /)"
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	hookReq := codexHookRequest{
		HookEventName: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": command}, CWD: "/repo",
	}
	response := api.evaluateCodexHook(t.Context(), hookReq)
	if response.Action != guardrailActionAllow || response.RawAction != guardrailActionAllow ||
		response.Severity != "LOW" ||
		!findingStringHasRuleID(response.Findings, trustedParserUncertaintyRuleID) {
		t.Fatalf("hook response = %+v, want raw allow with LOW parser telemetry", response)
	}

	verdict := api.inspectTrustedToolPolicyCtx(t.Context(), &ToolInspectRequest{
		Tool: "Bash", Args: args, Direction: "tool_call", Connector: "codex",
	}, trustedActionRequest{
		Input:      actionfacts.Input{Tool: "Bash", Args: args, CWD: "/repo"},
		LegacyText: string(args), Connector: "codex", EnforcementCapable: true,
	})
	if verdict.Action != guardrailActionAllow || len(verdict.DetailedFindings) == 0 {
		t.Fatalf("tool verdict = %+v, want retained detection-only findings", verdict)
	}
	for _, finding := range verdict.DetailedFindings {
		if finding.contributesToEnforcement() {
			t.Fatalf("detection-only tool finding became enforceable: %+v", finding)
		}
	}

	dangerous := api.evaluateCodexHook(t.Context(), codexHookRequest{
		HookEventName: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": "rm -rf /"}, CWD: "/repo",
	})
	if dangerous.RawAction == guardrailActionAllow {
		t.Fatalf("authoritative dangerous action lost enforcement: %+v", dangerous)
	}
}

func TestInspectToolCalls_AllDetectionOnlyAllows(t *testing.T) {
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	payload, err := json.Marshal([]map[string]interface{}{{
		"type": "function",
		"function": map[string]string{
			"name":      "Bash",
			"arguments": `{"command":"cat =(rm -rf /)"}`,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	verdict := proxy.inspectToolCalls(t.Context(), payload)
	if verdict == nil || verdict.Action != guardrailActionAllow || verdict.Severity != "LOW" ||
		!findingStringHasRuleID(verdict.Findings, trustedParserUncertaintyRuleID) {
		t.Fatalf("proxy verdict = %+v, want retained LOW detection-only allow", verdict)
	}
}

func TestArtifactPromotion_AllDetectionOnlyAllows(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "claudecode"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()
	path := filepath.Join(dir, "unreachable.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nrm -rf /\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: "shell", Command: fmt.Sprintf("false && bash %q", path), CWD: dir,
	})
	capture := &toolChainHookCapture{}
	capture.recordTrustedAction(facts, nil)
	req := agentHookRequest{
		ConnectorName: connectorName, HookEventName: "PreToolUse",
		SuppressCorrelationEmit: true, toolChain: capture,
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	api := &APIServer{scannerCfg: cfg}
	original := agentHookResponse{
		Action: guardrailActionAllow, RawAction: guardrailActionAllow,
		Severity: "NONE", Mode: "action",
	}
	got := api.safeApplyExperimentalArtifactPromotion(
		t.Context(), api.hookProfileForConnector(connectorName), req, original, 0,
	)
	if got.Action != guardrailActionAllow || got.RawAction != guardrailActionAllow ||
		len(got.Findings) == 0 {
		t.Fatalf("artifact response = %+v, want retained detection-only allow", got)
	}
}

func findingStringHasRuleID(findings []string, ruleID string) bool {
	prefix := ruleID + ":"
	for _, finding := range findings {
		if finding == ruleID || len(finding) > len(prefix) && finding[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
