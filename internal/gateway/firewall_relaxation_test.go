// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	completeFirewallRelaxationRuleID        = "tamper.complete_firewall_relaxation"
	completeFirewallRelaxationAttemptRuleID = "tamper.complete_firewall_relaxation_attempt"
)

func TestCompleteFirewallRelaxationProfilePosture(t *testing.T) {
	positives := []string{
		"iptables -F\niptables -P INPUT ACCEPT",
		"sudo iptables -F INPUT\nsudo iptables -P INPUT ACCEPT",
		"iptables -P INPUT ACCEPT\niptables -P FORWARD ACCEPT\niptables -P OUTPUT ACCEPT",
	}
	profiles := []struct {
		name     string
		action   string
		severity string
	}{
		{name: "default", action: "alert", severity: "HIGH"},
		{name: "permissive", action: "alert", severity: "HIGH"},
		{name: "strict", action: "block", severity: "CRITICAL"},
	}

	for _, profile := range profiles {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.name)
			for _, command := range positives {
				input := actionfacts.Input{
					Tool: "shell", Command: command, CWD: "/repo",
					DialectHint: actionfacts.DialectPOSIX,
				}
				facts := actionfacts.Analyze(input)
				proof, owned := trustedSemanticOwnerFindingProof(
					completeFirewallRelaxationRuleID, input, facts,
				)
				if !owned || !proof.authorizes(completeFirewallRelaxationRuleID) {
					t.Fatalf("exact owner did not authorize proof=%+v facts=%+v", proof, facts)
				}

				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
				response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
					t.Context(),
					codexHookRequest{
						HookEventName: "PreToolUse",
						ToolName:      "shell",
						CWD:           "/repo",
						ToolInput: map[string]interface{}{
							"command": command,
						},
					},
				)
				if response.Action != profile.action || response.RawAction != profile.action ||
					response.Severity != profile.severity ||
					!findingStringHasRuleID(response.Findings, completeFirewallRelaxationRuleID) {
					t.Fatalf("response=%+v want %s/%s with %s", response, profile.action, profile.severity, completeFirewallRelaxationRuleID)
				}
			}
		})
	}
}

func TestCompleteFirewallRelaxationFallbackContract(t *testing.T) {
	contract, ok := exactFallbackContracts[completeFirewallRelaxationRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil || contract.detectionOnly {
		t.Fatalf("firewall-relaxation fallback contract is incomplete: %+v", contract)
	}
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "complete exact pair",
			command: "iptables -F\niptables -P INPUT ACCEPT",
			want:    true,
		},
		{
			name:    "partial administrative operation",
			command: "iptables -P INPUT ACCEPT",
		},
		{
			name:    "augmented exact pair",
			command: "iptables -F\nwhoami\niptables -P INPUT ACCEPT",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := actionfacts.Input{
				Tool: "shell", Command: test.command, CWD: "/repo",
				DialectHint: actionfacts.DialectPOSIX,
			}
			facts := actionfacts.Analyze(input)
			if got := contract.proves(input, facts); got != test.want {
				t.Fatalf("fallback proof=%t want=%t facts=%+v", got, test.want, facts)
			}
			if got := contract.boundedSubgraphProves(input, facts); got != test.want {
				t.Fatalf("bounded proof=%t want=%t facts=%+v", got, test.want, facts)
			}
		})
	}
}

func TestCompleteFirewallRelaxationSemanticOwnerRejectsPartialAndInertText(t *testing.T) {
	for _, command := range []string{
		"iptables -P INPUT ACCEPT",
		"iptables -P INPUT ACCEPT\niptables -P FORWARD ACCEPT",
		"iptables -P INPUT ACCEPT\niptables -F",
		"iptables -F && iptables -P INPUT ACCEPT",
		"echo 'iptables -F; iptables -P INPUT ACCEPT'",
		"printf '%s\\n' 'iptables -F' 'iptables -P INPUT ACCEPT' > /tmp/open-firewall.sh",
	} {
		input := actionfacts.Input{
			Tool: "shell", Command: command, CWD: "/repo",
			DialectHint: actionfacts.DialectPOSIX,
		}
		facts := actionfacts.Analyze(input)
		proof, _ := trustedSemanticOwnerFindingProof(
			completeFirewallRelaxationRuleID, input, facts,
		)
		if proof.authorizes(completeFirewallRelaxationRuleID) {
			t.Fatalf("negative escaped exact owner: command=%q proof=%+v facts=%+v", command, proof, facts)
		}
	}
}

func TestCompleteFirewallRelaxationAttemptAlertsInEveryProfile(t *testing.T) {
	positives := []string{
		"iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT",
		"iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT && echo 'Default policies set to ACCEPT'",
	}
	owner := semanticOwners[completeFirewallRelaxationAttemptRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("attempt owner posture=%+v", owner)
	}
	contract, ok := exactFallbackContracts[completeFirewallRelaxationAttemptRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
		!contract.requiresExactDetectionProof || !contract.codeOwnedDetection ||
		!contract.alertOnly || contract.detectionOnly {
		t.Fatalf("attempt fallback contract=%+v", contract)
	}

	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			for _, command := range positives {
				input := actionfacts.Input{
					Tool: "shell", Command: command, CWD: "/repo",
					DialectHint: actionfacts.DialectPOSIX,
				}
				facts := actionfacts.Analyze(input)
				if facts.Authoritative() || !owner.eligible(facts) ||
					!contract.proves(input, facts) {
					t.Fatalf("attempt not exactly owned: facts=%+v", facts)
				}
				response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
					t.Context(),
					codexHookRequest{
						HookEventName: "PreToolUse",
						ToolName:      "shell",
						CWD:           "/repo",
						ToolInput: map[string]interface{}{
							"command": command,
						},
					},
				)
				if response.Action != guardrailActionAlert ||
					response.RawAction != guardrailActionAlert ||
					response.Severity != "HIGH" || response.WouldBlock ||
					!findingStringHasRuleID(response.Findings, completeFirewallRelaxationAttemptRuleID) {
					t.Fatalf("profile=%s response=%+v", profile, response)
				}
			}
		})
	}
}

func TestCompleteFirewallRelaxationAttemptRejectsUnsafeNearMisses(t *testing.T) {
	for _, command := range []string{
		"iptables -P INPUT ACCEPT || iptables -P FORWARD ACCEPT || iptables -P OUTPUT ACCEPT",
		"iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT || iptables -P OUTPUT ACCEPT",
		"iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT",
		"sudo iptables -P INPUT ACCEPT && sudo iptables -P FORWARD ACCEPT && sudo iptables -P OUTPUT ACCEPT",
		"iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT > /tmp/status",
		"iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT && whoami",
	} {
		input := actionfacts.Input{
			Tool: "shell", Command: command, CWD: "/repo",
			DialectHint: actionfacts.DialectPOSIX,
		}
		facts := actionfacts.Analyze(input)
		if semanticOwners[completeFirewallRelaxationAttemptRuleID].eligible(facts) {
			t.Fatalf("near miss escaped owner: command=%q facts=%+v", command, facts)
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, EnforcementCapable: true,
		})
		if findingWithID(findings, completeFirewallRelaxationAttemptRuleID) != nil {
			t.Fatalf("near miss produced attempt finding: command=%q findings=%v", command, FindingStrings(findings))
		}
	}
}
