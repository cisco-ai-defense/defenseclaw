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

const fakeMacOSUpdateCredentialPromptRuleID = "credential.macos_fake_update_prompt"

func TestFakeMacOSUpdateCredentialPromptProfilePosture(t *testing.T) {
	positives := []struct {
		name    string
		command string
	}{
		{name: "system preferences", command: `osascript -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to display dialog "Software Update requires that you type your password to apply changes." & return & return  default answer "" with icon 1 with hidden answer with title "Software Update"'`},
		{name: "captured security update", command: `PWD_SPOOF=$(osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer')
echo $PWD_SPOOF`},
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
			for _, positive := range positives {
				positive := positive
				t.Run(positive.name, func(t *testing.T) {
					command := positive.command
					input := actionfacts.Input{
						Tool: "shell", Command: command, CWD: "/repo",
						DialectHint: actionfacts.DialectPOSIX,
					}
					facts := actionfacts.Analyze(input)
					if !actionfacts.ExactFakeMacOSUpdateCredentialPrompt(facts) {
						t.Fatalf("exact ActionFacts proof did not match: %+v", facts)
					}
					if facts.Authoritative() {
						proof, owned := trustedSemanticOwnerFindingProof(
							fakeMacOSUpdateCredentialPromptRuleID, input, facts,
						)
						if !owned || !proof.authorizes(fakeMacOSUpdateCredentialPromptRuleID) {
							t.Fatalf("exact owner did not authorize proof=%+v facts=%+v", proof, facts)
						}
					}
					dispatched := dispatchTrustedAction(t.Context(), trustedActionRequest{
						Input: input, LegacyText: command, Connector: connector, EnforcementCapable: true,
					})
					if !findingStringHasRuleID(FindingStrings(dispatched), fakeMacOSUpdateCredentialPromptRuleID) {
						t.Fatalf("trusted dispatch lost exact prompt: findings=%v facts=%+v", FindingStrings(dispatched), facts)
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
						!findingStringHasRuleID(response.Findings, fakeMacOSUpdateCredentialPromptRuleID) {
						t.Fatalf("response=%+v want %s/%s with %s", response, profile.action, profile.severity, fakeMacOSUpdateCredentialPromptRuleID)
					}
				})
			}
		})
	}
}

func TestFakeMacOSUpdateCredentialPromptFallbackContract(t *testing.T) {
	contract, ok := exactFallbackContracts[fakeMacOSUpdateCredentialPromptRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil || contract.detectionOnly {
		t.Fatalf("fake macOS update prompt fallback contract is incomplete: %+v", contract)
	}
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "exact captured source prompt",
			command: `ANSWER=$(osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer')`,
			want:    true,
		},
		{
			name:    "legitimate hidden credential dialog",
			command: `osascript -e 'display dialog "Enter your approved VPN password" default answer "" with hidden answer'`,
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

func TestFakeMacOSUpdateCredentialPromptOwnerRejectsNearMisses(t *testing.T) {
	for _, command := range []string{
		`osascript -e 'display dialog "Build completed" buttons {"OK"}'`,
		`osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "Security Update" default answer "" with icon stop with hidden answer'`,
		`osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop'`,
		`test -f /tmp/ready && osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer'`,
		`echo 'osascript -e display dialog Software Update with hidden answer'`,
	} {
		input := actionfacts.Input{
			Tool: "shell", Command: command, CWD: "/repo",
			DialectHint: actionfacts.DialectPOSIX,
		}
		facts := actionfacts.Analyze(input)
		proof, _ := trustedSemanticOwnerFindingProof(
			fakeMacOSUpdateCredentialPromptRuleID, input, facts,
		)
		if proof.authorizes(fakeMacOSUpdateCredentialPromptRuleID) {
			t.Fatalf("negative escaped exact owner: command=%q proof=%+v facts=%+v", command, proof, facts)
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, Connector: "codex", EnforcementCapable: true,
		})
		if findingStringHasRuleID(FindingStrings(findings), fakeMacOSUpdateCredentialPromptRuleID) {
			t.Fatalf("negative produced owner finding: command=%q findings=%v facts=%+v", command, FindingStrings(findings), facts)
		}
	}
}
