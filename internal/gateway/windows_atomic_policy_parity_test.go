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

func TestWindowsAtomicPolicyParityProfilePosture(t *testing.T) {
	positives := []struct {
		name, ruleID, command, tool string
		dialect                     actionfacts.Dialect
	}{
		{
			name:    "Defender scheduled task removal",
			ruleID:  "tamper.windows_defender_component_disable",
			command: "schtasks /delete /tn \"\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /f",
			tool:    "cmd",
			dialect: actionfacts.DialectCMD,
		},
		{
			name:    "accessibility binary replacement",
			ruleID:  "persistence.windows_accessibility_feature_hijack",
			command: "copy /Y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe",
			tool:    "cmd",
			dialect: actionfacts.DialectCMD,
		},
		{
			name:   "UAC event viewer handler chain",
			ruleID: "privilege.windows_uac_autoelevation_hijack",
			command: "reg.exe add hkcu\\software\\classes\\mscfile\\shell\\open\\command /ve /d \"C:\\Windows\\System32\\cmd.exe\" /f\n" +
				"Start-Process -FilePath \"C:\\Windows\\System32\\eventvwr.msc\"",
			tool:    "PowerShell",
			dialect: actionfacts.DialectPowerShell,
		},
		{
			name:    "PowerShell UAC policy suppression",
			ruleID:  windowsRegistrySecurityControlRuleID,
			command: "Set-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name PromptOnSecureDesktop -Value 0 -Type Dword -Force",
			tool:    "PowerShell",
			dialect: actionfacts.DialectPowerShell,
		},
	}
	profiles := []struct {
		name, action, severity string
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
					input := actionfacts.Input{
						Tool: positive.tool, Command: positive.command,
						CWD: "C:\\repo", DialectHint: positive.dialect,
					}
					facts := actionfacts.Analyze(input)
					proof, owned := trustedSemanticOwnerFindingProof(
						positive.ruleID, input, facts,
					)
					if !owned || !proof.authorizes(positive.ruleID) {
						t.Fatalf("exact owner did not authorize %s: proof=%+v facts=%+v", positive.ruleID, proof, facts)
					}

					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					cfg.Guardrail.RulePackDir = filepath.Join(
						guardrailPoliciesRoot(t), profile.name,
					)
					response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
						t.Context(),
						codexHookRequest{
							HookEventName: "PreToolUse",
							ToolName:      positive.tool,
							CWD:           "C:\\repo",
							ToolInput: map[string]interface{}{
								"command": positive.command,
							},
						},
					)
					if response.Action != profile.action ||
						response.RawAction != profile.action ||
						response.Severity != profile.severity ||
						!findingStringHasRuleID(response.Findings, positive.ruleID) {
						t.Fatalf(
							"response=%+v, want %s/%s with %s",
							response, profile.action, profile.severity, positive.ruleID,
						)
					}
				})
			}
		})
	}
}

func TestWindowsAtomicPolicyParityHardNegatives(t *testing.T) {
	tests := []struct {
		name, ruleID, command, tool string
		dialect                     actionfacts.Dialect
	}{
		{
			name:    "Defender signature update",
			ruleID:  "tamper.windows_defender_component_disable",
			command: "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate",
			tool:    "cmd",
			dialect: actionfacts.DialectCMD,
		},
		{
			name:    "accessibility backup",
			ruleID:  "persistence.windows_accessibility_feature_hijack",
			command: "copy C:\\Windows\\System32\\utilman.exe C:\\Windows\\System32\\utilman_backup.exe",
			tool:    "cmd",
			dialect: actionfacts.DialectCMD,
		},
		{
			name:   "UAC handler mismatch",
			ruleID: "privilege.windows_uac_autoelevation_hijack",
			command: "reg.exe add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /ve /d C:\\Windows\\System32\\cmd.exe /f\n" +
				"Start-Process C:\\Windows\\System32\\eventvwr.msc",
			tool:    "PowerShell",
			dialect: actionfacts.DialectPowerShell,
		},
		{
			name:    "restore UAC policy",
			ruleID:  windowsRegistrySecurityControlRuleID,
			command: "Set-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA -Value 1 -Type Dword -Force",
			tool:    "PowerShell",
			dialect: actionfacts.DialectPowerShell,
		},
	}

	const connector = "windows-atomic-policy-hard-negatives"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			input := actionfacts.Input{
				Tool: test.tool, Command: test.command,
				CWD: "C:\\repo", DialectHint: test.dialect,
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: test.command, Connector: connector,
				EnforcementCapable: true,
			})
			if findingWithID(findings, test.ruleID) != nil {
				t.Fatalf("hard negative matched %s: %v", test.ruleID, FindingStrings(findings))
			}
		})
	}
}

func TestWindowsAtomicPolicyParityFallbackContracts(t *testing.T) {
	for _, ruleID := range []string{
		"tamper.windows_defender_component_disable",
		"privilege.windows_uac_autoelevation_hijack",
		"persistence.windows_accessibility_feature_hijack",
		windowsRegistrySecurityControlRuleID,
	} {
		contract, ok := exactFallbackContracts[ruleID]
		if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
			contract.detectionOnly {
			t.Fatalf("exact fallback contract %s is incomplete: %+v", ruleID, contract)
		}
	}
}
