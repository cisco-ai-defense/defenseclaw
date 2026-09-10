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

const windowsRegistrySecurityControlRuleID = "tamper.windows_registry_security_control_disable"

func exactWindowsRegistryWeakeningCommands() []struct {
	name    string
	command string
} {
	return []struct {
		name    string
		command string
	}{
		{name: "uac", command: `reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f`},
		{name: "uac admin prompt", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f`},
		{name: "hvci", command: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f`},
		{name: "tamper protection", command: `reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f`},
		{name: "credssp oracle", command: `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f`},
		{name: "rdp security layer", command: `reg add "hklm\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`},
		{name: "rdp nla", command: `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /d 0 /t REG_DWORD /f`},
	}
}

func TestWindowsRegistryWeakeningProfilePosture(t *testing.T) {
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
			for _, positive := range exactWindowsRegistryWeakeningCommands() {
				positive := positive
				t.Run(positive.name, func(t *testing.T) {
					input := actionfacts.Input{
						Tool: "shell", Command: positive.command,
						CWD: `C:\repo`, DialectHint: actionfacts.DialectCMD,
					}
					facts := actionfacts.Analyze(input)
					proof, owned := trustedSemanticOwnerFindingProof(
						windowsRegistrySecurityControlRuleID, input, facts,
					)
					if !owned || !proof.authorizes(windowsRegistrySecurityControlRuleID) {
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
							CWD:           `C:\repo`,
							ToolInput: map[string]interface{}{
								"command": positive.command,
							},
						},
					)
					if response.Action != profile.action || response.RawAction != profile.action ||
						response.Severity != profile.severity ||
						!findingStringHasRuleID(response.Findings, windowsRegistrySecurityControlRuleID) {
						t.Fatalf("response=%+v want %s/%s with %s", response, profile.action, profile.severity, windowsRegistrySecurityControlRuleID)
					}
				})
			}
		})
	}
}

func TestWindowsRegistryWeakeningFallbackContract(t *testing.T) {
	contract, ok := exactFallbackContracts[windowsRegistrySecurityControlRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil || contract.detectionOnly {
		t.Fatalf("Windows registry fallback contract is incomplete: %+v", contract)
	}
	for _, positive := range exactWindowsRegistryWeakeningCommands() {
		input := actionfacts.Input{
			Tool: "shell", Command: positive.command,
			CWD: `C:\repo`, DialectHint: actionfacts.DialectCMD,
		}
		facts := actionfacts.Analyze(input)
		if !contract.proves(input, facts) || !contract.boundedSubgraphProves(input, facts) {
			t.Fatalf("%s fallback contract rejected exact proof: %+v", positive.name, facts)
		}
	}
}
