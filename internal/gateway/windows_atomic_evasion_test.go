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

func TestWindowsAtomicEvasionProfilePosture(t *testing.T) {
	rules := []struct {
		name    string
		ruleID  string
		command string
		dialect actionfacts.Dialect
		tool    string
	}{
		{
			name:    "telemetry",
			ruleID:  "tamper.windows_telemetry_disable",
			command: `REG ADD HKCU\Environment /v COMPlus_ETWEnabled /t REG_SZ /d 0 /f`,
			dialect: actionfacts.DialectCMD,
			tool:    "cmd",
		},
		{
			name:    "credential protection",
			ruleID:  "tamper.windows_credential_protection_weaken",
			command: `reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f`,
			dialect: actionfacts.DialectCMD,
			tool:    "cmd",
		},
		{
			name:    "AMSI",
			ruleID:  "tamper.windows_amsi_disable",
			command: `New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script\Settings" -Name AmsiEnable -Value 0 -PropertyType DWORD -Force`,
			dialect: actionfacts.DialectPowerShell,
			tool:    "PowerShell",
		},
	}
	profiles := []struct {
		name   string
		action string
	}{
		{name: "default", action: "alert"},
		{name: "permissive", action: "alert"},
		{name: "strict", action: "block"},
	}

	for _, profile := range profiles {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.name)
			for _, rule := range rules {
				rule := rule
				t.Run(rule.name, func(t *testing.T) {
					input := actionfacts.Input{
						Tool:        "shell",
						Command:     rule.command,
						CWD:         `C:\repo`,
						DialectHint: rule.dialect,
					}
					facts := actionfacts.Analyze(input)
					proof, owned := trustedSemanticOwnerFindingProof(rule.ruleID, input, facts)
					if !owned || !proof.authorizes(rule.ruleID) {
						t.Fatalf("exact owner did not authorize %s: proof=%+v facts=%+v", rule.ruleID, proof, facts)
					}

					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
					response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
						HookEventName: "PreToolUse",
						ToolName:      rule.tool,
						CWD:           `C:\repo`,
						ToolInput: map[string]interface{}{
							"command": rule.command,
						},
					})
					if response.Action != profile.action || response.RawAction != profile.action ||
						response.Severity != "HIGH" ||
						!findingStringHasRuleID(response.Findings, rule.ruleID) {
						t.Fatalf("response=%+v, want %s/HIGH with %s", response, profile.action, rule.ruleID)
					}
				})
			}
		})
	}
}
