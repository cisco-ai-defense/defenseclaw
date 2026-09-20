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

const netExecDefenderCommand = `nxc smb 192.0.2.10 -u fixture-user -H REDACTED_SECRET_0001 --exec-method smbexec -x 'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableScriptScanning $true"'`

func TestNetExecWindowsDefenderMultiControlProfilePosture(t *testing.T) {
	input := actionfacts.Input{
		Tool: "shell", Command: netExecDefenderCommand,
		CWD: "/repo", DialectHint: actionfacts.DialectPOSIX,
	}
	facts := actionfacts.Analyze(input)
	contract := exactFallbackContracts["tamper.windows_defender_multi_control_disable"]
	if contract.boundedSubgraphProves == nil ||
		!contract.boundedSubgraphProves(input, facts) {
		t.Fatalf("bounded fallback contract rejected exact trace facts=%+v", facts)
	}

	for _, profile := range []struct {
		name     string
		action   string
		severity string
	}{
		{name: "default", action: "alert", severity: "HIGH"},
		{name: "permissive", action: "alert", severity: "HIGH"},
		{name: "strict", action: "block", severity: "CRITICAL"},
	} {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.name)
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
						"command": netExecDefenderCommand,
					},
				},
			)
			if response.Action != profile.action || response.RawAction != profile.action ||
				response.Severity != profile.severity ||
				!findingStringHasRuleID(
					response.Findings,
					"tamper.windows_defender_multi_control_disable",
				) {
				t.Fatalf("response=%+v want %s/%s", response, profile.action, profile.severity)
			}
		})
	}
}

func TestNetExecWindowsDefenderMultiControlProfileRejectsOpenGrammar(t *testing.T) {
	const command = `nxc smb 192.0.2.10 -u fixture-user -H REDACTED_SECRET_0001 --exec-method smbexec -x 'powershell -EncodedCommand REDACTED_ENCODED_PAYLOAD'`
	const connector = "codex"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
		t.Context(),
		codexHookRequest{
			HookEventName: "PreToolUse",
			ToolName:      "shell",
			CWD:           "/repo",
			ToolInput:     map[string]interface{}{"command": command},
		},
	)
	if findingStringHasRuleID(
		response.Findings,
		"tamper.windows_defender_multi_control_disable",
	) {
		t.Fatalf("open grammar produced Defender finding: %+v", response)
	}
}
