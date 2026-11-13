// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"slices"
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

// TestNetExecWindowsDefenderMultiControlWindowsDialectSelection runs the
// Windows hook's dialect choice on every OS. The -x body carries a literal
// double quote, which Windows PowerShell 5.1 can reserialize, so the PowerShell
// parse must not be authoritative: the hook then keeps the default dialect, and
// the NetExec remote-command recognizer still proves the Defender tamper next
// to the credentialed-NetExec rule in every pack. (The AD pack's PowerShell
// NetExec classifier once made this parse complete, the hook picked
// PowerShell, and the Defender finding was lost on Windows only.)
func TestNetExecWindowsDefenderMultiControlWindowsDialectSelection(t *testing.T) {
	input := actionfacts.Input{Tool: "shell", Command: netExecDefenderCommand, CWD: `C:\repo`}
	powerShell := input
	powerShell.DialectHint = actionfacts.DialectPowerShell
	if facts := actionfacts.Analyze(powerShell); facts.Authoritative() {
		t.Fatalf("PowerShell parse is authoritative for a reserializable native argv: parse=%+v", facts.Parse)
	}
	input.DialectHint = selectWindowsShellDialect("shell", netExecDefenderCommand, input)
	if input.DialectHint == actionfacts.DialectPowerShell {
		t.Fatalf("Windows hook selected PowerShell for a reserializable NetExec argv")
	}
	for _, base := range []string{"default", "permissive", "strict"} {
		t.Run(base, func(t *testing.T) {
			got := EvaluateDeterministicAction(context.Background(), input, netExecDefenderCommand, "benchmark-"+base, base)
			wantAction := "alert"
			if base == "strict" {
				wantAction = "block"
			}
			if got.Action != wantAction ||
				!slices.Contains(got.RuleIDs, "tamper.windows_defender_multi_control_disable") ||
				!slices.Contains(got.RuleIDs, "credential.directory_ticket_request") {
				t.Fatalf("action=%q rules=%v parse=%q, want %s with the Defender and NetExec credential rules",
					got.Action, got.RuleIDs, got.ParseStatus, wantAction)
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
