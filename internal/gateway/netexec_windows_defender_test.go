// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
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
			// The call runs as the hook judges it on a Linux host and, through
			// the Windows-only dialect gate (windowsHookHost), as on Windows.
			for _, windowsHost := range []bool{false, true} {
				previous := windowsHookHost
				windowsHookHost = func() bool { return windowsHost }
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
				windowsHookHost = previous
				if response.Action != profile.action || response.RawAction != profile.action ||
					response.Severity != profile.severity ||
					!findingStringHasRuleID(
						response.Findings,
						"tamper.windows_defender_multi_control_disable",
					) ||
					!findingStringHasRuleID(
						response.Findings,
						"credential.directory_ticket_request",
					) {
					t.Fatalf("windows host=%v response=%+v want %s/%s with both rules",
						windowsHost, response, profile.action, profile.severity)
				}
			}
		})
	}
}

// TestNetExecWindowsDefenderMultiControlIsDialectIndependent proves the
// Defender and the credentialed-NetExec findings of one call whichever shell
// reading the Windows hook ends up with: the reading its dialect choice picks
// (selectWindowsShellDialect, which runs on every OS), PowerShell forced, and
// the POSIX reading where a POSIX shell can spell the call. The spellings are
// the one program identity of rel-1-0-10:GAP-0366 (bare, launcher extension,
// upper case, a pipx path, a Windows path), built from
// netExecDefenderCommand by a prefix transform, so no new command text is
// kept here. An earlier fix made the PowerShell parse partial instead, which
// lost the credential finding of the same call under a PowerShell reading.
func TestNetExecWindowsDefenderMultiControlIsDialectIndependent(t *testing.T) {
	rest := strings.TrimPrefix(netExecDefenderCommand, "nxc ")
	spellings := []struct {
		name, prefix string
		posix        bool
	}{
		{"bare", "nxc ", true},
		{"exe", "nxc.exe ", true},
		{"upper exe", "NXC.EXE ", true},
		{"pipx path", "/home/fixture/.local/bin/nxc ", true},
		{"windows path", `C:\Tools\nxc.exe `, false},
		{"call operator path", `& 'C:\Tools\nxc.exe' `, false},
		{"unquoted call operator", "& nxc.exe ", false},
		{"unquoted call operator path", `& C:\Tools\nxc.exe `, false},
		{"call operator without a space", "&nxc.exe ", false},
		{"dot-sourced path", `. C:\Tools\nxc.exe `, false},
		{"cme alias", "cme.exe ", false},
	}
	for _, spelling := range spellings {
		command := spelling.prefix + rest
		base := actionfacts.Input{Tool: "shell", Command: command, CWD: `C:\repo`}
		readings := map[string]actionfacts.Dialect{
			"powershell": actionfacts.DialectPowerShell,
			"selected":   selectWindowsShellDialect("shell", command, base),
		}
		if spelling.posix {
			readings["posix"] = actionfacts.DialectPOSIX
		}
		for name, dialect := range readings {
			for _, pack := range []string{"default", "permissive", "strict"} {
				t.Run(spelling.name+"/"+name+"/"+pack, func(t *testing.T) {
					input := base
					input.DialectHint = dialect
					got := EvaluateDeterministicAction(context.Background(), input, command, "benchmark-"+pack, pack)
					wantAction := "alert"
					if pack == "strict" {
						wantAction = "block"
					}
					if got.Action != wantAction ||
						!slices.Contains(got.RuleIDs, "tamper.windows_defender_multi_control_disable") ||
						!slices.Contains(got.RuleIDs, "credential.directory_ticket_request") {
						t.Fatalf("dialect=%q action=%q rules=%v parse=%q, want %s with the Defender and the NetExec credential rules",
							dialect, got.Action, got.RuleIDs, got.ParseStatus, wantAction)
					}
				})
			}
		}
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
