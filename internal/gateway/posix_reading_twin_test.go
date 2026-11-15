// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestPOSIXReadingTwinOnlyForAShellToolThatNamesNoShell: agy run_command
// (and send_command_input, projected as run_command) on a Windows host is
// also judged in its POSIX reading; a tool that names its shell, a call the
// Windows dialect did not place, and a twin keep one reading
// (rel-1-0-10:GAP-0850).
func TestPOSIXReadingTwinOnlyForAShellToolThatNamesNoShell(t *testing.T) {
	for _, tc := range []struct {
		connector, tool string
		want            bool
	}{
		{"antigravity", "run_command", true},
		{"antigravity", agentHookTrustedActionTool("antigravity", "send_command_input", "windows"), true},
		{"antigravity", "write_to_file", false},
		{"claudecode", "Bash", false},
		{"claudecode", "PowerShell", false},
		{"copilot", agentHookTrustedActionTool("copilot", "powershell", "windows"), false},
		{"kiro", agentHookTrustedActionTool("kiro", "execute_pwsh", "windows"), false},
	} {
		if got := agentHookShellToolNamesNoShell(tc.connector, tc.tool); got != tc.want {
			t.Errorf("agentHookShellToolNamesNoShell(%q, %q) = %v, want %v", tc.connector, tc.tool, got, tc.want)
		}
	}

	request := trustedActionRequest{
		Input:               actionfacts.Input{Tool: "run_command", DialectHint: actionfacts.DialectPowerShell},
		windowsShellDialect: true, windowsDialectReadings: true, posixReadingTwin: true,
		windowsPowerShellReading: &windowsHintedReading{},
		record:                   func(actionfacts.Facts, []RuleFinding) {},
	}
	twin, ok := posixReadingTwinRequest(request)
	if !ok {
		t.Fatal("no POSIX reading for a Windows-dialect run_command call")
	}
	if twin.Input.DialectHint != "" || twin.windowsShellDialect || twin.windowsDialectReadings ||
		twin.windowsPowerShellReading != nil || twin.posixReadingTwin || !twin.readingTwin || twin.record != nil {
		t.Errorf("POSIX reading twin = %+v, want the unhinted reading as a twin that records nothing and reads no further", twin)
	}
	for name, mutate := range map[string]func(*trustedActionRequest){
		"flag off":        func(r *trustedActionRequest) { r.posixReadingTwin = false },
		"a twin":          func(r *trustedActionRequest) { r.readingTwin = true },
		"no Windows hint": func(r *trustedActionRequest) { r.windowsShellDialect = false },
		"already POSIX":   func(r *trustedActionRequest) { r.Input.DialectHint = actionfacts.DialectPOSIX },
	} {
		r := request
		mutate(&r)
		if _, ok := posixReadingTwinRequest(r); ok {
			t.Errorf("%s: a POSIX reading twin was made", name)
		}
	}
}

// TestWindowsHostAntigravityCredentialOperandPastTheArgvBound: the
// acp_parity Bash case gap/rel-1-0-6_GAP-1069/128 (a credential-file operand
// past the argv bound) sent as agy run_command on a Windows host answers at
// least what Claude Code Bash answers, in every tier: the POSIX reading
// proves the credential operand that the PowerShell reading left at the
// unknown tier (rel-1-0-10:GAP-0850, native dc-win2 in review s7-tfprev2).
func TestWindowsHostAntigravityCredentialOperandPastTheArgvBound(t *testing.T) {
	prev := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = prev })
	var args map[string]any
	for _, c := range shapeParityCases(t) {
		if c.id == "gap/rel-1-0-6_GAP-1069/128" && c.tool == "Bash" {
			args = c.args
		}
	}
	if args == nil {
		t.Fatal("fixture case gap/rel-1-0-6_GAP-1069/128 not found")
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		cwd := t.TempDir()
		claude := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		agy := gap0437Server(t, p, "antigravity", "action")
		installToolCallCorpusProfileConnector(t, "antigravity", p.pack)
		base := shapeParityHook(t, claude.handleAgentHook("claudecode"), shapeParityCall{name: "claudecode/Bash",
			conn: "claudecode", event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, "Bash", args)}, p.managed)
		seen := 0
		for _, call := range shapeParityNative("Bash", args, cwd) {
			if call.conn != "antigravity" {
				continue
			}
			seen++
			if got := shapeParityHook(t, agy.handleAgentHook("antigravity"), call, p.managed); shapeParityRank[got] < shapeParityRank[base] {
				t.Errorf("%s: %s answered %s, Claude Code Bash %s", p.name, call.name, got, base)
			}
		}
		if seen == 0 {
			t.Fatal("no antigravity rendering of the Bash case")
		}
	})
}
