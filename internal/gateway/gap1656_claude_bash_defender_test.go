// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// A Defender stop or disable typed to the Claude Code Bash tool on a Windows
// host (Git Bash, POSIX dialect hint) is read as the same service operation as
// the cmd and PowerShell forms: the strict pack in action mode blocks it, in
// the per-user and the managed tier alike (rel-1-0-10:GAP-1656). The Bash tool
// word list of sc.exe was never read in the POSIX dialect, and the two-word
// start= disabled spelling matched in no dialect.
func TestGAP1656ClaudeBashDefenderServiceStop(t *testing.T) {
	prev := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = prev })
	forms := []string{
		"sc.exe stop WinDefend",
		"sc stop WinDefend",
		"sc.exe stop WinDefend; echo x",
		"sc.exe config WinDefend start= disabled",
		"sc config WinDefend start= disabled",
		"sc.exe config WinDefend start=disabled",
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		if p.name != "strict" && p.name != "managed-strict" {
			return
		}
		cwd := t.TempDir()
		claude := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		for _, form := range forms {
			got := shapeParityHook(t, claude.handleAgentHook("claudecode"), shapeParityCall{name: "claudecode/Bash",
				conn: "claudecode", event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, "Bash",
					map[string]any{"command": form})}, p.managed)
			if got != "block" {
				t.Errorf("%s: claudecode Bash %q = %s, want block (tamper.endpoint_security_product_disable)", p.name, form, got)
			}
		}
	})
}

// TestGAP1656ClaudeBashServiceQueriesStayAllowed: reading sc in the Git Bash
// dialect adds no block on a status query, a configuration read, an other
// service or an other start type, in any tier.
// The Defender stop and disable forms get the endpoint finding in the
// non-strict tiers too (alert, as the codex shell call does).
func TestGAP1656ClaudeBashServiceQueriesStayAllowed(t *testing.T) {
	prev := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = prev })
	benign := []string{
		"sc query WinDefend",
		"sc.exe query WinDefend",
		"sc qc WinDefend",
		"sc.exe qc WinDefend",
		"sc query",
		"sc.exe stop Spooler",
		"sc config Spooler start= disabled",
		"sc.exe config WinDefend start= auto",
	}
	attacks := []string{
		"sc.exe stop WinDefend",
		"sc config WinDefend start= disabled",
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		cwd := t.TempDir()
		claude := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		judge := func(form string) string {
			return shapeParityHook(t, claude.handleAgentHook("claudecode"), shapeParityCall{name: "claudecode/Bash",
				conn: "claudecode", event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, "Bash",
					map[string]any{"command": form})}, p.managed)
		}
		for _, form := range benign {
			if got := judge(form); got != "allow" {
				t.Errorf("%s: benign claudecode Bash %q = %s, want allow", p.name, form, got)
			}
		}
		want := "alert"
		if p.pack == "strict" {
			want = "block"
		}
		for _, form := range attacks {
			if got := judge(form); got != want {
				t.Errorf("%s: claudecode Bash %q = %s, want %s", p.name, form, got, want)
			}
		}
	})
}
