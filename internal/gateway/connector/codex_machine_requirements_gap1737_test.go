// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// GAP-1737 (#898): the Windows Codex machine requirements writer keeps the
// administrator's requirements.toml as written: comments, key order,
// spelling and the administrator's own hook groups survive install, a repair
// and removal, on the Secure Client and the standalone profile. Before the
// fix every write re-marshalled the whole document and dropped every comment.
func TestGAP1737CodexRequirementsKeepAdministratorText(t *testing.T) {
	admin := strings.Join([]string{
		"# Contoso Codex policy, owned by IT (ticket 4711).",
		"# Do not edit by hand.",
		`approval_policy_floor = "on-request"   # floor for every user`,
		"",
		"[features]",
		"# keep web search off",
		"web_search = false",
		"",
		"[sandbox_workspace_write]",
		"# network stays off",
		"network_access = false",
		"",
		"[hooks]",
		"# IT audit hook",
		"[[hooks.PreToolUse]]",
		`matcher = "Bash"`,
		"# the IT logger",
		"[[hooks.PreToolUse.hooks]]",
		`type = "command"`,
		`command = 'C:\IT\audit.exe'`,
		"timeout = 5",
		"",
	}, "\n")
	adminLines := []string{}
	for _, line := range strings.Split(admin, "\n") {
		if strings.TrimSpace(line) != "" {
			adminLines = append(adminLines, line)
		}
	}
	for name, opts := range map[string]WindowsCodexMachineRequirementsOptions{
		"secure client": testWindowsCodexMachineOptions(),
		"standalone":    standaloneWindowsCodexMachineOptions(),
	} {
		for _, newline := range []string{"\n", "\r\n"} {
			raw := []byte(strings.ReplaceAll(admin, "\n", newline))
			installed, changed, err := reconcileWindowsCodexRequirements(raw, opts, false)
			if err != nil || !changed {
				t.Fatalf("%s: install changed=%v err=%v", name, changed, err)
			}
			for _, line := range adminLines {
				if !strings.Contains(string(installed), line+newline) {
					t.Fatalf("%s: install lost the administrator line %q:\n%s", name, line, installed)
				}
			}
			if err := verifyWindowsCodexRequirementsBytes(installed, opts); err != nil {
				t.Fatalf("%s: installed file does not verify: %v\n%s", name, err, installed)
			}
			if newline == "\r\n" && strings.Count(string(installed), "\n") != strings.Count(string(installed), "\r\n") {
				t.Fatalf("%s: install mixed line endings into a CRLF file:\n%q", name, installed)
			}
			repaired, changed, err := reconcileWindowsCodexRequirements(installed, opts, true)
			if err != nil || changed || string(repaired) != string(installed) {
				t.Fatalf("%s: a repair of an intact file rewrote it (changed=%v err=%v):\n%s", name, changed, err, repaired)
			}
			removed, _, err := removeWindowsCodexRequirementsOwnedChanges(installed, raw, opts)
			if err != nil {
				t.Fatalf("%s: removal: %v", name, err)
			}
			for _, line := range adminLines {
				if !strings.Contains(string(removed), line+newline) {
					t.Fatalf("%s: removal lost the administrator line %q:\n%s", name, line, removed)
				}
			}
			if strings.Contains(string(removed), "defenseclaw-hook") {
				t.Fatalf("%s: removal left a DefenseClaw hook group:\n%s", name, removed)
			}
			stripped, ok, err := stripWindowsCodexLayout(installed, opts.HookBinary, opts.ManagedDir)
			if err != nil || !ok {
				t.Fatalf("%s: strip ok=%v err=%v", name, ok, err)
			}
			for _, line := range adminLines {
				if !strings.Contains(string(stripped), line+newline) {
					t.Fatalf("%s: strip lost the administrator line %q:\n%s", name, line, stripped)
				}
			}
		}
	}
}
