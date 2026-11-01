// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"golang.org/x/sys/windows"
)

// GAP-0869 and GAP-0971 on Windows: the gateway checks file identity itself
// (the Windows hook sends no client evidence). A write through a hard link,
// a short (8.3) name, or to the physical file a symlinked CLAUDE.md reaches
// writes the instruction file. Creating a hard link from PowerShell, cmd or
// fsutil writes nothing, and an ordinary write stays allowed.
func TestInstructionProtectionWindowsHardLinks(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	instruction := writeActiveAgentTestFile(t, project, "CLAUDE.md")
	alias := instructionIdentityTestLink(t, instruction, filepath.Join(root, "scratch", "notes.txt"))
	plain := writeActiveAgentTestFile(t, project, "plain.txt")
	type windowsCase struct {
		name, command string
		dialect       actionfacts.Dialect
		blocked       bool
	}
	cases := []windowsCase{
		{"PowerShell alias write", "Set-Content -LiteralPath '" + alias + "' -Value changed", actionfacts.DialectPowerShell, true},
		{"PowerShell alias append", "Add-Content -LiteralPath '" + alias + "' -Value changed", actionfacts.DialectPowerShell, true},
		{"cmd alias append", "echo changed >> \"" + alias + "\"", actionfacts.DialectCMD, true},
		{"PowerShell new hard link", "New-Item -ItemType HardLink -Path '" + filepath.Join(root, "scratch", "n2") + "' -Target '" + instruction + "'", actionfacts.DialectPowerShell, false},
		{"cmd mklink", "mklink /H \"" + filepath.Join(root, "scratch", "n3") + "\" \"" + instruction + "\"", actionfacts.DialectCMD, false},
		{"fsutil", "fsutil hardlink create \"" + filepath.Join(root, "scratch", "n4") + "\" \"" + instruction + "\"", actionfacts.DialectCMD, false},
		{"ordinary write", "Set-Content -LiteralPath '" + plain + "' -Value changed", actionfacts.DialectPowerShell, false},
	}
	if short := windowsShortPath(t, instruction); short != "" {
		cases = append(cases, windowsCase{"short name", "Set-Content -LiteralPath '" + short + "' -Value changed", actionfacts.DialectPowerShell, true})
	}
	symlinkProject := filepath.Join(root, "symlinked")
	shared := writeActiveAgentTestFile(t, filepath.Join(root, "shared"), "instructions.txt")
	symlinked := true
	if err := os.MkdirAll(symlinkProject, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shared, filepath.Join(symlinkProject, "CLAUDE.md")); err != nil {
		t.Logf("symlinks unavailable, skipping the GAP-0971 case: %v", err)
		symlinked = false
	}
	api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	run := func(t *testing.T, cwd string, tc windowsCase) {
		input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: root, DialectHint: tc.dialect}
		verdict := api.inspectTrustedToolPolicyCtx(t.Context(), &ToolInspectRequest{Tool: "Bash", Direction: "tool_call", Connector: "claudecode"}, trustedActionRequest{
			Input: input, LegacyText: tc.command, Connector: "claudecode", EnforcementCapable: true,
		})
		if tc.blocked {
			if verdict.Action != guardrailActionBlock || !findingStringHasRuleID(verdict.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("%s: action=%q findings=%v, want a COG-CLAUDE-MD block", tc.command, verdict.Action, verdict.Findings)
			}
			return
		}
		for rule := range instructionRuleFiles {
			if findingStringHasRuleID(verdict.Findings, rule) {
				t.Fatalf("%s: got %s, want no instruction finding: %v", tc.command, rule, verdict.Findings)
			}
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { run(t, project, tc) })
	}
	if symlinked {
		t.Run("symlinked CLAUDE.md target", func(t *testing.T) {
			run(t, symlinkProject, windowsCase{"", "Set-Content -LiteralPath '" + shared + "' -Value changed", actionfacts.DialectPowerShell, true})
		})
	}
}

func windowsShortPath(t *testing.T, path string) string {
	t.Helper()
	long, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(long, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) > len(buffer) {
		return ""
	}
	short := windows.UTF16ToString(buffer[:n])
	if strings.EqualFold(filepath.Base(short), filepath.Base(path)) {
		// 8.3 names are off on this volume.
		return ""
	}
	return short
}
