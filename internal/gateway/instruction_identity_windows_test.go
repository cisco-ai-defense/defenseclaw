// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"golang.org/x/sys/windows"
)

// GAP-0869 on Windows: the gateway reads the file's names itself (the
// Windows hook sends no client evidence). A hard link anywhere on the volume,
// a short (8.3) name and new hard links from PowerShell, cmd and fsutil all
// reach the instruction file.
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
		{"PowerShell new hard link", "New-Item -ItemType HardLink -Path '" + filepath.Join(root, "scratch", "n2") + "' -Target '" + instruction + "'", actionfacts.DialectPowerShell, true},
		{"cmd mklink", "mklink /H \"" + filepath.Join(root, "scratch", "n3") + "\" \"" + instruction + "\"", actionfacts.DialectCMD, true},
		{"fsutil", "fsutil hardlink create \"" + filepath.Join(root, "scratch", "n4") + "\" \"" + instruction + "\"", actionfacts.DialectCMD, true},
		{"ordinary write", "Set-Content -LiteralPath '" + plain + "' -Value changed", actionfacts.DialectPowerShell, false},
	}
	if short := windowsShortPath(t, instruction); short != "" {
		cases = append(cases, windowsCase{"short name", "Set-Content -LiteralPath '" + short + "' -Value changed", actionfacts.DialectPowerShell, true})
	}
	api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: project, ActiveHome: root, DialectHint: tc.dialect}
			verdict := api.inspectTrustedToolPolicyCtx(t.Context(), &ToolInspectRequest{Tool: "Bash", Direction: "tool_call", Connector: "claudecode"}, trustedActionRequest{
				Input: input, LegacyText: tc.command, Connector: "claudecode", EnforcementCapable: true,
			})
			blocked := verdict.Action == guardrailActionBlock
			if blocked != tc.blocked || tc.blocked && !findingStringHasRuleID(verdict.Findings, "COG-CLAUDE-MD") {
				t.Fatalf("%s: action=%q findings=%v, want blocked=%t", tc.command, verdict.Action, verdict.Findings, tc.blocked)
			}
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
