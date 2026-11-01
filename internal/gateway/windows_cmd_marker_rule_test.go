// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-1727: on a Windows home a custom complete-argv rule must enforce on
// every cmd.exe /c spelling of the marker write, quoted or not, whatever
// shell tool name the agent reports and whichever grammar (PowerShell, CMD
// or the Git Bash reading) the call is read in. Before the fix the quoted
// bodies were a detection-only match: CMD reads cmd.exe /c without /d as
// partial (AutoRun), and the argv view existed only for PowerShell lists.
func TestR105WindowsCMDWrapperMarkerRuleEveryShellTool(t *testing.T) {
	resetConnectorRuleCategories(t)
	const ruleID = "R105-GAP1727-MARKER"
	if err := ApplyRulePackOverrides(&guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version: 1, Category: "r105-gap1727-marker", Rules: []guardrail.RuleDefYAML{{
			ID: ruleID, ToolCallOnly: true, Pattern: "fc-block-marker-",
			Expression: `f.commands.exists(c, c.argv_complete && c.argv.exists(a, a.startsWith("fc-block-marker-")))`,
			Title:      "marker", Severity: "CRITICAL", Confidence: 0.99,
		}},
	}}}); err != nil {
		t.Fatal(err)
	}
	sq := string(rune(39))
	home := `C:\Users\Alice`
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"plain echo", `echo fc-block-marker-1727 > fcout.txt`, true},
		{"unquoted redirect", `cmd.exe /c echo fc-block-marker-1727 > fcout.txt`, true},
		{"d switch unquoted", `cmd.exe /d /c echo fc-block-marker-1727`, true},
		{"quoted body redirect", `cmd.exe /c "echo fc-block-marker-1727 > fcout.txt"`, true},
		{"quoted body", `cmd.exe /c "echo fc-block-marker-1727"`, true},
		{"single-quoted body", `cmd.exe /c ` + sq + `echo fc-block-marker-1727` + sq, true},
		{"doubled quotes", `cmd.exe /c ""echo fc-block-marker-1727 > fcout.txt""`, true},
		{"quoted body list", `cmd.exe /c "echo fc-block-marker-1727 > x.txt && type x.txt"`, true},
		{"quoted body then type", `cmd.exe /c "echo fc-block-marker-1727 > x.txt" && type x.txt`, true},
		{"cmd quoted body", `cmd /c "echo fc-block-marker-1727 > fcout.txt"`, true},
		{"d switch quoted body", `cmd.exe /d /c "echo fc-block-marker-1727 > fcout.txt"`, true},
		{"benign quoted body", `cmd.exe /c "echo benign-1727 > fcout.txt"`, false},
		{"benign unquoted", `cmd.exe /c echo benign-1727 > fcout.txt`, false},
		{"benign quoted list", `cmd.exe /c "echo hello > x.txt && type x.txt"`, false},
		{"benign dir", `cmd.exe /c dir /b`, false},
		{"marker as a file name only", `cmd.exe /c "type notes.txt" > fc-block-marker-notes.txt`, false},
	} {
		for _, tool := range []string{"Bash", "PowerShell", "shell_command", "exec_command"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			if tool == "exec_command" {
				args, _ = json.Marshal(map[string]string{"cmd": tc.command})
			}
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\proj`, ActiveHome: home}
			input.DialectHint = selectWindowsShellDialect(tool, tc.command, input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: "codex", EnforcementCapable: true,
			})
			match := findingWithID(findings, ruleID)
			blocked := match != nil && match.contributesToEnforcement() &&
				buildVerdict(findings, "tool_call").Action == "block"
			if blocked != tc.block {
				t.Errorf("%s %s (%q, hint %q): blocked=%v, want %v (%v)",
					tc.name, tool, tc.command, input.DialectHint, blocked, tc.block, FindingStrings(findings))
			}
		}
	}
}
