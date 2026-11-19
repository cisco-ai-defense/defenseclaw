// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The cmd body reader bounds its nested reading and counts a command past
// the bounds as the state write it may hide (RV10-3). A command that no
// reading can make name cmd.exe has nothing for it to find: since
// 7470f896d8 a deeply nested double-quoted $(...) state READ with no cmd in
// it (driven row rows17 B08, ALLOW at a2a0574ca4) went past the depth bound
// and was blocked as tamper.detector_state_write.
func TestR105WindowsCMDReaderSkipsCommandsWithoutCMD(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{`cmd /c dir`, true},
		{`C:\Windows\System32\CMD.EXE /c dir`, true},
		{`c^md /c dir`, true},
		{"c`md /c dir", true},
		{`"c"md /c dir`, true},
		{"c\\md //c dir", true},
		{"c^\r\nmd /c dir", true},
		{`& $env:ComSpec /c dir`, true},
		{`%COMSPEC% /c dir`, true},
		{"c\u2019md /c dir", true},
		{`Get-Content $HOME\.defenseclaw\config.yaml`, false},
		{`Write-Output "$("$(Get-Content x)")"`, false},
	} {
		if got := cmdSpellingPossible(tc.command); got != tc.want {
			t.Errorf("cmdSpellingPossible(%q) = %t, want %t", tc.command, got, tc.want)
		}
	}

	const connectorName = "r105-cmd-reader-scope"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml"} {
		resolved[value] = value
	}
	nest := func(n int, body string) string {
		return strings.Repeat(`"$(`, n) + body + strings.Repeat(`)"`, n)
	}
	const read = `Get-Content $HOME\.defenseclaw\config.yaml`
	const cmdWrite = `cmd /c type nul > %USERPROFILE%\.defenseclaw\config.yaml`
	for _, tc := range []struct {
		command string
		block   bool
		// rules: per tool, the rules the call blocks for (past the compound
		// limit beside the state write), not as the HIGH state write alert
		// (GAP-1563); a tool without an entry is the HIGH alert.
		rules map[string][]string
	}{
		{nest(20, read), false, nil},
		{nest(40, read), false, nil},
		{nest(2, cmdWrite), true, nil},
		{nest(40, cmdWrite), true, map[string][]string{
			"Bash":          {gap0747StateRule, gap0747CompoundLimitRule},
			"shell_command": {gap0747StateRule, gap0747CompoundLimitRule},
		}},
		{nest(400, cmdWrite), true, map[string][]string{
			"Bash":          {gap0747StateRule, gap0747CompoundLimitRule},
			"shell_command": {gap0747StateRule, gap0747CompoundLimitRule},
			"PowerShell":    {gap0747StateRule, gap0747CompoundLimitRule},
		}},
	} {
		for _, tool := range []string{"Bash", "shell_command", "PowerShell"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			// A proven state write is a HIGH alert on the default pack (GAP-0747
			// owner tiering 2026-11-15T15:20Z).
			got := gap0747DefaultTierCheck(findings, true) == ""
			if rules, ok := tc.rules[tool]; ok {
				got = gap0747BlockedForRule(findings, rules...) == ""
			}
			if !tc.block {
				// Past the action analysis depth bound a call is the unknown
				// tier of the pack whatever it names (rel-1-0-10:GAP-0688, the
				// one bound rule): an alert in this default pack. Only a proven
				// finding may block it; the CMD reader adds none.
				got = operandBoundTierAction(findings, false) == guardrailActionBlock
			}
			if got != tc.block {
				t.Errorf("%s %d bytes %q...: block=%t, want %t (%v)", tool, len(tc.command),
					tc.command[:min(len(tc.command), 40)], got, tc.block, FindingStrings(findings))
			}
		}
	}
}
