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
	}{
		{nest(20, read), false},
		{nest(40, read), false},
		{nest(2, cmdWrite), true},
		{nest(40, cmdWrite), true},
		{nest(400, cmdWrite), true},
	} {
		for _, tool := range []string{"Bash", "shell_command", "PowerShell"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect("", input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			if got := buildVerdict(findings, "tool_call").Action == "block"; got != tc.block {
				t.Errorf("%s %d bytes %q...: block=%t, want %t (%v)", tool, len(tc.command),
					tc.command[:min(len(tc.command), 40)], got, tc.block, FindingStrings(findings))
			}
		}
	}
}
