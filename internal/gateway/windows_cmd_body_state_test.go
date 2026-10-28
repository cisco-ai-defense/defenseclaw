// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2408 (live route): Claude Code's Bash tool and PowerShell pass the
// quoted body of cmd /c "<body>" to cmd, which expands %USERPROFILE% and
// opens the redirect target. The outer reading had no facts for the body,
// so a state write through cmd /c was ALLOW in every dialect.
func TestWindowsCMDBodyRedirectToActiveStateBlocks(t *testing.T) {
	const connectorName = "gap2408-cmd-body"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	cwd := home + `\proj`
	state := "C:/Users/Alice/.defenseclaw/config.yaml"
	// The hook client's resolved target map, as a native Windows hook sends
	// it; this host cannot open a Windows path.
	hook := "C:/Users/Alice/.defenseclaw/hooks/x.cmd"
	resolved := map[string]string{state: state, hook: hook}
	rows := []struct {
		command string
		block   bool
	}{
		{`cmd /c "type nul > %USERPROFILE%\.defenseclaw\config.yaml"`, true},
		{`cmd /d /c "type nul > %USERPROFILE%\.defenseclaw\config.yaml"`, true},
		{`cmd.exe /c "type nul >> %USERPROFILE%\.defenseclaw\config.yaml"`, true},
		{`cmd /c "echo x > %USERPROFILE%\.defenseclaw\config.yaml"`, true},
		{`cmd /c "echo x > C:\Users\Alice\.defenseclaw\config.yaml"`, true},
		{`cmd /c "type a.txt & type nul > %USERPROFILE%\.defenseclaw\config.yaml"`, true},
		// Git Bash spells cmd's switches //d and //c.
		{`cmd //c "type nul > %USERPROFILE%\.defenseclaw\hooks\x.cmd"`, true},
		{`cmd //d //c "echo x > %USERPROFILE%\.defenseclaw\config.yaml"`, true},
		{`cmd //c "type nul > notes.txt"`, false},
		{`cmd /c "type nul > notes.txt"`, false},
		{`cmd /c "type a.txt"`, false},
		{`cmd /c "type nul > %USERPROFILE%\proj\empty.txt"`, false},
		{`cmd /c "echo %USERPROFILE%\.defenseclaw\config.yaml"`, false},
	}
	for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX, actionfacts.DialectPowerShell, actionfacts.DialectCMD} {
		for _, row := range rows {
			input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: dialect}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connectorName, EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			verdict := buildVerdict(findings, "tool_call")
			if got := verdict.Action == "block"; got != row.block {
				t.Errorf("%q %q: action=%q want block=%v", dialect, row.command, verdict.Action, row.block)
			}
		}
	}
}
