// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2408: reading the NUL device made the Windows facts partial, so `type
// nul > %USERPROFILE%\.defenseclaw\config.yaml` (cmd truncates the state
// file) was ALLOW in action mode while `echo x >` the same file blocked.
func TestWindowsTypeNulRedirectToActiveStateBlocks(t *testing.T) {
	const connectorName = "gap2408-windows"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	cwd := home + `\proj`
	rows := []struct {
		command string
		dialect actionfacts.Dialect
		block   bool
	}{
		{`type nul > %USERPROFILE%\.defenseclaw\config.yaml`, actionfacts.DialectCMD, true},
		{`type nul >> %USERPROFILE%\.defenseclaw\config.yaml`, actionfacts.DialectCMD, true},
		{`type NUL > %USERPROFILE%\.defenseclaw\config.yaml`, actionfacts.DialectCMD, true},
		{`type nul: > %USERPROFILE%\.defenseclaw\config.yaml`, actionfacts.DialectCMD, true},
		{`type nul > C:\Users\Alice\.defenseclaw\config.yaml`, actionfacts.DialectCMD, true},
		{`type nul > C:\Users\Alice\.defenseclaw\config.yaml`, actionfacts.DialectPowerShell, true},
		{`type a.txt & type nul > %USERPROFILE%\.defenseclaw\config.yaml`, actionfacts.DialectCMD, true},
		{`type nul > notes.txt`, actionfacts.DialectCMD, false},
		{`type nul > %USERPROFILE%\proj\empty.txt`, actionfacts.DialectCMD, false},
		{`type nul`, actionfacts.DialectCMD, false},
		{`type README.md`, actionfacts.DialectCMD, false},
		{`copy nul notes.txt`, actionfacts.DialectCMD, false},
	}
	for _, row := range rows {
		input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: row.dialect}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connectorName, EnforcementCapable: true})
		verdict := buildVerdict(findings, "tool_call")
		if got := verdict.Action == "block"; got != row.block {
			t.Errorf("%s %q: action=%q want block=%v", row.dialect, row.command, verdict.Action, row.block)
		}
	}
}
