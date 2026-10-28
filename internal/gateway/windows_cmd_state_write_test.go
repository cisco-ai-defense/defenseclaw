// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestR105WindowsCMDStateWriteThroughNul: a cmd redirect, copy or rename
// whose target is DefenseClaw state is tamper.detector_state_write in action
// mode whatever the source is. type nul > state truncates it, copy nul state
// empties it, ren state x removes it (GAP-2408); the null device read made
// the command partial and %USERPROFILE% lost the target.
func TestR105WindowsCMDStateWriteThroughNul(t *testing.T) {
	const connectorName = "r105-cmd-state"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`type nul > %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`type nul > C:\Users\Alice\.defenseclaw\config.yaml`, true},
		{`type nul >> %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`type nul 1> %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`type nul 2> %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`type NUL > "%USERPROFILE%\.defenseclaw\config.yaml"`, true},
		{`type a.txt & type nul > %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`copy nul %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`copy /y nul C:\Users\Alice\.defenseclaw\config.yaml`, true},
		{`ren %USERPROFILE%\.defenseclaw\config.yaml config.bak`, true},
		{`rename C:\Users\Alice\.defenseclaw\policies\default.yaml x.yaml`, true},
		{`ren notes.txt n.bak & type nul > %USERPROFILE%\.defenseclaw\.env`, true},
		{`echo x > %USERPROFILE%\.defenseclaw\config.yaml`, true},
		// Ordinary work stays allowed.
		{`type nul > notes.txt`, false},
		{`type nul > %USERPROFILE%\project\out.txt`, false},
		{`copy nul %USERPROFILE%\project\empty.txt`, false},
		{`type %USERPROFILE%\.defenseclaw\config.yaml`, false},
		{`ren notes.txt notes.bak`, false},
		{`ren %USERPROFILE%\project\a.txt b.txt`, false},
		{`type nul`, false},
		{`echo x > nul`, false},
		{`type a.txt 2>nul`, false},
		{`copy nul NUL`, false},
		{`type nul > %USERPROFILE%\.defenseclaw-notes.txt`, false},
	} {
		args, _ := json.Marshal(map[string]string{"command": tc.command})
		input := actionfacts.Input{
			Tool: "Bash", Args: args, CWD: home + `\project`, ActiveHome: home,
			DialectHint: actionfacts.DialectCMD,
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: string(args), Connector: connectorName, EnforcementCapable: true,
		})
		verdict := buildVerdict(findings, "tool_call")
		if got := verdict.Action == "block"; got != tc.block {
			t.Errorf("%s: action %q, want block=%t (findings %v)", tc.command, verdict.Action, tc.block, findings)
		}
		if tc.block && !slices.ContainsFunc(findings, func(f RuleFinding) bool {
			return f.RuleID == "tamper.detector_state_write"
		}) {
			t.Errorf("%s: no tamper.detector_state_write finding: %v", tc.command, findings)
		}
	}
}
