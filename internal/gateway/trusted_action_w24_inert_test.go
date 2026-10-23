// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A definition that this action never runs adds no finding: an exported
// Bash function no later command can run, and a PowerShell scriptblock
// literal that is not invoked. The same body still blocks once it can run.
func TestTrustedActionW24InertDefinitionsDoNotBlock(t *testing.T) {
	const connector = "w24-inert-test"
	installDefaultProfileConnector(t, connector)
	for _, tt := range []struct {
		name, command string
		dialect       actionfacts.Dialect
		block         bool
	}{
		{"exported function never run", "f() { rm -rf /; }; export -f f", actionfacts.DialectPOSIX, false},
		{"declared export then builtin", "f() { rm -rf /; }; declare -fx f; echo done", actionfacts.DialectPOSIX, false},
		{"typeset export then utility", "f() { rm -rf /; }; typeset -fx f; ls -la", actionfacts.DialectPOSIX, false},
		{"child shell before export", "f() { rm -rf /; }; bash -c f; export -f f", actionfacts.DialectPOSIX, false},
		{"exported function in child shell", "f() { rm -rf /; }; export -f f; bash -c f", actionfacts.DialectPOSIX, true},
		{"exported function through xargs", "f() { rm -rf /; }; export -f f; printf x | xargs bash -c f", actionfacts.DialectPOSIX, true},
		{"exported function in script", "f() { rm -rf /; }; export -f f; ./run.sh", actionfacts.DialectPOSIX, true},
		{"exported function redefined", "f() { echo ok; }; export -f f; f() { rm -rf /; }; bash -c f", actionfacts.DialectPOSIX, true},
		{"bare scriptblock", `{ Remove-Item -Recurse -Force C:\ }`, actionfacts.DialectPowerShell, false},
		{"bare scriptblock then statement", `{ Remove-Item -Recurse -Force C:\ }; Write-Output a`, actionfacts.DialectPowerShell, false},
		{"statement then bare scriptblock", `Write-Output a; { Remove-Item -Recurse -Force C:\ }`, actionfacts.DialectPowerShell, false},
		{"bare scriptblock in invoked block", `& { { Remove-Item -Recurse -Force C:\ } }`, actionfacts.DialectPowerShell, false},
		{"invoked scriptblock", `& { Remove-Item -Recurse -Force C:\ }`, actionfacts.DialectPowerShell, true},
		{"scriptblock piped to a consumer", `{ Remove-Item -Recurse -Force C:\ } | ForEach-Object Invoke`, actionfacts.DialectPowerShell, true},
		{"exported name as data", "f() { rm -rf /; }; export -f f; ls f", actionfacts.DialectPOSIX, false},
		{"child shell calls nothing", "f() { rm -rf /; }; export -f f; bash -c 'echo ok'", actionfacts.DialectPOSIX, false},
		{"child shell calls the function", "f() { rm -rf /; }; export -f f; bash -c 'echo ok; f'", actionfacts.DialectPOSIX, true},
		{"command skips the function", "f() { rm -rf /; }; command f", actionfacts.DialectPOSIX, false},
		{"builtin skips the function", "f() { rm -rf /; }; builtin f", actionfacts.DialectPOSIX, false},
		{"command eval calls the function", "f() { rm -rf /; }; command eval f", actionfacts.DialectPOSIX, true},
		{"subshell definition", "( f() { rm -rf /; }; ); f", actionfacts.DialectPOSIX, false},
		{"call inside the subshell", "( f() { rm -rf /; }; f )", actionfacts.DialectPOSIX, true},
		{"scriptblock to Out-Null", `{ Remove-Item -Recurse -Force C:\ } | Out-Null`, actionfacts.DialectPowerShell, false},
		{"scriptblock to a consumer alias", `{ Remove-Item -Recurse -Force C:\ } | % Invoke`, actionfacts.DialectPowerShell, true},
		{"if block", `if ($true) { Write-Output a }`, actionfacts.DialectPowerShell, false},
		{"bare scriptblock in if body", `if ($true) { { Remove-Item -Recurse -Force C:\ } }`, actionfacts.DialectPowerShell, false},
		{"if body runs", `if ($true) { Remove-Item -Recurse -Force C:\ }`, actionfacts.DialectPowerShell, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cwd, home := "/repo", "/home/alice"
			if tt.dialect == actionfacts.DialectPowerShell {
				cwd, home = `C:\repo`, `C:\Users\alice`
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{Tool: "shell", Command: tt.command, CWD: cwd,
					ActiveHome: home, DialectHint: tt.dialect},
				LegacyText: tt.command, Connector: connector, EnforcementCapable: true,
			})
			blocked := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
			if blocked != tt.block {
				t.Errorf("blocked=%v, want %v: %v", blocked, tt.block, FindingStrings(findings))
			}
			finding := findingWithID(findings, "CMD-RM-RF")
			enforced := finding != nil && finding.contributesToEnforcement()
			if enforced != tt.block {
				t.Errorf("CMD-RM-RF enforced=%v, want %v: %v", enforced, tt.block, FindingStrings(findings))
			}
		})
	}
}
