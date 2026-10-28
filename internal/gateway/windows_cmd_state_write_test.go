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

// TestR105WindowsCMDSlashCStateWrite: the same writes handed to cmd.exe by a
// PowerShell or Git Bash tool call as cmd /c BODY (GAP-2408 live rows S1-S7,
// S9). The gateway resolves the write target on the Windows host; the test
// supplies that map as the hook does.
func TestR105WindowsCMDSlashCStateWrite(t *testing.T) {
	const connectorName = "r105-cmd-slash-c"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, name := range []string{"config.yaml", ".env", "config.bak", `policies/default.yaml`} {
		value := "C:/Users/Alice/.defenseclaw/" + name
		resolved[value] = value
	}
	const state = `%USERPROFILE%\.defenseclaw\config.yaml`
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`cmd /c "type nul > ` + state + `"`, true},
		{`cmd /c "type nul >> ` + state + `"`, true},
		{`cmd /c copy /y nul ` + state, true},
		{`cmd /c ren ` + state + ` config.bak`, true},
		{`cmd.exe /c "type nul > C:\Users\Alice\.defenseclaw\config.yaml"`, true},
		{`cmd /c "echo x > ` + state + `"`, true},
		{`cmd /q /c "type notes.txt & type nul > ` + state + `"`, true},
		{`C:\Windows\System32\cmd.exe /c "type nul > ` + state + `"`, true},
		{`cmd /c "cmd /c type nul > ` + state + `"`, true},
		// Every way an agent hands the body to cmd.exe (checker it8 RV8-1).
		{`& cmd /c "type nul > ` + state + `"`, true},
		{`cmd /c 'type nul > ` + state + `'`, true},
		{`cmd.exe /c 'echo x > ` + state + `'`, true},
		{`cmd //c "type nul > ` + state + `"`, true},
		{`cmd //c 'type nul > ` + state + `'`, true},
		{`cmd/c "type nul > ` + state + `"`, true},
		{`cmd /v:on /c "type nul > ` + state + `"`, true},
		{`cmd /e:on /c "type nul > ` + state + `"`, true},
		{`cmd /u /c "type nul > ` + state + `"`, true},
		{`cmd /k "type nul > ` + state + `"`, true},
		{`cmd //k "echo x > ` + state + `"`, true},
		{`& $env:ComSpec /c "type nul > ` + state + `"`, true},
		{`& ${env:ComSpec} /c "type nul > ` + state + `"`, true},
		{`%ComSpec% /c "type nul > ` + state + `"`, true},
		{`Start-Process cmd -ArgumentList '/c type nul > ` + state + `' -Wait`, true},
		{`Start-Process -FilePath cmd.exe -ArgumentList "/c copy /y nul ` + state + `" -Wait`, true},
		{`"C:\Windows\System32\cmd.exe" /c "type nul > ` + state + `"`, true},
		{`Write-Output a; & cmd /c 'type nul > ` + state + `'`, true},
		// Ordinary work stays allowed.
		{`cmd /c "type nul > notes8.txt"`, false},
		{`cmd /c copy /y nul empty8.txt`, false},
		{`cmd /c ren notes8.txt notes8b.txt`, false},
		{`cmd /c type ` + state, false},
		{`cmd /c "type notes.txt 2>nul"`, false},
		{`cmd /c dir %USERPROFILE%\.defenseclaw`, false},
		{`& cmd /c "type nul > notes8.txt"`, false},
		{`cmd //c 'dir'`, false},
		{`cmd /k "echo hi"`, false},
		{`cmd /v:on /c "echo !PATH! > notes.txt"`, false},
		{`Start-Process cmd -ArgumentList '/c type nul > notes.txt' -Wait`, false},
		{`& $env:ComSpec /c "copy ` + state + ` backup.yaml"`, false},
		{`cmd /c 'type nul > %USERPROFILE%\.defenseclawx\a.txt'`, false},
		{`cmdkey /list`, false},
		{`Write-Output 'cmd /c dir'`, false},
	} {
		for _, tool := range []string{"Bash", "shell_command", "PowerShell"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			verdict := buildVerdict(findings, "tool_call")
			if got := verdict.Action == "block"; got != tc.block {
				t.Errorf("%s %s (dialect %q): action %q, want block=%t (findings %v)",
					tool, tc.command, input.DialectHint, verdict.Action, tc.block, findings)
			}
		}
	}
}
