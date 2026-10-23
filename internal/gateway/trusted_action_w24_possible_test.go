// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// W24 loop round 4 (balanced defaults). A command that may run only through
// a runtime choice (GAP-0934: x=f; $x; GAP-0935: a PowerShell body under a
// condition that is not a literal) adds an ACTION-POSSIBLE-EXECUTION finding:
// an alert with the default and permissive packs, a block with strict. The
// benign forms of the same shapes, and unset -f, are allowed in every tier.
func TestTrustedActionW24PossibleExecutionIsStrictOnly(t *testing.T) {
	const connector = "w24-possible-test"
	installDefaultProfileConnector(t, connector)
	tiers := map[string]*config.Config{}
	for _, pack := range []string{"permissive", "default", "strict"} {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.RulePack = pack
		tiers[pack] = cfg
	}
	for _, tt := range []struct {
		name, command string
		dialect       actionfacts.Dialect
		possible      bool
		strictBlocks  bool
		defaultBlocks bool
	}{
		{"GAP-0934 assigned program word", "f() { rm -rf /; }; x=f; $x", actionfacts.DialectPOSIX, true, true, false},
		{"GAP-0934 quoted assigned program word", `f() { rm -rf /; }; x=f; "$x"`, actionfacts.DialectPOSIX, true, true, false},
		{"GAP-0935 command condition", `if (Test-Path x) { Remove-Item -Recurse -Force C:\ }`, actionfacts.DialectPowerShell, true, true, false},
		{"GAP-0935 else branch", `if (Test-Path x) { Write-Output a } else { Remove-Item -Recurse -Force C:\ }`, actionfacts.DialectPowerShell, true, true, false},
		{"literal condition still blocks", `if ($true) { Remove-Item -Recurse -Force C:\ }`, actionfacts.DialectPowerShell, false, true, true},
		{"direct function call still blocks", "f() { rm -rf /; }; f", actionfacts.DialectPOSIX, false, true, true},
		{"benign assigned program word", "f() { echo ok; }; x=f; $x", actionfacts.DialectPOSIX, false, false, false},
		{"benign command condition", `if (Test-Path package.json) { npm install }`, actionfacts.DialectPowerShell, false, false, false},
		{"benign variable condition", `if ($env:CI) { npm ci } else { npm install }`, actionfacts.DialectPowerShell, false, false, false},
		{"benign negated condition", `if (-not (Test-Path out)) { New-Item -ItemType Directory out }`, actionfacts.DialectPowerShell, false, false, false},
		{"benign comparison", `$items = Get-ChildItem; if ($items.Count -gt 0) { Write-Output many }`, actionfacts.DialectPowerShell, false, false, false},
		{"unset -f then the name", "f() { rm -rf /; }; unset -f f; f", actionfacts.DialectPOSIX, false, false, false},
		{"unset then the name", "f() { rm -rf /; }; unset f; f", actionfacts.DialectPOSIX, false, false, false},
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
			finding := findingWithID(findings, possibleExecutionRuleID)
			if got := finding != nil && finding.contributesToEnforcement(); got != tt.possible {
				t.Fatalf("%s=%v, want %v: %v", possibleExecutionRuleID, got, tt.possible, FindingStrings(findings))
			}
			if finding != nil && finding.Severity != "MEDIUM" {
				t.Fatalf("%s severity %q, want MEDIUM", possibleExecutionRuleID, finding.Severity)
			}
			for pack, cfg := range tiers {
				want := pack == "strict" && tt.strictBlocks || pack != "strict" && tt.defaultBlocks
				action := guardrailActionForConnectorFindings(cfg, connector, findings, false)
				if (action == guardrailActionBlock) != want {
					t.Errorf("%s pack: action=%q, want block=%v: %v", pack, action, want, FindingStrings(findings))
				}
			}
		})
	}
}

// GAP-0992, GAP-0997: on a Windows host a call with no command text (a
// native Write, a delegation) or a literal PowerShell echo-and-sleep is not a
// protected write; a literal authorized_keys write still blocks.
func TestTrustedActionW24WindowsLiteralAndNoCommandCallsAreNotPersistence(t *testing.T) {
	const cwd, home = `C:\Users\alice\project`, `C:\Users\alice`
	for _, tt := range []struct {
		name, connector, tool, command string
		args                           map[string]string
		block                          bool
	}{
		{"GAP-0992 Codex echo and sleep", "codex", "exec_command", `Write-Output ok; Start-Sleep -Seconds 70`, nil, false},
		{"GAP-0992 Codex call carried in cmd only", "codex", "exec_command", "", map[string]string{"cmd": `Write-Output ok; Start-Sleep -Seconds 70`, "shell": "powershell"}, false},
		{"GAP-0997 native Write of an ordinary file", "claudecode", "Write", "", map[string]string{"file_path": cwd + `\node_modules\.pnpm\pkg\index.js`, "content": "changed"}, false},
		{"GAP-0997 native Edit of an ordinary file", "claudecode", "Edit", "", map[string]string{"file_path": cwd + `\src\main.go`, "old_string": "a", "new_string": "b"}, false},
		{"literal authorized_keys write", "codex", "exec_command", `Add-Content -Path '~/.ssh/authorized_keys' -Value 'dummy-key'`, nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: agentHookTrustedActionTool(tt.connector, tt.tool, "windows"),
				Command: tt.command, CWD: cwd, ActiveHome: home}
			if tt.args != nil {
				raw, err := json.Marshal(tt.args)
				if err != nil {
					t.Fatal(err)
				}
				input.Args = raw
			}
			input.DialectHint = selectWindowsShellDialect(input.Tool, input.Command, input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: tt.connector, EnforcementCapable: true,
			})
			finding := findingWithID(findings, "persistence.ssh_authorized_keys_command")
			if got := finding != nil && finding.contributesToEnforcement(); got != tt.block {
				t.Fatalf("persistence blocked=%v, want %v: %v", got, tt.block, FindingStrings(findings))
			}
		})
	}
}
