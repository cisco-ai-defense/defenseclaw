// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP0750PowerShellHereStringWriteOfTheDefenseClawConfig: Set-Content,
// Add-Content and Out-File write the file they are given whatever the value
// is, so a value PowerShell reads at run time (a here-string, a variable)
// does not make the write of the DefenseClaw config an unproven one. It was
// allowed in every pack, strict included, while the same write with a quoted
// string, Add-Content or a piped string blocked as a proven mutation of the
// active state (rel-1-0-10:GAP-0750). A proven write of the state follows the
// tamper rule, one enforcement level in every pack, not the unknown tier.
//
// The managed rows give the target through the hook client's map, as the
// managed gateway has it. A per-user gateway resolves the Windows path on the
// host that holds it: those rows run on Windows only.
func TestGAP0750PowerShellHereStringWriteOfTheDefenseClawConfig(t *testing.T) {
	const home = `C:\Users\Alice`
	const state = `C:\Users\Alice\.defenseclaw\config.yaml`
	const body = "setting:\n  enabled: false\n"
	double := "@\"\n" + body + "\"@"
	single := "@'\n" + body + "'@"
	rows := []struct {
		name, command string
		block         bool
	}{
		{"quoted string", `Set-Content -Path ` + state + ` -Value "x"`, true},
		{"double here-string", `Set-Content -Path ` + state + ` -Value ` + double, true},
		{"single here-string", `Set-Content -Path ` + state + ` -Value ` + single, true},
		{"positional value", `Set-Content ` + state + ` ` + double, true},
		{"value first", `Set-Content -Value ` + double + ` -Path ` + state, true},
		{"literal path", `Set-Content -LiteralPath ` + state + ` -Value ` + double, true},
		{"add content", `Add-Content -Path ` + state + ` -Value ` + double, true},
		{"piped here-string", double + ` | Out-File ` + state, true},
		{"here-string in a variable", `$c = ` + double + "\nSet-Content -Path " + state + ` -Value $c`, true},
		{"variable value", `Set-Content -Path ` + state + ` -Value $c`, true},
		{"CRLF line ends", `Set-Content -Path ` + state + " -Value @\"\r\n" + body + "\"@", true},
		{"between other statements", "Write-Output start\nSet-Content -Path " + state + ` -Value ` + single + "\nWrite-Output done", true},
		// The benign twins: a here-string written to an ordinary file, the
		// state path only in the text, a print and a read of the state.
		{"ordinary file", `Set-Content -Path C:\Users\Alice\project\notes.txt -Value ` + double, false},
		{"state path in the value", `Set-Content -Path C:\Users\Alice\project\notes.txt -Value @'` + "\n" + state + "\n'@", false},
		{"print", `Write-Output ` + double, false},
		{"read of the state", `Get-Content -Path ` + state, false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{true, false} {
			for _, row := range rows {
				name := connector + "/" + row.name
				if managed {
					name += "/managed"
				} else {
					name += "/per-user"
				}
				t.Run(name, func(t *testing.T) {
					ctx := context.Background()
					var resolved map[string]string
					if managed {
						ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
						resolved = map[string]string{state: state}
					} else if row.block && runtime.GOOS != "windows" {
						t.Skip("a per-user gateway resolves the Windows path on its own host")
					}
					tool := "PowerShell"
					if connector == "codex" {
						tool = "exec_command"
					}
					findings := dispatchTrustedAction(ctx, trustedActionRequest{
						Input: actionfacts.Input{Tool: tool, Command: row.command, CWD: home + `\project`,
							ActiveHome: home, DialectHint: actionfacts.DialectPowerShell},
						Connector: connector, EnforcementCapable: true, ResolvedWriteTargets: resolved,
					})
					action := buildVerdict(findings, "tool_call").Action
					want := guardrailActionAllow
					if row.block {
						// A proven state write alerts (HIGH) outside strict.
						want = guardrailActionAlert
					}
					if action != want || (row.block && (findingWithID(findings, "tamper.detector_state_write") == nil || gap0747DefaultTierCheck(findings, true) != "")) {
						t.Fatalf("action=%s findings=%v, want %s (tamper.detector_state_write: %t)", action, findingIDs(findings), want, row.block)
					}
				})
			}
		}
	}
}
