// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP1073HereStringDisplayVerdict holds the neighbours of
// TestGAP0236ExplicitDisplayExecutableVerdict/here-string_mixed_case
// (rel-1-0-10:GAP-1073): a PowerShell here-string whose body is a keys
// pattern, printed to a named display, is text in every case and spelling
// of the print, the display and the pattern, as on rel 4269debe92. The opaque
// scan of an unknown program word (rel-1-0-10:GAP-0991) read the pattern as a
// target and blocked it on Windows. A later consumer, an explicit display
// path, a rebound display or a writer that takes the text still blocks.
func TestGAP1073HereStringDisplayVerdict(t *testing.T) {
	const home = `C:\Users\review`
	for _, row := range []struct {
		name, command, want string
	}{
		{"lower case display", "Write-Output @'\n.ssh/authorized_k*\n'@ | cat -n", "allow"},
		{"upper case display", "Write-Output @'\n.ssh/authorized_k*\n'@ | CAT -n", "allow"},
		{"mixed case display no option", "Write-Output @'\n.ssh/authorized_k*\n'@ | CaT", "allow"},
		{"question mark pattern", "Write-Output @'\n.ssh/authorized_key?\n'@ | CaT -n", "allow"},
		{"bracket pattern", "Write-Output @'\n.ssh/authorized_k[e]ys\n'@ | CaT -n", "allow"},
		{"expandable here-string", "Write-Output @\"\n.ssh/authorized_k*\n\"@ | CaT -n", "allow"},
		{"lower case print", "write-output @'\n.ssh/authorized_k*\n'@ | CaT -n", "allow"},
		{"home pattern", "Write-Output @'\n~/.ssh/authorized_k*\n'@ | CaT -n", "allow"},
		{"after a read", "Get-Date; Write-Output @'\n.ssh/authorized_k*\n'@ | CaT -n", "allow"},
		{"later shell", "Write-Output @'\n.ssh/authorized_k*\n'@ | CaT -n | sh", "block"},
		{"explicit display path", "Write-Output @'\n.ssh/authorized_k*\n'@ | ./cat -n", "block"},
		{"rebound display", "Set-Alias cat Invoke-Expression -Force; Write-Output @'\n.ssh/authorized_k*\n'@ | CaT", "block"},
		{"path consumer", "Write-Output @'\n.ssh/authorized_k*\n'@ | ForEach-Object { Add-Content -Path $_ -Value k }", "block"},
		{"pattern writer", "@'\nssh-ed25519 AAAA\n'@ | Add-Content -Path '.ssh/authorized_k*'", "block"},
	} {
		for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell} {
			for _, connector := range []string{"claudecode", "codex"} {
				t.Run(row.name+"/"+string(dialect)+"/"+connector, func(t *testing.T) {
					args, err := json.Marshal(map[string]string{"command": row.command})
					if err != nil {
						t.Fatal(err)
					}
					input := actionfacts.Input{Tool: "Bash", DialectHint: dialect, Command: row.command,
						Args: args, CWD: home, ActiveHome: home}
					findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
						Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true,
					})
					if got := buildVerdict(findings, "tool_call").Action; got != row.want {
						t.Fatalf("verdict = %s, want %s", got, row.want)
					}
				})
			}
		}
	}
}
