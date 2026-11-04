// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0236ExplicitDisplayExecutableVerdict(t *testing.T) {
	const home = `C:\Users\review`
	for _, row := range []struct {
		name, command, want string
	}{
		{"absolute", "echo 'cp a.txt .ssh/authorized_k*' | /tmp/cat -n", "block"},
		{"relative", "echo 'cp a.txt .ssh/authorized_k*' | ./cat -n", "block"},
		{"named display", "echo 'cp a.txt .ssh/authorized_k*' | cat -n", "allow"},
		{"named display mixed case", "echo 'cp a.txt .ssh/authorized_k*' | CaT -n", "allow"},
		{"here-string mixed case", "Write-Output @'\n.ssh/authorized_k*\n'@ | CaT -n", "allow"},
		{"named display after read", "Get-Date; echo 'cp a.txt .ssh/authorized_k*' | cat -n", "allow"},
		{"named wrapped display", "echo 'cp a.txt .ssh/authorized_k*' | env -S 'cat -n'", "allow"},
		{"explicit wrapped executable", "echo 'cp a.txt .ssh/authorized_k*' | ./env -S 'cat -n'", "block"},
		{"later consumer", "echo 'cp a.txt .ssh/authorized_k*' | cat -n | sh", "block"},
		{"mixed case later consumer", "echo 'cp a.txt .ssh/authorized_k*' | CaT -n | sh", "block"},
		{"rebound display", "Set-Alias cat Invoke-Expression -Force; echo 'cp a.txt .ssh/authorized_k*' | cat", "block"},
		{"mixed case rebound display", "Set-Alias cat Invoke-Expression -Force; echo 'cp a.txt .ssh/authorized_k*' | CaT", "block"},
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
