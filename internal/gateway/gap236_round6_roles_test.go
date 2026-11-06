// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func gap236Round6Action(t *testing.T, command, cwd, home, connector string, dialect actionfacts.Dialect) string {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "Bash", Args: args, Command: command, CWD: cwd,
		ActiveHome: home, DialectHint: dialect}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true,
	})
	return buildVerdict(findings, "tool_call").Action
}

func TestGAP0548CopyItemSourceAndDestinationRoles(t *testing.T) {
	const home = `C:\Users\review`
	const cwd = home + `\project`
	for _, row := range []struct {
		name, command, want string
	}{
		{"plain source", `$t="$HOME/.ssh"; Copy-Item -Path "$t" -Destination a.txt`, "allow"},
		{"recursive source", `$t="$HOME/.ssh"; Copy-Item -Path "$t" -Destination a.txt -Recurse`, "allow"},
		{"container source", `$t="$HOME/.ssh"; Copy-Item -Path "$t" -Destination a.txt -Container:$false`, "allow"},
		{"alias source", `$t="$HOME/.ssh"; cpi -Path "$t" -Destination a.txt`, "allow"},
		{"named destination", `$t="$HOME/.ssh"; Copy-Item -Path "$t" -Destination "$HOME/.ssh/authorized_keys" -Recurse`, "block"},
		{"bound named destination", `$t="$HOME/.ssh/authorized_keys"; Copy-Item -Path a.txt -Destination "$t"`, "block"},
	} {
		for _, connector := range []string{"codex", "claudecode"} {
			t.Run(row.name+"/"+connector, func(t *testing.T) {
				tool, field := "exec_command", "cmd"
				if connector == "claudecode" {
					tool, field = "Bash", "command"
				}
				args, err := json.Marshal(map[string]string{field: row.command})
				if err != nil {
					t.Fatal(err)
				}
				input := actionfacts.Input{Tool: tool, Args: args, Command: row.command, CWD: cwd,
					ActiveHome: home, DialectHint: actionfacts.DialectPowerShell}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, Connector: connector, EnforcementCapable: true,
				})
				if got := buildVerdict(findings, "tool_call").Action; got != row.want {
					t.Fatalf("verdict = %s, want %s", got, row.want)
				}
			})
		}
	}
}

func TestGAP0236EnvDisplayAndConsumerRoles(t *testing.T) {
	const home = `C:\Users\review`
	for _, row := range []struct {
		name, command, want string
	}{
		{"split assignment display", `echo 'cp a.txt .ssh/authorized_k*' | env -S 'X=1 cat -n'`, "allow"},
		{"long split assignment display", `echo 'cp a.txt .ssh/authorized_k*' | env --split-string='X=1 cat -n'`, "allow"},
		{"separator display", `echo 'cp a.txt .ssh/authorized_k*' | env -- cat -n`, "allow"},
		{"split command consumer", `echo 'cp a.txt .ssh/authorized_k*' | env -S 'X=1 bash -s'`, "block"},
		{"long split command consumer", `echo 'cp a.txt .ssh/authorized_k*' | env --split-string='X=1 bash -s'`, "block"},
		{"explicit executable", `echo 'cp a.txt .ssh/authorized_k*' | ./env -S 'X=1 cat -n'`, "block"},
	} {
		for _, connector := range []string{"codex", "claudecode"} {
			t.Run(row.name+"/"+connector, func(t *testing.T) {
				if got := gap236Round6Action(t, row.command, home, home, connector, ""); got != row.want {
					t.Fatalf("verdict = %s, want %s", got, row.want)
				}
			})
		}
	}
}
