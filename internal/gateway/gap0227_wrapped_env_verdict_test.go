// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0227WrappedEnvVerdict(t *testing.T) {
	const home = `C:\Users\review`
	rows := []struct {
		name, command, want string
	}{
		{"separator assignment", "echo 'cp a.txt .ssh/authorized_k*' | env -- X=1 bash", "block"},
		{"split string", "echo 'cp a.txt .ssh/authorized_k*' | env -S 'bash -s'", "block"},
		{"split string equals", "echo 'cp a.txt .ssh/authorized_k*' | env --split-string='bash -s'", "block"},
		{"ordinary script", "echo 'git status' | env -- X=1 bash", "allow"},
	}
	for _, row := range rows {
		for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell} {
			for _, connector := range []string{"claudecode", "codex"} {
				args, err := json.Marshal(map[string]string{"command": row.command})
				if err != nil {
					t.Fatal(err)
				}
				input := actionfacts.Input{Tool: "Bash", DialectHint: dialect, Command: row.command, Args: args,
					CWD: home, ActiveHome: home}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true,
				})
				if got := buildVerdict(findings, "tool_call").Action; got != row.want {
					t.Errorf("%s dialect=%q connector=%s: %s, want %s", row.name, dialect, connector, got, row.want)
				}
			}
		}
	}
}
