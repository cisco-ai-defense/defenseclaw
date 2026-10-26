// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1872 / GAP-1741 (GAP-0781 class): a call that runs or looks up
// apply_patch with no readable envelope is not the SSH rule unless it names
// a protected target (TGT-0194). Windows home, Codex exec_command and Copilot
// powershell, action mode. The commands are the GAP-1872 live calls; the
// native Windows run of this test (dcw-preflight) is the decisive one.
func TestR105PatchLookupWithoutEnvelopeIsNotSSHPersistence(t *testing.T) {
	home := `C:\Users\u`
	cases := []struct {
		connector, tool, command string
		want                     bool
	}{
		{"codex", "exec_command", "Get-Command apply_patch | Format-List *; apply_patch --help", false},
		{"copilot", "powershell", "Get-Command apply_patch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source", false},
		{"codex", "exec_command", "apply_patch (Get-Content patch.txt -Raw)", false},
		{"codex", "exec_command", "bash -lc \"apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: calc.py\n@@\n def divide(first, second):\n     return first / second\n+\n+def power(base, exponent):\n+    return base ** exponent\n*** End Patch\nPATCH\"", false},
		// GAP-1919: an @"..."@ envelope with $ and a backtick to a project file.
		{"copilot", "powershell", "apply_patch @\"\n*** Begin Patch\n*** Add File: C:\\Users\\u\\proj\\notes.txt\n+$x = 1\n+`done\n*** End Patch\n\"@", false},
		{"codex", "exec_command", "Set-Content ~\\.ssh\\authorized_keys k; apply_patch --help", true},
	}
	for _, tc := range cases {
		t.Run(tc.connector+"/"+tc.command, func(t *testing.T) {
			key := "command"
			if tc.tool == "exec_command" {
				key = "cmd"
			}
			args, _ := json.Marshal(map[string]string{key: tc.command})
			input := actionfacts.Input{Tool: tc.tool, Args: args, CWD: home + `\proj`, ActiveHome: home,
				DialectHint: actionfacts.DialectPowerShell}
			findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: tc.connector, EnforcementCapable: true,
			})
			got := false
			for _, finding := range findings {
				if finding.RuleID == "persistence.ssh_authorized_keys_command" && finding.contributesToEnforcement() {
					got = true
				}
			}
			if got != tc.want {
				t.Fatalf("SSH rule = %t, want %t: %v", got, tc.want, findingIDs(findings))
			}
		})
	}
}
