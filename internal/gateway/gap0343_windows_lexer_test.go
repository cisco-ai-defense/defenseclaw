// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A short PowerShell call with a balanced value has room under the statement
// budget, so the destructive tail must be judged on both connectors, both
// per-user and behind a managed hook peer (rel-1-0-6:GAP-0343).
func TestGAP0343PowerShellTailAfterBalancedValue(t *testing.T) {
	const home = `C:\Users\Alice`
	for _, tc := range []struct {
		name, prefix string
	}{
		{"subexpression", `$x = $(Get-Date); `},
		{"array", `$a = @(1, 2); `},
		{"hashtable", `$h = @{ a = 1; b = 2 }; `},
		{"braced variable", `${x} = 1; `},
		{"here-string", "$t = @'\nRemove-Item -Recurse -Force C:\\decoy\n'@\n"},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				t.Run(tc.name+"/"+connector+map[bool]string{false: "/per-user", true: "/managed"}[managed], func(t *testing.T) {
					ctx := context.Background()
					if managed {
						ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
					}
					tool := "PowerShell"
					if connector == "codex" {
						tool = "exec_command"
					}
					judge := func(command string) []RuleFinding {
						resolved := map[string]string(nil)
						if managed {
							const state = `C:/Users/Alice/.defenseclaw/config.yaml`
							resolved = map[string]string{state: state}
						}
						return dispatchTrustedAction(ctx, trustedActionRequest{
							Input: actionfacts.Input{Tool: tool, Command: command, CWD: home + `\project`, ActiveHome: home,
								DialectHint: actionfacts.DialectPowerShell},
							Connector: connector, EnforcementCapable: true, ResolvedWriteTargets: resolved,
						})
					}
					for _, tail := range []struct{ command, finding string }{
						{`Remove-Item -Recurse -Force C:\`, "CMD-RM-RF"},
						{`Clear-Content $HOME\.defenseclaw\config.yaml`, "tamper.detector_state_write"},
					} {
						findings := judge(tc.prefix + tail.command)
						if findingWithID(findings, tail.finding) == nil ||
							buildVerdict(findings, "tool_call").Action != guardrailActionBlock {
							t.Fatalf("tail %q: findings %v, want blocking %s", tail.command, findingIDs(findings), tail.finding)
						}
					}
					if tc.name == "subexpression" {
						// The reproducer is below the 128-statement cap. A block
						// here must name the destructive tail, not the budget.
						long := tc.prefix + strings.Repeat("Write-Output ok; ", 100)
						findings := judge(long + `Remove-Item -Recurse -Force C:\`)
						if findingWithID(findings, "CMD-RM-RF") == nil ||
							findingWithID(findings, "ACTION-COMPOUND-LIMIT") != nil {
							t.Fatalf("100 benign statements and destructive tail: findings %v", findingIDs(findings))
						}
						if got := buildVerdict(judge(long+"Write-Output done"), "tool_call").Action; got == guardrailActionBlock {
							t.Fatal("balanced 100-statement benign script was blocked")
						}
					}
					if got := buildVerdict(judge(tc.prefix+"Write-Output done"), "tool_call").Action; got == guardrailActionBlock {
						t.Fatal("balanced benign script was blocked")
					}
				})
			}
		}
	}
}
