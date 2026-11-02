// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// PowerShell 7 ParseInput reads the tail in every executable row as a command.
func TestGAP0451PowerShellValueFrameCommentBoundaries(t *testing.T) {
	testPowerShellValueFrameCommentBoundaries(t, true)
}

// ParseInput reads the tail of these forms as comment text, so none may block.
func TestGAP0452PowerShellCommentedTailsStayInert(t *testing.T) {
	testPowerShellValueFrameCommentBoundaries(t, false)
}

func testPowerShellValueFrameCommentBoundaries(t *testing.T, executable bool) {
	const home = `C:\Users\Alice`
	const state = `C:\Users\Alice\.defenseclaw\config.yaml`
	rows := []struct {
		name, prefix string
		executable   bool
	}{
		{"subexpression path", `Write-Output $(.\a[1]#); `, true},
		{"subexpression glued double quote", `Write-Output $(a"b"#); `, true},
		{"array glued double quote", `Write-Output @(a"b"#); `, true},
		{"assignment subexpression", `$x = $(a"b"#); `, true},
		{"paren glued double quote", `Write-Output (a"b"#); `, true},
		{"paren path", `(.\a[1]#); `, true},
		{"subexpression command", `Write-Output $(Write-Output a"b"#); `, true},
		{"call subexpression", `& $(a"b"#); `, true},
		{"interpolated subexpression", `Write-Output "$(a"b"#)"; `, true},
		{"subexpression glued single quote", `Write-Output $(a'b'#); `, true},
		{"subexpression block marker", `Write-Output $(.\a[1]<#x#>); `, true},
		{"scriptblock path", `& {.\a[1]#}; `, true},
		{"subexpression type comment", "Write-Output $([int]#\n); ", true},
		{"type expression comment", `[int]#; `, false},
		{"single quoted comment", `Write-Output 'a'#; `, false},
		{"double quoted comment", `"a"#; `, false},
	}
	for _, frame := range []struct{ name, prefix string }{
		{"subexpression", `Write-Output $(`},
		{"array", `Write-Output @(`},
		{"parenthesized", `Write-Output (`},
	} {
		for _, word := range []string{"/a", "-a", "*a", "%a", "!a", "?a", "=a", "1a", "0x1"} {
			rows = append(rows, struct {
				name, prefix string
				executable   bool
			}{frame.name + " " + word, frame.prefix + word + `"b"#); `, true})
		}
	}
	tails := []struct{ name, command string }{
		{"rm-rf", `Remove-Item -Recurse -Force C:\`},
		{"rm-rf order", `Remove-Item C:\ -Force -Recurse`},
		{"clear state", `Clear-Content $HOME\.defenseclaw\config.yaml`},
		{"set state", `Set-Content -Path ` + state + ` -Value x`},
		{"redirect state", `'x' > ` + state},
		{"rm state dir", `Remove-Item -Recurse -Force $HOME\.defenseclaw`},
	}
	judge := func(connector string, managed bool, command string) ([]RuleFinding, string) {
		ctx := context.Background()
		if managed {
			ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
		}
		tool := "PowerShell"
		if connector == "codex" {
			tool = "exec_command"
		}
		var resolved map[string]string
		if managed {
			resolved = map[string]string{state: state}
		}
		findings := dispatchTrustedAction(ctx, trustedActionRequest{
			Input: actionfacts.Input{Tool: tool, Command: command, CWD: home + `\project`,
				ActiveHome: home, DialectHint: actionfacts.DialectPowerShell},
			Connector: connector, EnforcementCapable: true, ResolvedWriteTargets: resolved,
		})
		return findings, buildVerdict(findings, "tool_call").Action
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, tail := range tails {
				_, tailAction := judge(connector, managed, tail.command)
				for _, row := range rows {
					if row.executable != executable {
						continue
					}
					t.Run(row.name+"/"+connector+"/"+tail.name+map[bool]string{false: "/per-user", true: "/managed"}[managed], func(t *testing.T) {
						findings, action := judge(connector, managed, row.prefix+tail.command)
						want := tailAction
						if !row.executable {
							want = guardrailActionAllow
						}
						if action != want {
							t.Fatalf("action=%s findings=%v, want %s", action, findingIDs(findings), want)
						}
						if row.executable && tail.name == "rm-rf" && findingWithID(findings, "CMD-RM-RF") == nil {
							t.Fatalf("destructive command missing: %v", findingIDs(findings))
						}
					})
				}
			}
		}
	}
}
