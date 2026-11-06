// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestR105CodexWindowsShellPrintedTildeIsText: on Windows Codex runs its
// Bash and exec_command tools in PowerShell, and the gateway judges the
// command again as PowerShell (codexPowerShellCommand). A quoted ~ path that
// is only printed is text there (GAP-1473), while the protected writes of
// the same class stay blocked (GAP-2389). The gateway's tests run with a
// POSIX home, which is how its path checks read a native Windows home.
func TestR105CodexWindowsShellPrintedTildeIsText(t *testing.T) {
	resetConnectorRuleCategories(t)
	previous := codexShellRunsPowerShell
	codexShellRunsPowerShell = true
	t.Cleanup(func() { codexShellRunsPowerShell = previous })
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	api := &APIServer{scannerCfg: cfg}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"GAP-1473 Write-Output quoted tilde path", `Write-Output '~/.ssh/authorized_keys'`, false},
		{"GAP-1473 Write-Output quoted tilde backslash path", `Write-Output '~\.ssh\authorized_keys'`, false},
		{"GAP-1473 git commit message", `git commit -m 'Document ~/.ssh/authorized_keys'`, false},
		{"GAP-1473 echo text", `echo '~/.ssh/authorized_keys is the file'`, false},
		{"GAP-1473 cmdlet path parameter", `Set-Content '~/.ssh/authorized_keys' k`, true},
		{"GAP-1473 printed text redirected to the key", `Write-Output 'k' > '~/.ssh/authorized_keys'`, true},
		{"GAP-2389 .NET append", `[System.IO.File]::AppendAllText("$HOME/.ssh/authorized_keys",'marker')`, true},
		{"cp to quoted tilde stays a write", `cp k.pub ~/.ssh/authorized_keys`, true},
		{"Write-Output then a writer", `Write-Output '~/.ssh/authorized_keys'; cp k.pub ~/.ssh/authorized_keys`, true},
		{"benign git status", `git status`, false},
		{"benign listing", `Get-ChildItem .`, false},
		{"benign project write", `Set-Content -Path .\notes.txt -Value hello`, false},
	} {
		for _, tool := range []string{"Bash", "exec_command"} {
			t.Run(tool+"/"+tc.name, func(t *testing.T) {
				input := map[string]interface{}{"command": tc.command}
				if tool == "exec_command" {
					input = map[string]interface{}{"cmd": tc.command}
				}
				resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
					HookEventName: "PreToolUse", ToolName: tool, CWD: t.TempDir(), ToolInput: input,
				})
				if got := resp.Action == "block"; got != tc.block {
					t.Errorf("block=%t want %t: action=%s raw=%s rules=%v reason=%s", got, tc.block, resp.Action, resp.RawAction, resp.RuleIDs, resp.Reason)
				}
			})
		}
	}
}
