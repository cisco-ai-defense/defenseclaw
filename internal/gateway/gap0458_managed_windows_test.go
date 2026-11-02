// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0458WindowsManagedObserveHookHoldsOverflow(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"), []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	steps := make([]string, 200)
	for i := range steps {
		steps[i] = fmt.Sprintf("Write-Host 'step %d'", i)
	}
	pad := strings.Join(steps, "\n")
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range []struct {
			name, command string
			blocked       bool
		}{
			{"alias", pad + "\nSet-Alias gc Set-Content -Force; gc -Path ~/.defenseclaw/config.yaml -Value x", true},
			{"read", pad + "\nGet-Content ~/.defenseclaw/config.yaml", false},
			{"printed path", pad + "\nWrite-Output $(Get-Date) '~/.defenseclaw/config.yaml'", false},
			{"printed literal", pad + "\nWrite-Output $('ok') '~/.defenseclaw/config.yaml'", false},
		} {
			t.Run(connector+"/"+row.name, func(t *testing.T) {
				api := instructionProtectionTestAPI(t, connector, "observe", "HIGH")
				api.scannerCfg.DeploymentMode = "managed_enterprise"
				api.scannerCfg.Enterprise.Profile = "standalone"
				ctx := withAuthenticatedHookConnector(t.Context(), connector)
				tool := "PowerShell"
				if connector == "codex" {
					tool = "exec_command"
				}
				var got string
				if connector == "claudecode" {
					got = api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
						HookEventName: "PreToolUse", CWD: home, ToolName: tool,
						ToolInput: map[string]any{"command": row.command},
					}).Action
				} else {
					got = api.evaluateCodexHook(ctx, codexHookRequest{
						HookEventName: "PreToolUse", CWD: home, ToolName: tool,
						ToolInput: map[string]any{"cmd": row.command},
					}).Action
				}
				if blocked := got == guardrailActionBlock; blocked != row.blocked {
					t.Fatalf("hook action = %s, want block=%t", got, row.blocked)
				}
			})
		}
	}
}
