// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A statement the reader cannot parse, then a removal of the DefenseClaw state
// folder. Where the reader resolves the removal to the state folder, which is
// the Windows PowerShell reading of a drive-letter home, the call is a proven
// mutation of DefenseClaw state: self-protection blocks it in every profile.
// Where it does not (POSIX homes), the call proves no target, so it alerts
// outside the strict profile and blocks in strict (lead ruling,
// rel-1-0-6:GAP-0675 round 12). The ordinary-file twin follows the same
// reading: on POSIX the unparsed statement leaves the call unanalysed, so it
// alerts outside strict; on Windows the reader parses the whole call, finds an
// ordinary file and allows it in every profile. The hook answers within its
// time budget.
func TestGAP0534PowerShellHookFixedPointBlocks(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	stateDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "config.yaml"), []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	const unparsed = `Write-Output $(.\a[1]<#x#>); `
	stateWant := map[string]string{"default": guardrailActionAlert, "strict": guardrailActionBlock}
	if runtime.GOOS == "windows" {
		stateWant = map[string]string{"default": guardrailActionBlock, "strict": guardrailActionBlock}
	}
	ordinaryWant := map[string]string{"default": guardrailActionAlert, "strict": guardrailActionBlock}
	if runtime.GOOS == "windows" {
		ordinaryWant = map[string]string{"default": guardrailActionAllow, "strict": guardrailActionAllow}
	}
	for _, row := range []struct {
		name, command string
		want          map[string]string
	}{
		{"state folder", unparsed + `Remove-Item -Recurse -Force ~/.defenseclaw`, stateWant},
		{"ordinary file", unparsed + `Remove-Item -Recurse -Force ~/project/settings.json`, ordinaryWant},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			for posture, want := range row.want {
				t.Run(row.name+"/"+connector+"/"+posture, func(t *testing.T) {
					api := instructionProtectionTestAPIWithPack(t, connector, "action", "HIGH", posture)
					start := time.Now()
					tool := "PowerShell"
					if connector == "codex" {
						tool = "exec_command"
					}
					if action := gap0568ToolHookAction(t, api, connector, tool, home, cwd, row.command, true, false); action != want {
						t.Fatalf("hook action = %s, want %s", action, want)
					}
					if elapsed := time.Since(start); elapsed > 5*time.Second {
						t.Fatalf("hook answer took %s", elapsed)
					}
				})
			}
		}
	}
}

func TestGAP0534PowerShellHookFixedPointNoWriteMapReturnsVerdict(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	stateDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "config.yaml"), []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	const command = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/.defenseclaw`
	for _, connector := range []string{"claudecode", "codex"} {
		t.Run(connector, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, connector, "action", "HIGH")
			start := time.Now()
			tool := "PowerShell"
			if connector == "codex" {
				tool = "exec_command"
			}
			action := gap0568ToolHookAction(t, api, connector, tool, home, cwd, command, false, false)
			if action == "" {
				t.Fatal("hook returned no verdict")
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("hook answer took %s", elapsed)
			}
		})
	}
}
