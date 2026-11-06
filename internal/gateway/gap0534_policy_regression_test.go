// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP0534RecoveredTargetsAndPolicy(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{cwd, state} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(state, "config.yaml")
	if err := os.WriteFile(file, []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "linkcfg")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"relative-link", "-linkcfg"} {
		if err := os.Symlink(file, filepath.Join(cwd, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		name, command        string
		protected, exhausted bool
	}{
		{"linked-state", `Write-Output $(.\a[1]<#x#>); Set-Content -Path ~/linkcfg -Value x`, true, true},
		{"absolute-linked-state", `Write-Output $(.\a[1]<#x#>); Set-Content -LiteralPath '` + link + `' -Value x`, true, true},
		{"relative-linked-state", `Write-Output $(.\a[1]<#x#>); Set-Content -Path relative-link -Value x`, true, true},
		{"quoted-linked-state", `Write-Output $(.\a[1]<#x#>); Set-Content -LiteralPath '-linkcfg' -Value x`, true, true},
		{"ordinary-twin", `Write-Output $(.\a[1]<#x#>); Set-Content -Path ~/project/output -Value x`, false, true},
		{"ordinary-cycle", "0`@A>`; Remove-Item -Force ~/project/output", false, true},
		{"protected-cycle", "0`@A>`; Remove-Item -Force ~/.defenseclaw/config.yaml", true, true},
	} {
		for _, connectorName := range []string{"claudecode", "codex"} {
			for _, tier := range []string{"default", "strict"} {
				t.Run(tc.name+"/"+connectorName+"/"+tier, func(t *testing.T) {
					tool := "PowerShell"
					if connectorName == "codex" {
						tool = "exec_command"
					}
					body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
						"tool_name": tool, "tool_input": map[string]string{"command": tc.command}})
					if err != nil {
						t.Fatal(err)
					}
					targets, ok := hookpaths.Decode(hookpaths.Resolve(body))
					if !ok {
						t.Fatal("write evidence unavailable")
					}
					ctx := context.WithValue(t.Context(), resolvedWritesContextKey{}, targets)
					api := instructionProtectionTestAPI(t, connectorName, "action", "HIGH")
					if tier == "strict" {
						installToolCallCorpusProfileConnector(t, connectorName, "strict")
						api.scannerCfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
					}
					start := time.Now()
					var action string
					var findings []string
					if connectorName == "claudecode" {
						response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", CWD: cwd,
							ToolName: tool, ToolInput: map[string]any{"command": tc.command}})
						action, findings = response.Action, response.Findings
					} else {
						response := api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", CWD: cwd,
							ToolName: tool, ToolInput: map[string]any{"cmd": tc.command}})
						action, findings = response.Action, response.Findings
					}
					want := "allow"
					if tc.protected || tier == "strict" && tc.exhausted {
						want = "block"
					}
					if action != want {
						t.Fatalf("action=%q, want %q; reason=%q; findings=%v", action, want, targets[hookpaths.UnprovenReasonKey], findings)
					}
					if elapsed := time.Since(start); elapsed > time.Second {
						t.Fatalf("hook answer took %s", elapsed)
					}
					if targets[hookpaths.UnprovenReasonKey] == "shell-parse-unreached" {
						rule := "ACTION-COMPOUND-UNRESOLVED"
						if tier == "strict" {
							rule = "ACTION-COMPOUND-LIMIT"
						}
						if !findingStringHasRuleID(findings, rule) {
							t.Fatalf("missing %s warning or strict bound: %v", rule, findings)
						}
					}
				})
			}
		}
	}
}

func TestGAP0534RecoveredStateAliases(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	physicalState := filepath.Join(home, "state-target")
	for _, dir := range []string{cwd, physicalState} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(physicalState, "config.yaml")
	if err := os.WriteFile(config, []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		filepath.Join(home, ".defenseclaw"): physicalState,
		filepath.Join(home, "state-link"):   config,
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(config, filepath.Join(home, "state-hardlink")); err != nil {
		t.Fatal(err)
	}
	ordinary := filepath.Join(cwd, "output")
	if err := os.WriteFile(ordinary, []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ordinary, filepath.Join(home, "ordinary-hardlink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	const prefix = `Write-Output $(.\a[1]<#x#>); Set-Content -Path `
	for _, tc := range []struct {
		name, target string
		protected    bool
	}{
		{"state-root-link", `~/.defenseclaw/config.yaml`, true},
		{"state-file-link", `~/state-link`, true},
		{"physical-state-file", `~/state-target/config.yaml`, true},
		{"state-hardlink", `~/state-hardlink`, true},
		{"state-root-recursive", `~/.defenseclaw`, true},
		{"ordinary-twin", `~/project/output`, false},
		{"ordinary-hardlink", `~/ordinary-hardlink`, false},
	} {
		for _, connectorName := range []string{"claudecode", "codex"} {
			t.Run(tc.name+"/"+connectorName, func(t *testing.T) {
				tool := "PowerShell"
				if connectorName == "codex" {
					tool = "exec_command"
				}
				command := prefix + tc.target + ` -Value x`
				if tc.name == "state-root-recursive" {
					command = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/.defenseclaw`
				}
				payload, err := json.Marshal(map[string]any{
					"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": tool,
					"tool_input": map[string]string{"command": command},
				})
				if err != nil {
					t.Fatal(err)
				}
				targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
				if !ok {
					t.Fatal("missing write evidence")
				}
				ctx := context.WithValue(t.Context(), resolvedWritesContextKey{}, targets)
				api := instructionProtectionTestAPI(t, connectorName, "action", "HIGH")
				start := time.Now()
				var action string
				if connectorName == "claudecode" {
					action = api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", CWD: cwd,
						ToolName: tool, ToolInput: map[string]any{"command": command}}).Action
				} else {
					action = api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", CWD: cwd,
						ToolName: tool, ToolInput: map[string]any{"cmd": command}}).Action
				}
				wantAction, wantReason := "allow", "shell-parse-unreached"
				if tc.protected {
					wantAction, wantReason = "block", "shell-parse-bound"
				}
				if action != wantAction || targets[hookpaths.UnprovenReasonKey] != wantReason {
					t.Fatalf("action=%q reason=%q, want action=%q reason=%q", action,
						targets[hookpaths.UnprovenReasonKey], wantAction, wantReason)
				}
				if elapsed := time.Since(start); elapsed > time.Second {
					t.Fatalf("hook answer took %s", elapsed)
				}
			})
		}
	}
}
