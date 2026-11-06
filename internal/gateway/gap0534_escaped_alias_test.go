// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP0534EscapedStateAliases(t *testing.T) {
	for _, linkedRoot := range []bool{false, true} {
		name := "plain-root"
		if linkedRoot {
			name = "linked-root"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			cwd := filepath.Join(home, "project")
			outside := filepath.Join(home, "outside")
			state := filepath.Join(home, ".defenseclaw")
			physicalState := state
			if linkedRoot {
				physicalState = filepath.Join(home, "state-target")
			}
			for _, dir := range []string{cwd, outside, physicalState} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if linkedRoot {
				if err := os.Symlink(physicalState, state); err != nil {
					t.Fatal(err)
				}
			}
			outsideConfig := filepath.Join(outside, "config.yaml")
			outsidePolicy := filepath.Join(outside, "policy.yaml")
			ordinary := filepath.Join(cwd, "output")
			for _, file := range []string{outsideConfig, outsidePolicy, ordinary, filepath.Join(physicalState, "notes.txt")} {
				if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for link, target := range map[string]string{
				filepath.Join(physicalState, "config.yaml"): outsideConfig,
				filepath.Join(physicalState, "policies"):    outside,
				filepath.Join(home, "config-alias"):         outsideConfig,
				filepath.Join(home, "policy-alias"):         outsidePolicy,
			} {
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			const prefix = `Write-Output $(.\a[1]<#x#>); Set-Content -Path `
			for _, tc := range []struct {
				name, target string
				protected    bool
			}{
				{"state-entry-link", `~/.defenseclaw/config.yaml`, true},
				{"state-file-physical", `~/outside/config.yaml`, true},
				{"state-file-alias", `~/config-alias`, true},
				{"state-file-alias-glob", filepath.Join(home, "config-alia?"), true},
				{"state-tree-link", `~/.defenseclaw/policies/policy.yaml`, true},
				{"state-tree-physical", `~/outside/policy.yaml`, true},
				{"state-tree-alias", `~/policy-alias`, true},
				{"state-tree-alias-glob", filepath.Join(home, "policy-alia?"), true},
				{"ordinary-twin", `~/project/output`, false},
				{"ordinary-unlisted-state-file", `~/.defenseclaw/notes.txt`, false},
				{"ordinary-unlisted-physical-file", filepath.Join(physicalState, "notes.txt"), false},
				{"ordinary-glob", filepath.Join(cwd, "outpu?"), false},
			} {
				for _, connector := range []string{"claudecode", "codex"} {
					t.Run(tc.name+"/"+connector, func(t *testing.T) {
						tool := "PowerShell"
						if connector == "codex" {
							tool = "exec_command"
						}
						command := prefix + tc.target + ` -Value x`
						payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": tool, "tool_input": map[string]string{"command": command}})
						if err != nil {
							t.Fatal(err)
						}
						directReason := hookpaths.UnprovenProtectedWrite(command, cwd, home)
						stateMention := hookpaths.ActionStateTargetMention(command, cwd, home)
						targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
						if !ok {
							t.Fatal("missing write evidence")
						}
						ctx := context.WithValue(t.Context(), resolvedWritesContextKey{}, targets)
						api := instructionProtectionTestAPI(t, connector, "action", "HIGH")
						start := time.Now()
						var action string
						if connector == "claudecode" {
							action = api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", CWD: cwd, ToolName: tool, ToolInput: map[string]any{"command": command}}).Action
						} else {
							action = api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", CWD: cwd, ToolName: tool, ToolInput: map[string]any{"cmd": command}}).Action
						}
						t.Logf("GAP_0534_R4 name=%s linked_root=%t connector=%s protected=%t action=%s direct=%s state_mention=%t reason=%s elapsed_us=%d", tc.name, linkedRoot, connector, tc.protected, action, directReason, stateMention, targets[hookpaths.UnprovenReasonKey], time.Since(start).Microseconds())
						if tc.protected && action != "block" || !tc.protected && action != "allow" {
							t.Errorf("action=%s for protected=%t", action, tc.protected)
						}
					})
				}
			}
		})
	}
}

func TestGAP0534DenseStateHardlink(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{cwd, filepath.Join(state, "hooks"), filepath.Join(state, "cache")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4100; i++ {
		if err := os.WriteFile(filepath.Join(state, "hooks", fmt.Sprintf("entry-%04d", i)), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	protected := filepath.Join(state, "cache", "target")
	if err := os.WriteFile(protected, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(protected, filepath.Join(home, "cache-hardlink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	command := `Write-Output $(.\a[1]<#x#>); Set-Content -Path ~/cache-hardlink -Value x`
	for _, connector := range []string{"claudecode", "codex"} {
		t.Run(connector, func(t *testing.T) {
			tool := "PowerShell"
			if connector == "codex" {
				tool = "exec_command"
			}
			payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": tool, "tool_input": map[string]string{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			directReason := hookpaths.UnprovenProtectedWrite(command, cwd, home)
			stateMention := hookpaths.ActionStateTargetMention(command, cwd, home)
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok {
				t.Fatal("missing write evidence")
			}
			ctx := context.WithValue(t.Context(), resolvedWritesContextKey{}, targets)
			api := instructionProtectionTestAPI(t, connector, "action", "HIGH")
			var action string
			if connector == "claudecode" {
				action = api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", CWD: cwd, ToolName: tool, ToolInput: map[string]any{"command": command}}).Action
			} else {
				action = api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", CWD: cwd, ToolName: tool, ToolInput: map[string]any{"cmd": command}}).Action
			}
			t.Logf("GAP_0534_R4 name=dense-state-hardlink connector=%s action=%s direct=%s state_mention=%t reason=%s", connector, action, directReason, stateMention, targets[hookpaths.UnprovenReasonKey])
			if action != "block" {
				t.Errorf("active state hardlink was allowed")
			}
		})
	}
}

func TestGAP0534DenseOrdinaryHardlink(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{cwd, filepath.Join(state, "hooks")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4100; i++ {
		if err := os.WriteFile(filepath.Join(state, "hooks", fmt.Sprintf("entry-%04d", i)), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ordinary := filepath.Join(cwd, "output")
	if err := os.WriteFile(ordinary, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ordinary, filepath.Join(home, "ordinary-hardlink")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	t.Setenv("HOME", home)
	command := `Write-Output $(.\a[1]<#x#>); Set-Content -Path ~/ordinary-hardlink -Value x`
	for _, connector := range []string{"claudecode", "codex"} {
		t.Run(connector, func(t *testing.T) {
			tool := "PowerShell"
			if connector == "codex" {
				tool = "exec_command"
			}
			payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": tool, "tool_input": map[string]string{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok {
				t.Fatal("missing write evidence")
			}
			ctx := context.WithValue(t.Context(), resolvedWritesContextKey{}, targets)
			api := instructionProtectionTestAPI(t, connector, "action", "HIGH")
			var action string
			if connector == "claudecode" {
				action = api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", CWD: cwd, ToolName: tool, ToolInput: map[string]any{"command": command}}).Action
			} else {
				action = api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", CWD: cwd, ToolName: tool, ToolInput: map[string]any{"cmd": command}}).Action
			}
			if action != "allow" {
				t.Errorf("ordinary hardlink action = %s, want allow", action)
			}
		})
	}
}

func TestGAP0534BroadLinkedRoot(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "output"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "config.yaml"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4100; i++ {
		if err := os.WriteFile(filepath.Join(cwd, fmt.Sprintf("ordinary-%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(cwd, filepath.Join(home, ".defenseclaw")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	command := `Write-Output $(.\a[1]<#x#>); Set-Content -Path ~/project/output -Value x`
	for _, connector := range []string{"claudecode", "codex"} {
		t.Run(connector, func(t *testing.T) {
			tool := "PowerShell"
			if connector == "codex" {
				tool = "exec_command"
			}
			payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": tool, "tool_input": map[string]string{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			directReason := hookpaths.UnprovenProtectedWrite(command, cwd, home)
			stateMention := hookpaths.ActionStateTargetMention(command, cwd, home)
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok {
				t.Fatal("missing write evidence")
			}
			ctx := context.WithValue(t.Context(), resolvedWritesContextKey{}, targets)
			api := instructionProtectionTestAPI(t, connector, "action", "HIGH")
			var action string
			if connector == "claudecode" {
				action = api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", CWD: cwd, ToolName: tool, ToolInput: map[string]any{"command": command}}).Action
			} else {
				action = api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", CWD: cwd, ToolName: tool, ToolInput: map[string]any{"cmd": command}}).Action
			}
			t.Logf("GAP_0534_R4 name=broad-linked-root connector=%s action=%s direct=%s state_mention=%t reason=%s", connector, action, directReason, stateMention, targets[hookpaths.UnprovenReasonKey])
			if action != "allow" {
				t.Errorf("ordinary project output was blocked")
			}
		})
	}
}
