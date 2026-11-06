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

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP0534NestedTreeLink(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, ".defenseclaw")
	cwd := filepath.Join(home, "project")
	outside := filepath.Join(home, "outside")
	for _, dir := range []string{filepath.Join(state, "policies"), cwd, outside} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	protected := filepath.Join(outside, "rule.yaml")
	solo := filepath.Join(outside, "solo.yaml")
	ordinary := filepath.Join(cwd, "output")
	for _, file := range []string{protected, solo, ordinary} {
		if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	nested := filepath.Join(state, "policies", "relocated")
	if err := os.Symlink(outside, nested); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(home, "rule-hardlink")
	if err := os.Link(protected, hard); err != nil {
		t.Fatal(err)
	}
	ordinaryHard := filepath.Join(home, "output-hardlink")
	if err := os.Link(ordinary, ordinaryHard); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		name, target string
		protected    bool
	}{
		{"lexical-protected", nested + "/rule.yaml", true},
		{"lexical-new-protected", nested + "/new-rule.yaml", true},
		{"physical-protected", protected, true},
		{"physical-solo-protected", solo, true},
		{"physical-new-protected", filepath.Join(outside, "new-rule.yaml"), true},
		{"hardlink-protected", hard, true},
		{"ordinary", ordinary, false},
		{"ordinary-hardlink", ordinaryHard, false},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			t.Run(tc.name+"/"+connector, func(t *testing.T) {
				tool := "PowerShell"
				if connector == "codex" {
					tool = "exec_command"
				}
				command := `Write-Output $(.\a[1]<#x#>); Set-Content -Path ` + tc.target + ` -Value x`
				payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": tool, "tool_input": map[string]string{"command": command}})
				if err != nil {
					t.Fatal(err)
				}
				direct := hookpaths.UnprovenProtectedWrite(command, cwd, home)
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
				mapped, listed := targets[tc.target]
				t.Logf("REVIEW_G534_R4 name=%s connector=%s protected=%t action=%s direct=%s reason=%s listed=%t mapped=%s", tc.name, connector, tc.protected, action, direct, targets[hookpaths.UnprovenReasonKey], listed, mapped)
				if tc.protected && action != "block" || !tc.protected && action != "allow" {
					t.Errorf("action=%s for protected=%t", action, tc.protected)
				}
			})
		}
	}
}

func TestGAP0534OrdinaryLongComment(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "output"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	command := `Write-Output $(.\a[1]<#x#>); Set-Content -Path ~/project/output -Value x #`
	for i := 0; i < 520; i++ {
		command += fmt.Sprintf(" ordinary%d", i)
	}
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
			direct := hookpaths.UnprovenProtectedWrite(command, cwd, home)
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
			t.Logf("REVIEW_G534_R4 long-comment connector=%s action=%s direct=%s reason=%s", connector, action, direct, targets[hookpaths.UnprovenReasonKey])
			if action != "allow" {
				t.Errorf("ordinary long comment blocked")
			}
		})
	}
}

func TestGAP0534OrdinaryQuotedComment(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "output"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	command := `Write-Output $(.\a[1]<#x#>); Set-Content -Path ~/project/output -Value x #`
	for i := 0; i < 260; i++ {
		command += fmt.Sprintf(" 'ordinary%d'", i)
	}
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
			direct := hookpaths.UnprovenProtectedWrite(command, cwd, home)
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
			t.Logf("REVIEW_G534_R4 quoted-comment connector=%s action=%s direct=%s reason=%s", connector, action, direct, targets[hookpaths.UnprovenReasonKey])
			if action != "allow" {
				t.Errorf("ordinary quoted comment blocked")
			}
		})
	}
}
