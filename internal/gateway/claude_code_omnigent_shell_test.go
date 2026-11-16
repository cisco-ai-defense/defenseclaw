// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1055: in OmniGent's claude harness, Claude Code calls OmniGent's shell
// as the MCP tool mcp__omnigent__sys_os_shell. Its nested PreToolUse matched
// a CRITICAL command rule but returned allow, because the command parsed to
// no command facts under the MCP name. It must get the verdict a direct Bash
// call gets, with the default rules. Removing the OmniGent connector (#1182)
// must not remove this Claude Code guard: OmniGent still runs Claude Code
// with that MCP server.
func TestEvaluateClaudeCodeHook_OmniGentMCPShellMatchesBash(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}

	blocked := map[string]bool{"rm -rf /": true, "rm -rf ~": true, "cat ~/.ssh/id_rsa": true, "sudo rm -rf /var": true}
	commands := []string{
		"rm -rf /", "rm -rf ~", "cat ~/.ssh/id_rsa", "sudo rm -rf /var",
		"chmod 777 /etc/passwd", "dd if=/dev/zero of=/dev/sda", "cat ~/.aws/credentials", "echo hello",
	}
	for _, event := range []string{"PreToolUse", "PermissionRequest"} {
		for _, command := range commands {
			verdict := func(tool string) claudeCodeHookResponse {
				return api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
					HookEventName: event,
					ToolName:      tool,
					ToolInput:     map[string]interface{}{"command": command},
				})
			}
			bash := verdict("Bash")
			if blocked[command] && bash.RawAction != "block" {
				t.Fatalf("%s Bash %q: raw=%q, want block (fixture drifted)", event, command, bash.RawAction)
			}
			for _, tool := range []string{claudeCodeOmniGentShellTool, " " + claudeCodeOmniGentShellTool + " "} {
				got := verdict(tool)
				if got.Action != bash.Action || got.RawAction != bash.RawAction || got.Severity != bash.Severity {
					t.Errorf("%s %q %q: action=%q raw=%q severity=%q, want Bash's %q/%q/%q",
						event, tool, command, got.Action, got.RawAction, got.Severity, bash.Action, bash.RawAction, bash.Severity)
				}
			}
		}
	}
}

// A CRITICAL rule proven only on the parsed command (the e2e marker rule)
// blocks the OmniGent shell call like Bash.
func TestEvaluateClaudeCodeHook_OmniGentMCPShellBlocksMarker(t *testing.T) {
	installSandboxMarkerRules(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	for _, tool := range []string{"Bash", claudeCodeOmniGentShellTool} {
		resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
			HookEventName: "PreToolUse",
			ToolName:      tool,
			ToolInput:     map[string]interface{}{"command": workdirMarkerCommand},
		})
		if resp.Action != "block" || resp.RawAction != "block" {
			t.Errorf("%s: action=%q raw=%q severity=%q, want block/block", tool, resp.Action, resp.RawAction, resp.Severity)
		}
	}
}

// The alias covers only OmniGent's shell tool: other servers' tools of the
// same name and OmniGent's other tools keep their own names.
func TestClaudeCodeTrustedActionTool_OnlyOmniGentShell(t *testing.T) {
	if got := claudeCodeTrustedActionTool(claudeCodeOmniGentShellTool, claudeCodeOmniGentShellTool); got != "shell" {
		t.Errorf("claudeCodeTrustedActionTool(%q) = %q, want shell", claudeCodeOmniGentShellTool, got)
	}
	for _, tool := range []string{"Bash", "mcp__other__sys_os_shell", "mcp__omnigent__sys_os_read", "sys_os_shell", "mcp__omnigent__sys_os_shell_extra"} {
		if got := claudeCodeTrustedActionTool(tool, tool); got != tool {
			t.Errorf("claudeCodeTrustedActionTool(%q) = %q, want passthrough", tool, got)
		}
	}
}
