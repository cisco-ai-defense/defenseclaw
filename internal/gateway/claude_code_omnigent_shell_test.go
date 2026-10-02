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
// no command facts under the MCP name. It must block like a direct Bash call
// (a CRITICAL marker rule, proven on the parsed command).
func TestEvaluateClaudeCodeHook_OmniGentMCPShellBlocksLikeBash(t *testing.T) {
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

	// The alias covers only that one MCP tool.
	for _, tool := range []string{"Bash", "mcp__other__sys_os_shell", "mcp__omnigent__sys_os_read"} {
		if got := claudeCodeTrustedActionTool(tool, tool); got != tool {
			t.Errorf("claudeCodeTrustedActionTool(%q) = %q, want passthrough", tool, got)
		}
	}
}
