// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// awsExampleSecretEnv is a .env holding AWS's published example key pair.
const awsExampleSecretEnv = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
	"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

// GAP-0034. A secret in a Read result reaches Claude Code (and Cowork, which
// runs the same engine and hook route) before PostToolUse runs, so in action
// mode the finding is recorded and named to the model in additionalContext,
// without the value, but is never returned as decision=block: that would not
// take the result back. Observe mode gives the same answer. Prevention is a
// PreToolUse rule on the path (next test).
func TestClaudeCodeReadResultSecretIsAdvisoryInEveryMode(t *testing.T) {
	for _, mode := range []string{"action", "observe"} {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = mode
		cfg.Guardrail.Connector = "claudecode"
		api := &APIServer{scannerCfg: cfg}
		resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
			HookEventName: "PostToolUse",
			ToolName:      "Read",
			ToolInput:     map[string]interface{}{"file_path": "/Users/alice/Desktop/cowork-test/.env"},
			ToolResponse:  map[string]interface{}{"type": "text", "file": map[string]interface{}{"content": awsExampleSecretEnv}},
			CWD:           "/Users/alice/Desktop/cowork-test",
		})
		// A tool result never blocks in the default pack (HIGH at most): in
		// action mode the secret is an alert, in observe mode advisory.
		wantAction := "alert"
		if mode == "observe" {
			wantAction = "allow"
		}
		if resp.Action != wantAction || resp.RawAction != "alert" || resp.WouldBlock || resp.Severity != "HIGH" {
			t.Fatalf("%s: action=%q raw=%q would_block=%v severity=%q, want %s/alert/false/HIGH",
				mode, resp.Action, resp.RawAction, resp.WouldBlock, resp.Severity, wantAction)
		}
		if !strings.Contains(strings.Join(resp.Findings, " "), "SEC-AWS-SECRET") {
			t.Fatalf("%s: findings=%v, want SEC-AWS-SECRET", mode, resp.Findings)
		}
		if decision, ok := resp.ClaudeCodeOutput["decision"]; ok && decision == "block" {
			t.Fatalf("%s: claude output %+v: PostToolUse cannot take back a result", mode, resp.ClaudeCodeOutput)
		}
		hookOutput, _ := resp.ClaudeCodeOutput["hookSpecificOutput"].(map[string]interface{})
		if context, _ := hookOutput["additionalContext"].(string); !strings.Contains(context, "SEC-AWS-SECRET") {
			t.Fatalf("%s: claude output %+v: the model is not told about the secret finding", mode, resp.ClaudeCodeOutput)
		}
		if strings.Contains(resp.AdditionalContext, "wJalrXUtnFEMI") || strings.Contains(resp.Reason, "wJalrXUtnFEMI") {
			t.Fatalf("%s: the secret value is echoed back: %+v", mode, resp)
		}
	}
}

// The prevention the docs show (connectors/claudecode.mdx, connectors/cowork.mdx):
// a custom pack rule on the parsed path facts blocks the .env read at
// PreToolUse in action mode, for Read and for a shell cat, and leaves near
// misses alone.
func TestClaudeCodeDotEnvPathRuleDeniesTheReadAtPreToolUse(t *testing.T) {
	pack := filepath.Join(t.TempDir(), "my-org")
	if err := os.CopyFS(pack, os.DirFS(filepath.Join(guardrailPoliciesRoot(t), "default"))); err != nil {
		t.Fatal(err)
	}
	rule := `version: 1
category: my-org-dotenv
rules:
  - id: ORG-DOTENV-READ
    tool_call_only: true
    expression: >-
      f.commands.exists(c,
      defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_READ in c.operations &&
      f.paths.exists(p, p.command_id == c.id &&
      p.access == defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_READ &&
      (p.resolved.endsWith('/.env') || p.resolved.endsWith('\\.env'))))
    pattern: '(?:^|[\s/\\])\.env(?:\s|$)'
    title: "Read of a .env file"
    severity: CRITICAL
    confidence: 0.95
    tags: [credential, file-sensitive]
`
	if err := os.WriteFile(filepath.Join(pack, "rules", "my-org-dotenv.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	installToolCallCorpusPackDirConnector(t, "claudecode", pack)
	dir := filepath.Join(t.TempDir(), "cowork-test")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".env", ".env.example", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("A=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"action", "observe"} {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = mode
		cfg.Guardrail.Connector = "claudecode"
		cfg.Guardrail.RulePackDir = pack
		api := &APIServer{scannerCfg: cfg}
		for _, tc := range []struct {
			name, tool string
			input      map[string]interface{}
			payload    map[string]interface{}
			hit        bool
		}{
			{"Read .env", "Read", map[string]interface{}{"file_path": dir + "/.env"}, nil, true},
			{"Bash cat .env", "Bash", map[string]interface{}{"command": "cat " + dir + "/.env"}, nil, true},
			{"Cowork shell cat .env", "mcp__workspace__bash", map[string]interface{}{"command": "cat .env"}, map[string]interface{}{"mcp_server": coworkWorkspaceServer()}, true},
			{"Read README.md", "Read", map[string]interface{}{"file_path": dir + "/README.md"}, nil, false},
			{"Read .env.example", "Read", map[string]interface{}{"file_path": dir + "/.env.example"}, nil, false},
			{"Bash ls", "Bash", map[string]interface{}{"command": "ls -la " + dir}, nil, false},
		} {
			if runtime.GOOS == "windows" && tc.tool != "Read" {
				// Shell dialect reading on a Windows gateway is pinned by
				// TestCoworkShellReplaysTheToolCallCorpusWithBashVerdicts.
				continue
			}
			payload := map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": tc.tool}
			for k, v := range tc.payload {
				payload[k] = v
			}
			resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: tc.tool, ToolInput: tc.input, CWD: dir, Payload: payload,
			})
			hit := strings.Contains(strings.Join(resp.Findings, " "), "ORG-DOTENV-READ")
			switch {
			case hit != tc.hit:
				t.Errorf("%s/%s: findings=%v, want rule hit %v", mode, tc.name, resp.Findings, tc.hit)
			case tc.hit && mode == "action" && (resp.Action != "block" || resp.RawAction != "block"):
				t.Errorf("%s/%s: action=%q raw=%q, want block/block", mode, tc.name, resp.Action, resp.RawAction)
			case tc.hit && mode == "observe" && (resp.Action != "allow" || !resp.WouldBlock):
				t.Errorf("%s/%s: action=%q would_block=%v, want allow/true", mode, tc.name, resp.Action, resp.WouldBlock)
			case !tc.hit && resp.Action == "block":
				t.Errorf("%s/%s: near miss blocked: %+v", mode, tc.name, resp)
			}
		}
	}
}
