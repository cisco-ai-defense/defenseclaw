package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Payloads captured from a real Claude Code session against the pre-755
// gateway. Each one produced a CRITICAL/HIGH "would block" finding purely
// because result text mentioned a command or a rule name. They are tool
// OUTPUT, never tool invocations.
func newNoiseAPI() *APIServer {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	return &APIServer{scannerCfg: cfg}
}

func TestSessionNoise_SourceCommentMentioningDeleteIsNotACommand(t *testing.T) {
	api := newNoiseAPI()
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]interface{}{"command": "sed -n '520,540p' internal/gateway/claude_code_hook.go"},
		ToolResponse: map[string]interface{}{
			"stdout": "// prevents source snippets such as \"rm -rf /\" from becoming a CRITICAL\n// command finding on PostToolBatch while retaining trust, secret, and PII",
		},
	})
	t.Logf("findings=%v would_block=%v", resp.Findings, resp.WouldBlock)
	if containsString(resp.Findings, "CMD-RM-RF:Recursive force delete from critical root path") {
		t.Errorf("REGRESSION: source comment treated as executable command: %v", resp.Findings)
	}
}

func TestSessionNoise_RuleNameListingIsNotACommand(t *testing.T) {
	api := newNoiseAPI()
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PostToolBatch",
		ToolCalls: map[string]interface{}{
			"stdout": "rule_id          severity  c\nCMD-MKFS         CRITICAL  348\nCMD-SUDO         LOW       75\nCMD-RM-RF        CRITICAL  161",
		},
	})
	t.Logf("findings=%v would_block=%v", resp.Findings, resp.WouldBlock)
	for _, bad := range []string{"CMD-MKFS", "CMD-SUDO", "CMD-RM-RF"} {
		for _, got := range resp.Findings {
			if strings.Contains(got, bad) {
				t.Errorf("REGRESSION: rule-name listing matched %s: %v", bad, resp.Findings)
			}
		}
	}
}

// TestSessionNoise_Issue787ExactRuleDescription pins the reporter's complete
// 62-byte reproduction. A Read result that names CMD-MKFS is documentation,
// not authoritative evidence that a format command was invoked.
func TestSessionNoise_Issue787ExactRuleDescription(t *testing.T) {
	api := newNoiseAPI()
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PostToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]interface{}{"file_path": "benign_prose.txt"},
		ToolResponse: map[string]interface{}{
			"content": "The rule CMD-MKFS is documented in the DefenseClaw rule pack.\n",
		},
	})
	if resp.Action != "allow" || resp.RawAction != "allow" || resp.WouldBlock {
		t.Fatalf("exact #787 reproduction action=%q raw=%q would_block=%v findings=%v",
			resp.Action, resp.RawAction, resp.WouldBlock, resp.Findings)
	}
	for _, finding := range resp.Findings {
		if strings.Contains(finding, "CMD-MKFS") {
			t.Fatalf("exact #787 prose produced command finding: %v", resp.Findings)
		}
	}
}

func TestSessionNoise_ReadingClaudeMDIsNotAnInstructionMutation(t *testing.T) {
	api := newNoiseAPI()
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PostToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]interface{}{"file_path": "/repo/CLAUDE.md"},
		ToolResponse:  map[string]interface{}{"content": "Project build instructions."},
	})
	for _, finding := range resp.Findings {
		if strings.Contains(finding, "COG-CLAUDE-MD") {
			t.Fatalf("ordinary CLAUDE.md read produced cognitive-mutation finding: %v", resp.Findings)
		}
	}
}

// Secret detection is deliberately RETAINED on untrusted content by #750/#755.
// This test documents that boundary rather than asserting silence.
func TestSessionNoise_SecretInResultStillDetected(t *testing.T) {
	api := newNoiseAPI()
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]interface{}{"command": "grep defenseclaw ~/.claude/settings.json"},
		ToolResponse: map[string]interface{}{
			"stdout": "\"OTEL_EXPORTER_OTLP_HEADERS\": \"authorization=Bearer 7c1d94ab30f6e582b47d0c9315ae6f28d51b83c4\"",
		},
	})
	t.Logf("SECRET-PATH findings=%v would_block=%v", resp.Findings, resp.WouldBlock)
	// This is the boundary #750/#755 deliberately kept: command rules stop at
	// tool output, secret rules do not. A synthetic-but-realistic token must
	// still be reported, or the placeholder tightening has gone too far.
	if !containsString(resp.Findings, "SEC-BEARER:Bearer token in header") {
		t.Errorf("findings=%v, want secret detection retained on tool output", resp.Findings)
	}
}

func TestSessionNoise_DirectoryListingWithEnvFile(t *testing.T) {
	api := newNoiseAPI()
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]interface{}{"command": "ls -la ~/.defenseclaw/"},
		ToolResponse: map[string]interface{}{
			"stdout": "-rw-------  1 user staff    91 Aug 10 18:48 .env\n-rw-------  1 user staff     0 Aug 10 18:35 .env.lock",
		},
	})
	t.Logf("PATH-RULE findings=%v would_block=%v", resp.Findings, resp.WouldBlock)
}
