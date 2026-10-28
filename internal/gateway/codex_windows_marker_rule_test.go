// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// Codex calls its Windows shell tool Bash. The same complete-argv rule that
// blocks Claude Code must block both PowerShell and cmd marker writes there.
func TestCodexWindowsActionBlocksCompleteArgvMarker(t *testing.T) {
	resetConnectorRuleCategories(t)
	const ruleID = "R102-OSS-MARKER-BLOCK"
	if err := ApplyRulePackOverrides(&guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version: 1, Category: "r102-oss-marker", Rules: []guardrail.RuleDefYAML{{
			ID: ruleID, ToolCallOnly: true,
			Pattern:    "dccert-block-marker",
			Expression: `f.commands.exists(c, c.argv_complete && "dccert-block-marker" in c.argv)`,
			Title:      "OSS smoke marker block", Severity: "CRITICAL", Confidence: 0.99,
		}},
	}}}); err != nil {
		t.Fatal(err)
	}
	previous := codexShellRunsPowerShell
	codexShellRunsPowerShell = true
	t.Cleanup(func() { codexShellRunsPowerShell = previous })

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	api := &APIServer{scannerCfg: cfg}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"PowerShell cmdlet", `Set-Content -Path codex-blocked-marker.txt -Value dccert-block-marker`, true},
		{"PowerShell wrapper", `powershell -NoProfile -Command "Set-Content -Path codex-blocked-marker.txt -Value dccert-block-marker"`, true},
		{"cmd wrapper", `cmd.exe /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd.exe /d /c unquoted body", `cmd.exe /d /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd.exe /s /c unquoted body", `cmd.exe /s /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd.exe /q /c unquoted body", `cmd.exe /q /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd.exe /a /c unquoted body", `cmd.exe /a /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd.exe /u /c unquoted body", `cmd.exe /u /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd.exe /e:on /c unquoted body", `cmd.exe /e:on /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd.exe /v:off /c unquoted body", `cmd.exe /v:off /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd.exe /f:on /c unquoted body", `cmd.exe /f:on /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd.exe /t:0A /c unquoted body", `cmd.exe /t:0A /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd /d /c one-word body", `cmd /d /c dccert-block-marker`, true},
		{"cmd /c one-word body", `cmd /c dccert-block-marker`, true},
		{"& cmd.exe /c call operator", `& cmd.exe /c echo dccert-block-marker > codex-blocked2.txt`, true},
		{"cmd caret redirect", `cmd.exe /c echo dccert-block-marker ^> codex-blocked2.txt`, true},
		{"cmd quoted wrapper", `cmd.exe /c "echo dccert-block-marker > codex-blocked2.txt"`, true},
		{"cmd with AutoRun disabled", `cmd.exe /d /c "echo dccert-block-marker > codex-blocked2.txt"`, true},
		{"quoted cmd body in list", `cmd.exe /c "echo dccert-block-marker > x.txt" && type x.txt`, true},
		{"doubled quoted cmd body in list", `cmd.exe /c ""echo dccert-block-marker > x.txt"" && type x.txt`, true},
		{"quoted cmd r body in list", `cmd.exe /r "echo dccert-block-marker > x.txt" && type x.txt`, true},
		{"quoted cmd joined switches in list", `cmd.exe /d/c "echo dccert-block-marker > x.txt" && type x.txt`, true},
		{"quoted cmd body contains a list", `cmd.exe /c "echo dccert-block-marker > x.txt && type x.txt"`, true},
		{"benign quoted cmd body in list", `cmd.exe /c "echo hello > x.txt" && type x.txt`, false},
		{"benign", `Set-Content -Path codex-action-allowed.txt -Value hi`, false},
		{"benign cmd.exe /d /c", `cmd.exe /d /c echo hello > codex-allowed.txt`, false},
		{"PowerShell call operator without Windows home", `& cmd.exe /c echo hello > codex-allowed.txt`, false},
		{"cmd.exe /k stays partial", `cmd.exe /k echo dccert-block-marker > codex-allowed.txt`, false},
		{"cmd.exe /x stays partial", `cmd.exe /x /c echo dccert-block-marker > codex-allowed.txt`, false},
		{"cmd.exe /e:maybe stays partial", `cmd.exe /e:maybe /c echo dccert-block-marker > codex-allowed.txt`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := codexWindowsMarkerKnownIssues[tc.name]; reason != "" && runtime.GOOS == "windows" {
				t.Skip(reason)
			}
			resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "Bash", CWD: t.TempDir(),
				ToolInput: map[string]interface{}{"command": tc.command},
			})
			if tc.blocked {
				if resp.Action != "block" || resp.RawAction != "block" || !strings.Contains(resp.Reason, ruleID) ||
					!strings.Contains(strings.ToLower(string(mustJSONMarshal(resp.CodexOutput))), "deny") {
					t.Fatalf("%s: action=%s raw=%s rules=%v output=%v reason=%s", tc.command, resp.Action, resp.RawAction, resp.RuleIDs, resp.CodexOutput, resp.Reason)
				}
			} else if resp.Action != "allow" || containsString(resp.RuleIDs, ruleID) {
				t.Fatalf("benign command: action=%s rules=%v reason=%s", resp.Action, resp.RuleIDs, resp.Reason)
			}
		})
	}
}

// codexWindowsMarkerKnownIssues are the rows that fail on a native Windows
// host only (they pass with the POSIX home the other platforms use): the
// quoted cmd /c body is read as one argv element there, so the complete-argv
// rule matches as detection-only.
var codexWindowsMarkerKnownIssues = map[string]string{
	"cmd quoted wrapper":              "GAP-1727: known 1.0.4 issue, fixed in 1.0.5",
	"quoted cmd body contains a list": "GAP-1727: known 1.0.4 issue, fixed in 1.0.5",
}

// The action dispatcher is shared by the Windows connector hook profiles.
// Each supported connector must retain the same enforceable exact-argv match;
// native hook capability and response shape are checked for Codex above.
func TestWindowsConnectorMarkerRuleUsesCompleteCMDWrapperArgv(t *testing.T) {
	resetConnectorRuleCategories(t)
	const ruleID = "R102-OSS-MARKER-BLOCK"
	if err := ApplyRulePackOverrides(&guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version: 1, Category: "r102-oss-marker", Rules: []guardrail.RuleDefYAML{{
			ID: ruleID, ToolCallOnly: true,
			Pattern:    "dccert-block-marker",
			Expression: `f.commands.exists(c, c.argv_complete && "dccert-block-marker" in c.argv)`,
			Title:      "OSS smoke marker block", Severity: "CRITICAL", Confidence: 0.99,
		}},
	}}}); err != nil {
		t.Fatal(err)
	}
	for _, connectorName := range []string{
		"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "opencode",
	} {
		t.Run(connectorName, func(t *testing.T) {
			for _, command := range []string{
				`cmd.exe /c echo dccert-block-marker > marker.txt`,
				`cmd.exe /d /c echo dccert-block-marker > marker.txt`,
				`cmd.exe /s /c echo dccert-block-marker > marker.txt`,
				`cmd.exe /q /c echo dccert-block-marker > marker.txt`,
				`cmd.exe /a /c echo dccert-block-marker > marker.txt`,
				`cmd.exe /u /c echo dccert-block-marker > marker.txt`,
				`cmd.exe /e:on /c echo dccert-block-marker > marker.txt`,
				`cmd.exe /v:off /c echo dccert-block-marker > marker.txt`,
				`cmd.exe /f:on /c echo dccert-block-marker > marker.txt`,
				`cmd.exe /t:0A /c echo dccert-block-marker > marker.txt`,
				`cmd /d /c dccert-block-marker`,
				`cmd /c dccert-block-marker`,
				`& cmd.exe /c echo dccert-block-marker > marker.txt`,
			} {
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input:      actionfacts.Input{Tool: "powershell", Command: command, DialectHint: actionfacts.DialectPowerShell},
					LegacyText: command, Connector: connectorName, EnforcementCapable: true,
				})
				match := findingWithID(findings, ruleID)
				if match == nil || !match.contributesToEnforcement() {
					t.Fatalf("marker rule was not enforceable for %s on %s: %v", connectorName, command, FindingStrings(findings))
				}
			}
		})
	}
}
