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

package gateway

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Text the user typed is the principal own instruction, not an injection: a
// trust-exploit finding on it is capped at HIGH, which alerts in the default and
// permissive packs and still blocks in strict (its block level is MEDIUM). The
// surface decides, never a rule ID. The attack text is the shared fixture of
// prompt_injection_floor_test.go (floorOverridePrompt).

// userTypedBlockingPrompt is a typed prompt that blocks in the default pack on
// every surface: a provider key is a secret finding, not a trust finding, so the
// user-typed ceiling does not touch it. Tests that need a prompt block to travel
// through a transport, a mode or a profile use it.
func userTypedBlockingPrompt() string {
	return "AWS_ACCESS_KEY_ID=" + codexHighEntropyAWSKey()
}

func userTypedTrustGeneration(t *testing.T, profile string) *compiledRulePackCategories {
	t.Helper()
	generation, err := compileRulePackCategories(mustLoadRulePack(t, filepath.Join("..", "..", "policies", "guardrail", profile)))
	if err != nil {
		t.Fatalf("compile %s pack: %v", profile, err)
	}
	return generation
}

func findingByRule(findings []RuleFinding, ruleID string) *RuleFinding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// The ceiling is decided by the category and the origin of the text: the same
// rule keeps CRITICAL on text of any other origin, and a rule of another
// category keeps its severity on user-typed text.
func TestUserTypedTrustCeilingByCategoryAndOrigin(t *testing.T) {
	wantAction := map[string]map[ruleTextOrigin]string{
		"default":    {ruleTextOriginUnspecified: "block", ruleTextOriginUserTyped: "alert"},
		"permissive": {ruleTextOriginUnspecified: "block", ruleTextOriginUserTyped: "alert"},
		"strict":     {ruleTextOriginUnspecified: "block", ruleTextOriginUserTyped: "block"},
	}
	for _, profile := range alertFatigueProfiles {
		generation := userTypedTrustGeneration(t, profile)
		for _, origin := range []ruleTextOrigin{ruleTextOriginUnspecified, ruleTextOriginUserTyped} {
			finding := findingByRule(scanContentRuleCategoryFromOrigin(
				generation, floorOverridePrompt, "message", ruleContentScopeUntrusted, "", origin), "TRUST-IGNORE-PREVIOUS")
			if finding == nil {
				t.Fatalf("%s origin %d: TRUST-IGNORE-PREVIOUS did not match", profile, origin)
			}
			wantSeverity := "CRITICAL"
			if origin == ruleTextOriginUserTyped {
				wantSeverity = "HIGH"
			}
			if finding.Severity != wantSeverity {
				t.Errorf("%s origin %d: severity %s, want %s", profile, origin, finding.Severity, wantSeverity)
			}
			if got := guardrailFallbackActionForProfile(finding.Severity, profile); got != wantAction[profile][origin] {
				t.Errorf("%s origin %d: action %s, want %s", profile, origin, got, wantAction[profile][origin])
			}
		}
	}
	options := ruleScanOptions{origin: ruleTextOriginUserTyped}
	for _, tc := range []struct{ category, severity, want string }{
		{"trust-exploit", "CRITICAL", "HIGH"},
		{"trust-exploit", "HIGH", "HIGH"},
		{"trust-exploit", "MEDIUM", "MEDIUM"},
		{"secret", "CRITICAL", "CRITICAL"},
		{"enterprise-data", "CRITICAL", "CRITICAL"},
		{"command", "CRITICAL", "CRITICAL"},
	} {
		got := applyUserTypedTrustCeiling(options, tc.category, RuleFinding{Severity: tc.severity}).Severity
		if got != tc.want {
			t.Errorf("%s %s on user-typed text = %s, want %s", tc.category, tc.severity, got, tc.want)
		}
		if other := applyUserTypedTrustCeiling(ruleScanOptions{}, tc.category, RuleFinding{Severity: tc.severity}).Severity; other != tc.severity {
			t.Errorf("%s %s on text of unspecified origin = %s, want it unchanged", tc.category, tc.severity, other)
		}
	}
}

// The /llm proxy: the prompt direction is the user turn and alerts; the
// completion direction is the model and still blocks.
func TestUserTypedTrustCeilingOnTheProxyPromptPath(t *testing.T) {
	for _, strategy := range []string{"regex_only", "regex_judge"} {
		t.Run(strategy, func(t *testing.T) {
			previous := liveGeneration.Load()
			liveGeneration.Store(nil)
			t.Cleanup(func() { liveGeneration.Store(previous) })
			inspector := NewGuardrailInspector("local", nil, nil)
			inspector.SetDetectionStrategy(strategy, "", "", "", false)
			prompt := inspector.Inspect(context.Background(), "prompt", floorOverridePrompt, nil, "model", "action")
			if prompt == nil || prompt.Action != "alert" || prompt.Severity != "HIGH" ||
				!strings.Contains(strings.Join(prompt.Findings, ","), "TRUST-IGNORE-PREVIOUS") {
				t.Fatalf("prompt verdict = %+v, want a HIGH alert naming TRUST-IGNORE-PREVIOUS", prompt)
			}
			completion := inspector.Inspect(context.Background(), "completion", floorOverridePrompt, nil, "model", "action")
			if completion == nil || completion.Action != "block" || completion.Severity != "CRITICAL" {
				t.Fatalf("completion verdict = %+v, want the CRITICAL block it had", completion)
			}
		})
	}
}

// The hooks: the turn-start event is what the user typed and alerts; the same
// text on a surface the user did not type (a tool result, an expansion, a model
// request) keeps its CRITICAL block.
func TestUserTypedTrustCeilingOnHookSurfaces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	ctx := context.Background()

	submit := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "UserPromptSubmit", Prompt: floorOverridePrompt})
	if submit.RawAction != "alert" || submit.Severity != "HIGH" || !containsString(submit.Findings, "TRUST-IGNORE-PREVIOUS:Ignore previous instructions") {
		t.Errorf("Claude Code UserPromptSubmit = %+v, want a HIGH alert", submit)
	}
	secret := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "UserPromptSubmit", Prompt: userTypedBlockingPrompt()})
	if secret.RawAction != "block" || secret.Severity != "CRITICAL" {
		t.Errorf("Claude Code UserPromptSubmit with a key = %+v, want the CRITICAL block (the ceiling is for trust findings only)", secret)
	}
	expansion := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "UserPromptExpansion", Prompt: floorOverridePrompt})
	if expansion.RawAction != "block" || expansion.Severity != "CRITICAL" {
		t.Errorf("Claude Code UserPromptExpansion = %+v, want the CRITICAL block it had", expansion)
	}

	toolResult := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		HookEventName: "PostToolUse", ToolName: "WebFetch", ToolResponse: floorOverridePrompt,
	})
	if toolResult.Severity != "CRITICAL" {
		t.Errorf("Claude Code PostToolUse with the same text = %+v, want CRITICAL (not typed by the user)", toolResult)
	}

	cfg.Guardrail.Connector = "codex"
	codexSubmit := api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "UserPromptSubmit", Prompt: floorOverridePrompt})
	if codexSubmit.RawAction != "alert" || codexSubmit.Severity != "HIGH" {
		t.Errorf("Codex UserPromptSubmit = %+v, want a HIGH alert", codexSubmit)
	}

	cfg.Guardrail.Connector = "cursor"
	for _, tc := range []struct {
		event, action, severity string
	}{
		{"beforeSubmitPrompt", "alert", "HIGH"},
		{"pre_user_prompt", "alert", "HIGH"},
		{"subagentStart", "block", "CRITICAL"},
		// These events cannot block (the hook answers allow), but the finding
		// keeps the severity it has on any surface the user did not type.
		{"beforeModel", "allow", "CRITICAL"},
		{"userPromptTransformed", "allow", "CRITICAL"},
	} {
		resp := api.evaluateAgentHook(ctx, agentHookRequest{
			ConnectorName: "cursor", HookEventName: tc.event, Content: floorOverridePrompt, SessionID: "user-typed-" + tc.event,
		})
		if resp.Action != tc.action || resp.Severity != tc.severity {
			t.Errorf("generic hook %s = action %s severity %s, want %s %s", tc.event, resp.Action, resp.Severity, tc.action, tc.severity)
		}
	}
}
