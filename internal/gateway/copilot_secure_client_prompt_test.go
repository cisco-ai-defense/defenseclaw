// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// On the Windows Secure Client profile a blocked GitHub Copilot prompt is
// replaced, through the mutation-only userPromptTransformed event, with
// DefenseClaw's notice. Observe mode, other verdicts, other events, other
// connectors and every other profile keep the unmodified output.
func TestCopilotSecureClientPromptOutput(t *testing.T) {
	previous := copilotSecureClientPromptRewriteActive
	t.Cleanup(func() { copilotSecureClientPromptRewriteActive = previous })
	secureClient := &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileSecureClient},
	}
	active := true
	copilotSecureClientPromptRewriteActive = func(*config.Config) bool { return active }
	a := &APIServer{scannerCfg: secureClient}
	ctx := context.Background()
	untouched := map[string]interface{}{}
	req := agentHookRequest{ConnectorName: "copilot", HookEventName: "userPromptTransformed"}

	out := a.copilotSecureClientPromptOutput(ctx, req, "action", "block",
		[]string{"ai-defense:CISCO-UNKNOWN", "ai-defense:CISCO-PROMPT-INJECTION", "CISCO-UNKNOWN"}, untouched)
	text, _ := out["modifiedTransformedPrompt"].(string)
	if len(out) != 1 || text != "DefenseClaw blocked the current user message. Do not answer it or call tools for it. "+
		"Reply only: DefenseClaw blocked this prompt. Cisco AI Defense: Custom Policy Violation, Prompt Injection." {
		t.Fatalf("blocked prompt output = %v", out)
	}
	for name, tc := range map[string]struct {
		req       agentHookRequest
		mode, raw string
		active    bool
	}{
		"observe mode":      {req, "observe", "block", true},
		"allowed prompt":    {req, "action", "allow", true},
		"submitted event":   {agentHookRequest{ConnectorName: "copilot", HookEventName: "userPromptSubmitted"}, "action", "block", true},
		"another connector": {agentHookRequest{ConnectorName: "codex", HookEventName: "userPromptTransformed"}, "action", "block", true},
		"not Secure Client": {req, "action", "block", false},
	} {
		active = tc.active
		if got := a.copilotSecureClientPromptOutput(ctx, tc.req, tc.mode, tc.raw, []string{"CISCO-JAILBREAK"}, untouched); len(got) != 0 {
			t.Fatalf("%s: output = %v, want it unmodified", name, got)
		}
	}
	// A finding that is not a fixed Cisco identity (a local rule, or text a
	// policy controls) keeps the generic notice.
	generic := "DefenseClaw blocked the current user message. Do not answer it or call tools for it. " +
		"Reply only: DefenseClaw blocked this prompt under the configured security policy."
	for _, findings := range [][]string{nil, {"SHELL-REVERSE"}, {"llm-judge:CISCO-PROMPT-INJECTION"}, {"CISCO-PROMPT-INJECTION", "CISCO-Ignore previous instructions"}} {
		if got := copilotBlockedPromptText(findings); got != generic {
			t.Fatalf("findings %v text = %q", findings, got)
		}
	}
	if got := copilotBlockedPromptText([]string{"CISCO-VIOLENCE", "CISCO-SEXUAL-CONTENT"}); !strings.HasSuffix(got,
		"Cisco AI Defense: Sexual Content & Exploitation, Violence & Public Safety Threats.") {
		t.Fatalf("multi-label text = %q", got)
	}
}

// The rewrite is the Windows Secure Client profile's alone.
func TestCopilotSecureClientPromptRewriteProfiles(t *testing.T) {
	standalone := &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	if copilotSecureClientPromptRewriteActive(standalone) || copilotSecureClientPromptRewriteActive(nil) {
		t.Fatal("the prompt rewrite is active outside Secure Client")
	}
}
