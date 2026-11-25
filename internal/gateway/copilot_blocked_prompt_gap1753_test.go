// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// gap1753GenericNotice is copilotBlockedPromptText with no Cisco AI Defense
// category (hookexec.CopilotBlockedPromptText), written out so the test also
// runs on the code before the fix.
const gap1753GenericNotice = "DefenseClaw blocked the current user message. Do not answer it or call tools for it. " +
	"Reply only: DefenseClaw blocked this prompt under the configured security policy."

// GAP-1753: the replacement of a blocked Copilot CLI prompt follows the mode
// the hook enforces, not the configured one. A failed check (here a recovered
// evaluator panic) is enforced in observe mode too, so it replaces the prompt
// in both configured modes, on the per-user and the standalone managed
// profile. Before the fix the failed check answered allow with would_block
// and no output, and the prompt reached the model.
func TestGAP1753CopilotFailedPromptCheckReplacesThePrompt(t *testing.T) {
	panicking := hookProfileRuntime{Evaluate: func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
		panic("gap1753 injected evaluator error")
	}}
	for _, deployment := range []struct{ name, mode, profile string }{
		{"per-user", "", ""},
		{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
	} {
		for _, mode := range []string{"observe", "action"} {
			for _, failMode := range []string{"open", "closed"} {
				cfg := config.DefaultConfig()
				cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
				cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode = mode, failMode
				if cfg.SecureClientIntegration() {
					t.Fatalf("%s: the fixture resolves to Secure Client", deployment.name)
				}
				server := &APIServer{scannerCfg: cfg}
				req := agentHookRequest{ConnectorName: "copilot", HookEventName: "userPromptTransformed", SessionID: "gap-1753"}
				resp, panicked := server.safeEvaluateHook(t.Context(), "copilot", req, nil, nil, panicking)
				text, _ := resp.HookOutput["modifiedTransformedPrompt"].(string)
				if !panicked || resp.Action != "block" || resp.RawAction != "block" || resp.WouldBlock ||
					text != gap1753GenericNotice || len(resp.HookOutput) != 1 {
					t.Errorf("%s %s fail_mode=%s: panicked=%t %s/%s would_block=%t output=%v, want block/block/false and the prompt replaced",
						deployment.name, mode, failMode, panicked, resp.Action, resp.RawAction, resp.WouldBlock, resp.HookOutput)
				}
			}
		}
	}
}

// GAP-1753: the generic replacement of the gateway is the one the native
// hook writes for a block without a replacement (GAP-1752).
func TestGAP1753CopilotGenericNoticeMatchesTheNativeHook(t *testing.T) {
	if got := copilotBlockedPromptText(nil); got != gap1753GenericNotice {
		t.Fatalf("copilotBlockedPromptText(nil)=%q, want %q", got, gap1753GenericNotice)
	}
	if got := copilotBlockedPromptText([]string{"local-rule-x"}); got != gap1753GenericNotice {
		t.Fatalf("copilotBlockedPromptText(local rule)=%q, want the generic notice", got)
	}
}
