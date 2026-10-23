// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A pre-receipt hook may consume a benign answer and close the connection
// during a package downgrade. The gateway cannot claim that it blocked it.
func TestDowngradedManagedHookDoesNotAuditAnUnprovenBlock(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{
		DeploymentMode: "managed_enterprise",
		Enterprise:     config.EnterpriseConfig{Profile: "standalone"},
	}}
	api.scannerCfg.Guardrail.HookFailMode = "closed"
	for _, connector := range []string{"claudecode", "codex", "opencode"} {
		got := api.unreceiptedHookDecision(false, connector, map[string]string{
			"claudecode": "PreToolUse", "codex": "PreToolUse", "opencode": "tool.execute.before",
		}[connector], agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"})
		if got.Action != hookActionUnconfirmed || got.RawAction != "allow" || got.Mode != "action" || got.Reason != hookexec.ManagedGatewayNoAnswerReason {
			t.Errorf("%s closed connection: %+v, want unconfirmed allow proposal in action mode", connector, got)
		}
	}
}

// An observe-mode answer in flight during gateway start has no receipt from
// an older native hook. Preserve its mode and proposal without inventing an
// enforced block.
func TestUnreceiptedObserveHookKeepsModeAndUnconfirmedAction(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{
		DeploymentMode: "managed_enterprise",
		Enterprise:     config.EnterpriseConfig{Profile: "standalone"},
	}}
	api.scannerCfg.Guardrail.HookFailMode = "closed"
	proposal := agentHookResponse{
		Action: "alert", RawAction: "block", Mode: "observe", WouldBlock: true,
	}
	for name, got := range map[string]agentHookResponse{
		"older hook":      api.unreceiptedHookDecision(false, "claudecode", "PreToolUse", proposal),
		"missing receipt": api.deliveredHookDecision("claudecode", proposal, ""),
	} {
		if got.Action != hookActionUnconfirmed || got.RawAction != "block" || got.Mode != "observe" || got.WouldBlock || got.Reason != hookexec.ManagedGatewayNoAnswerReason {
			t.Errorf("%s observe result = %+v, want unconfirmed block proposal in observe mode", name, got)
		}
	}
	confirmedBlock := api.deliveredHookDecision("claudecode", proposal, hookexec.HookDeliveryReceiptBlock)
	if confirmedBlock.Action != "block" || confirmedBlock.Mode != "action" {
		t.Errorf("confirmed fallback block = %+v, want enforced block", confirmedBlock)
	}
	api.scannerCfg.Guardrail.HookFailMode = "open"
	openProposal := agentHookResponse{Action: "block", RawAction: "block", Mode: "action"}
	got := api.deliveredHookDecision("claudecode", openProposal, "")
	if got.Action != hookActionUnconfirmed || got.RawAction != "block" || got.Mode != "action" {
		t.Errorf("open outage without a receipt = %+v, want unconfirmed block proposal", got)
	}
}
