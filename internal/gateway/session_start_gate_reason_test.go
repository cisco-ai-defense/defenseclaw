// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// A call of a Codex session whose start was refused after a Codex
// self-update reads the refusal and its repair commands, not redacted spans
// (GAP-2643). Free-form text inside the same sentence stays redacted.
func TestSessionStartGateReasonReadsOnTheAgentSurface(t *testing.T) {
	redaction.SetAgentReasonRedactionDisabled(false)
	t.Cleanup(func() { redaction.SetAgentReasonRedactionDisabled(false) })
	useAgentVerdictProfile(t, false, false)
	profile := connector.NewCodexConnector().HookProfile(connector.SetupOpts{})
	req := agentHookRequest{ConnectorName: "codex", HookEventName: "PreToolUse", ToolName: "Bash"}
	for _, reason := range []string{
		sessionStartBlockedReason(codexStartRegistrationUnavailable + ": " + connector.ErrCodexExecutableChanged.Error()),
		sessionStartBlockedReason(codexStartRegistrationUnavailable + codexStartRegistrationSetupStep),
		sessionStartBlockedReason(sessionStartUnfinishedReason),
		sessionStartPendingReason,
		"DefenseClaw blocked this tool call: it is too large for DefenseClaw to inspect.",
	} {
		for _, mode := range []string{"observe", "action"} {
			action, wouldBlock := "allow", true
			if mode == "action" {
				action, wouldBlock = "block", false
			}
			resp := agentHookResponseForProfile(profile, req, action, "block", "HIGH", reason,
				[]string{"SESSION-START-BLOCKED"}, mode, wouldBlock, profile.Capabilities)
			wire, err := json.Marshal(renderAgentHookResponseForProfile(profile, resp))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(wire), "<redacted") || !strings.Contains(string(wire), strings.TrimSuffix(reason, ".")) {
				t.Errorf("%s: agent text %s does not carry the readable reason %q", mode, wire, reason)
			}
		}
	}
	for _, reason := range []string{
		sessionStartBlockedReason("rule X: token sk-live-0123456789abcdef in the prompt"),
		sessionStartBlockedReason(codexStartRegistrationUnavailable + ": Codex home C:\\Users\\someone\\.codex goes through a link; run: defenseclaw setup codex --yes"),
	} {
		if got := agentDisplayReason(reason, redaction.SinkPolicyDefault); got == reason {
			t.Errorf("free-form start reason passed unredacted: %q", got)
		}
	}
}
