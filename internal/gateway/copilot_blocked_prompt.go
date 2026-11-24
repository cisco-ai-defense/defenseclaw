// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// GitHub Copilot drops the output of a userPromptSubmitted hook, so that
// event cannot stop a prompt. Its mutation-only userPromptTransformed event
// can replace the content the model receives, so on every profile (per-user,
// standalone managed and Secure Client) the gateway answers that event, when
// the guardrail blocks it in action mode, with DefenseClaw's notice in place
// of the prompt. That successful replacement is the enforcement mechanism, so
// the effective verdict is block (not would-block). Copilot's timeline still
// shows the user's prompt. Observe mode keeps the no-modification contract
// (GAP-1730; it reverses the GAP-0786 record-only ruling for Copilot).
//
// The mode is the one the hook enforces (effectiveMode), not the configured
// one: a verdict that must be enforced in observe mode and a failed check
// (closed in observe mode too) replace the prompt as well (GAP-1753). The
// native hook writes the generic replacement itself when a block arrives
// without one (hookexec.CopilotBlockedPromptText, GAP-1752).

// copilotBlockedPromptRewrite reports whether this decision will replace the
// prompt Copilot sends to the model. Callers use the same predicate for the
// returned vendor payload and the effective audit/telemetry outcome, with the
// effective mode.
func copilotBlockedPromptRewrite(req agentHookRequest, mode, rawAction string) bool {
	return req.ConnectorName == "copilot" && canonicalEvent(req.HookEventName) == "userprompttransformed" &&
		mode == "action" && normalizeCodexAction(rawAction) == "block"
}

// copilotBlockedPromptOutput returns the hook output for req: the rewrite of
// a blocked Copilot prompt, otherwise output.
func copilotBlockedPromptOutput(
	req agentHookRequest,
	mode, rawAction string,
	findings []string,
	output map[string]interface{},
) map[string]interface{} {
	if !copilotBlockedPromptRewrite(req, mode, rawAction) {
		return output
	}
	return map[string]interface{}{"modifiedTransformedPrompt": copilotBlockedPromptText(findings)}
}

// copilotBlockedPromptText is what the model receives in place of a blocked
// prompt: an instruction to reply only with DefenseClaw's notice. The notice
// names Cisco AI Defense categories by their fixed display labels; any
// other finding (a local rule, an unrecognized identity) keeps the generic
// notice, so no policy or cloud text reaches the model.
func copilotBlockedPromptText(findings []string) string {
	const lead = "DefenseClaw blocked the current user message. Do not answer it or call tools for it. Reply only: "
	labels := make([]string, 0, len(findings))
	seen := map[string]bool{}
	for _, finding := range findings {
		// The hook verdict tags each Cisco finding with its lane
		// (mergeWithLaneVerdict).
		id := strings.TrimPrefix(strings.TrimSpace(finding), "ai-defense:")
		label := ciscoFindingDisplayLabel(id)
		if id != ciscoUnknownFindingID && label == ciscoFindingDisplayLabel(ciscoUnknownFindingID) {
			return hookexec.CopilotBlockedPromptText
		}
		if !seen[label] {
			seen[label] = true
			labels = append(labels, label)
		}
	}
	if len(labels) == 0 {
		return hookexec.CopilotBlockedPromptText
	}
	sort.Strings(labels)
	return lead + "DefenseClaw blocked this prompt. Cisco AI Defense: " + strings.Join(labels, ", ") + "."
}
