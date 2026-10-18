// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// On the Windows Secure Client profile a GitHub Copilot prompt that the
// guardrail blocks in action mode cannot be blocked: Copilot drops the output
// of a config-file userPromptSubmitted hook. Its mutation-only
// userPromptTransformed event can replace the content the model receives, so
// the gateway answers that event with DefenseClaw's notice in place of the
// prompt. The verdict accounting is unchanged (raw block, effective allow,
// would_block), Copilot's timeline still shows the user's prompt, and every
// other profile keeps the no-modification contract.

// copilotSecureClientPromptRewriteActive reports a gateway serving the
// Windows Secure Client profile. Replaced in tests.
var copilotSecureClientPromptRewriteActive = func(cfg *config.Config) bool {
	return runtime.GOOS == "windows" && cfg != nil && cfg.SecureClientIntegration()
}

// copilotSecureClientPromptOutput returns the hook output for req: the
// rewrite of a blocked Copilot prompt on Secure Client, otherwise output.
func (a *APIServer) copilotSecureClientPromptOutput(
	ctx context.Context,
	req agentHookRequest,
	mode, rawAction string,
	findings []string,
	output map[string]interface{},
) map[string]interface{} {
	if req.ConnectorName != "copilot" || canonicalEvent(req.HookEventName) != "userprompttransformed" ||
		mode != "action" || normalizeCodexAction(rawAction) != "block" ||
		!copilotSecureClientPromptRewriteActive(a.decisionConfig(ctx)) {
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
			return lead + "DefenseClaw blocked this prompt under the configured security policy."
		}
		if !seen[label] {
			seen[label] = true
			labels = append(labels, label)
		}
	}
	if len(labels) == 0 {
		return lead + "DefenseClaw blocked this prompt under the configured security policy."
	}
	sort.Strings(labels)
	return lead + "DefenseClaw blocked this prompt. Cisco AI Defense: " + strings.Join(labels, ", ") + "."
}
