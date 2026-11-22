// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
)

// acpArtifactVerdict reads the script a shell frame names, as the hook path
// reads the script a Bash call names at its execution boundary
// (safeApplyExperimentalArtifactPromotion): a frame that runs `sh prog.sh`
// whose body writes an authorized_keys file was allowed on ACP and blocked
// on every hook connector (rel-1-0-10:GAP-0783). The facts of the call just
// judged (capture) name the script; its current bytes are reopened and judged
// with the same rules and the same bounds. The verdict is nil when no script
// is named, none can be read, or its body matches nothing.
func (a *APIServer) acpArtifactVerdict(
	ctx context.Context, connectorName string, call acpToolCall, cwd string, capture *toolChainHookCapture, enforceable bool,
) *ToolInspectVerdict {
	if a == nil || capture == nil || !capture.recorded || ManagedEnterpriseActive() || call.tool != "shell" {
		return nil
	}
	artifactCtx, cancel := context.WithTimeout(ctx, promotedArtifactHookBudget)
	defer cancel()
	findings := promotedArtifactFindings(
		artifactCtx,
		agentHookRequest{ConnectorName: connectorName, CWD: hookCWDForContext(ctx, cwd), ReportedCWD: cwd, ToolName: call.tool},
		capture.facts,
		enforceable,
		nil,
	)
	if len(findings) == 0 {
		return nil
	}
	action := guardrailActionAllow
	if enforced := enforceableRuleFindings(findings); len(enforced) > 0 {
		action = profileMeetActionForFindings(ctx, a.decisionConfig(ctx), connectorName, enforced, true, false)
	}
	return &ToolInspectVerdict{
		Action:           action,
		RawAction:        action,
		Severity:         HighestSeverity(findings),
		Reason:           "matched ordered safety rule: " + strings.Join(ruleFindingIDs(findings), ", "),
		Findings:         FindingStrings(findings),
		DetailedFindings: findings,
	}
}

func ruleFindingIDs(findings []RuleFinding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}
