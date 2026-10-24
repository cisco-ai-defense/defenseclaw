// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// overLimitUnverifiedWriteTitle is the reason of the conservative block of a
// write tool call whose targets cannot be read.
const overLimitUnverifiedWriteTitle = "File-write tool call too large or malformed to verify which file it writes; split it into smaller calls"

// appendTrustedWriteTargetFindings adds the authorized-keys write findings
// of appendTrustedHomeResolvedSSHKeyWriteFinding, and judges a structured
// write tool call whose arguments are limit-exceeded (GAP-0674): with no
// path facts, no file-write rule saw its target, so it was allowed.
//
//   - When actionfacts.OverLimitWriteTargetReduction reads its targets, the
//     same proofs run on the reduced call. The semantic rules already ran on
//     that view in dispatchTrustedAction (only a match counts there).
//     The hook client lists the targets of the same reduced call
//     (hookpaths.ResolveConnector), resolved as the user, so its evidence
//     is used unchanged: a truncation marker it still carries means the
//     map is incomplete for another reason (a target it could not list, a
//     second spelling of the call), and a target the gateway cannot place
//     itself then fails closed.
//   - When it cannot, and the call is no apply_patch envelope whose files
//     hookpaths names (the proof above judged each of those), the protected
//     files may be among its targets: an enforcement-capable call takes the
//     conservative block of the persistence rule, as a write whose target
//     the hook could not resolve does.
//
// Other tools keep the limit-exceeded result unchanged.
func appendTrustedWriteTargetFindings(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
) []RuleFinding {
	if !actionfacts.LimitExceededWriteTool(request.Input, facts) {
		return appendTrustedHomeResolvedSSHKeyWriteFinding(findings, generation, request, facts)
	}
	if view, args, ok := actionfacts.OverLimitWriteTargetReduction(request.Input, facts); ok {
		reduced := request
		reduced.Input.Args = args
		return appendTrustedHomeResolvedSSHKeyWriteFinding(findings, generation, reduced, view)
	}
	if actionfacts.ApplyPatchTool(request.Input.Tool) {
		if clientProvedOrdinaryOverLimitPatch(request.ResolvedWriteTargets, facts.ActiveHome) {
			// The semantic view of an oversized patch can be invalid even when
			// the user's hook proved every file target. In that case a generic
			// protected-write finding from the reduced/legacy view is stale.
			// Keep all unrelated findings and the protected-link decision.
			kept := findings[:0]
			for _, finding := range findings {
				if finding.RuleID != "persistence.ssh_authorized_keys_command" {
					kept = append(kept, finding)
				}
			}
			return kept
		}
	}
	findings = appendTrustedHomeResolvedSSHKeyWriteFinding(findings, generation, request, facts)
	if !request.EnforcementCapable {
		return findings
	}
	if actionfacts.ApplyPatchTool(request.Input.Tool) {
		if _, known := hookpaths.ApplyPatchWriteTargets(
			request.Input.Tool, request.Input.Args, "", facts.CWD, facts.ActiveHome,
		); known {
			return findings
		}
	}
	for _, finding := range findings {
		if finding.contributesToEnforcement() {
			return findings
		}
	}
	_, rule, ok := trustedActionCatalogRule(generation, "persistence.ssh_authorized_keys_command")
	if !ok {
		return findings
	}
	return append(findings, adjustConfidence(request.Input.Tool, RuleFinding{
		RuleID: rule.ID, Title: overLimitUnverifiedWriteTitle, Severity: rule.Severity,
		Confidence: rule.Confidence, Evidence: trustedActionInputText(request.Input, ""),
		Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
		enforcement: findingEnforcementAllowed,
	}))
}

func clientProvedOrdinaryOverLimitPatch(evidence map[string]string, home string) bool {
	if evidence[hookpaths.PatchCompleteKey] != "1" || home == "" {
		return false
	}
	protected := hookpaths.ProtectedAuthorizedKeysPaths(home)
	targets := 0
	for operand, resolved := range evidence {
		if strings.HasPrefix(operand, "\x00") {
			continue
		}
		if !isAbsoluteSemanticPath(operand) || !isAbsoluteSemanticPath(resolved) ||
			strings.ContainsAny(operand+resolved, "\x00\r\n") {
			return false
		}
		for _, path := range protected {
			if canonicalSemanticPath(operand) == canonicalSemanticPath(path) ||
				canonicalSemanticPath(resolved) == canonicalSemanticPath(path) {
				return false
			}
		}
		targets++
	}
	return targets > 0
}
