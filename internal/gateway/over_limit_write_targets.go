// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
//     The hook client reads the call with the same limit-exceeded analysis,
//     so its evidence lists no target of that analysis and carries the
//     truncation marker for that reason alone (withoutLimitTruncation).
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
	findings = appendTrustedHomeResolvedSSHKeyWriteFinding(findings, generation, request, facts)
	if !actionfacts.LimitExceededWriteTool(request.Input, facts) {
		return findings
	}
	if view, args, ok := actionfacts.OverLimitWriteTargetReduction(request.Input, facts); ok {
		reduced := request
		reduced.Input.Args = args
		reduced.ResolvedWriteTargets = withoutLimitTruncation(request.ResolvedWriteTargets)
		return appendTrustedHomeResolvedSSHKeyWriteFinding(findings, generation, reduced, view)
	}
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

// withoutLimitTruncation is the hook's write-target evidence for the reduced
// call. The hook marks its map truncated because the call's analysis is
// limit-exceeded, which the reduction resolves; the marker would otherwise
// fail every target of the reduced call closed where the gateway cannot
// resolve paths itself, a benign project write included. The targets the
// hook did list (an apply_patch envelope's files) are kept.
func withoutLimitTruncation(targets map[string]string) map[string]string {
	if targets[hookpaths.TruncatedKey] != "1" {
		return targets
	}
	out := make(map[string]string, len(targets))
	for key, value := range targets {
		if key != hookpaths.TruncatedKey {
			out[key] = value
		}
	}
	return out
}
