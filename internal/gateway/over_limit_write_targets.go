// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
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
		findings = appendTrustedHomeResolvedSSHKeyWriteFinding(findings, generation, reduced, view)
		return appendOverLimitElidedContentFinding(findings, generation, request, facts)
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

// overLimitElidedContentTitle is the reason of the conservative finding of
// a write whose text was left out of the analysis and whose target's
// content rules decide on that text.
const overLimitElidedContentTitle = "File-write text too large to verify for a file whose content rules decide on it; split it into smaller calls"

// overLimitContentRules names, per content-rule target class
// (actionfacts.OverLimitWriteElidedContentTarget), the rule that judges the
// text written to that file.
var overLimitContentRules = map[string]string{
	"docker-daemon-config": "tamper.docker_insecure_http_registry",
	"sudoers":              "privilege.sudoers_unrestricted_nopasswd",
	"account-database":     "privilege.posix_non_root_uid_zero_account_write",
	"global-preload":       "persistence.global_ld_preload_install",
	"pam":                  "tamper.pam_permit_authentication_bypass",
}

// appendOverLimitElidedContentFinding judges an over-limit write whose
// reduced call still left a text out and whose target is a file a content
// rule decides on (GAP-0687): that rule cannot read the text, so the call
// takes the rule's conservative finding. It blocks only where the call is
// enforcement-capable and the rule pack blocks with that rule (observe and
// alert-only profiles record it); a rule the pack does not have adds
// nothing, and an ordinary file is never such a target.
func appendOverLimitElidedContentFinding(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
) []RuleFinding {
	class, ok := actionfacts.OverLimitWriteElidedContentTarget(request.Input, facts)
	if !ok {
		return findings
	}
	_, rule, ok := trustedActionCatalogRule(generation, overLimitContentRules[class])
	if !ok {
		return findings
	}
	for _, finding := range findings {
		if finding.RuleID == rule.ID {
			return findings
		}
	}
	enforcement := findingEnforcementAllowed
	if !request.EnforcementCapable {
		enforcement = findingEnforcementDetectionOnly
	}
	return append(findings, adjustConfidence(request.Input.Tool, RuleFinding{
		RuleID: rule.ID, Title: overLimitElidedContentTitle, Severity: rule.Severity,
		Confidence: rule.Confidence, Evidence: trustedActionInputText(request.Input, ""),
		Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
		enforcement: enforcement,
	}))
}

// overLimitWriteBoundedTwinRequest is the request for the bounded twin of a
// native write whose text is over the string limit only by white space
// (actionfacts.OverLimitWriteBoundedTwin): the same call within the limits,
// so every rule, content rules included, judges it (GAP-0687).
func overLimitWriteBoundedTwinRequest(request trustedActionRequest, facts actionfacts.Facts) (trustedActionRequest, bool) {
	args, ok := actionfacts.OverLimitWriteBoundedTwin(request.Input, facts)
	if !ok {
		return trustedActionRequest{}, false
	}
	twin := request
	twin.Input.Args = args
	twin.LegacyText = string(args)
	twin.conflictSource = nil
	twin.record, twin.recordTelemetry = nil, nil
	return twin, true
}

// withOverLimitTwinFindings adds the findings of a bounded twin: its blocks
// as withTwinProvenBlocks counts them, and the rules it only records.
func withOverLimitTwinFindings(findings, twin []RuleFinding) []RuleFinding {
	findings = withTwinProvenBlocks(findings, twin)
	for _, finding := range twin {
		if finding.contributesToEnforcement() ||
			slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == finding.RuleID }) {
			continue
		}
		findings = append(findings, finding)
	}
	return findings
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
