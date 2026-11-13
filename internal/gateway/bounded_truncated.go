// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The one place every reader's truncation reaches the hook decision (the
// bound rule, internal/guardrail/bounded). A reader that hit a cap returns
// its bounded.Truncated beside what it read; its caller judges what was read
// as before and then calls withBoundedTruncation (findings that the profile
// maps) or floorBoundedTruncated (a verdict a lane already decided). Both add
// the evaluation-limit finding (ACTION-COMPOUND-LIMIT) with the audit reason
// "bounded_truncated cap=<kinds>" in its title and evidence, so the audit
// row, the finding events and the agent notice name the cap. No new audit
// action, finding id or telemetry field.
//
// The unknown tier follows the pack (rel-1-0-6:GAP-0675): the profile maps
// the evaluation-limit finding to an alert in the default and permissive
// packs, a managed install's included, and to a block in the strict pack
// (guardrailActionForProfile).

// boundedTruncatedTitle is the ship-authored title of a truncated input. The
// reason (a closed set of cap names) follows it; it carries no input text.
const boundedTruncatedTitle = "Input exceeds policy evaluation limit, judged as unknown"

// boundedTier is the tier of the pack a call of connectorName is judged by.
func (a *APIServer) boundedTier(ctx context.Context, connectorName string) bounded.Tier {
	cfg := a.decisionConfig(ctx)
	if cfg == nil {
		return bounded.TierDefault
	}
	return bounded.TierOf(cfg.HookPolicyTierForConnector(connectorName))
}

// boundedTruncatedFinding is the evaluation-limit finding of an input read up
// to the caps in t. A call whose projection cannot authorize a block
// (enforcementCapable false) still alerts: a truncated input is never a
// silent allow.
func boundedTruncatedFinding(t bounded.Truncated, enforcementCapable bool) RuleFinding {
	finding := trustedActionLimitFindings(enforcementCapable)[0]
	reason := t.Reason()
	finding.Title = boundedTruncatedTitle + " (" + reason + ")"
	finding.Evidence = reason
	if !enforcementCapable {
		finding.enforcement = findingEnforcementAlertOnly
	}
	return finding
}

// withBoundedTruncation adds the truncation of t to the findings of what was
// read before the caps, which keep deciding on their own: the profile maps
// the result to at least the unknown tier of the pack and never below those
// findings (guardrailActionForProfile). An evaluation-limit finding the call
// already carries is kept and takes the bounded reason, so a call has one
// limit finding. The caller's slice is not changed. No cap hit: findings as
// they are, without allocation.
func withBoundedTruncation(findings []RuleFinding, t bounded.Truncated, request trustedActionRequest) []RuleFinding {
	if !t.Any() {
		return findings
	}
	bound := boundedTruncatedFinding(t, request.EnforcementCapable)
	index := slices.IndexFunc(findings, func(finding RuleFinding) bool {
		return canonicalTrustedRuleID(finding.RuleID) == evaluationLimitRuleID
	})
	if index < 0 {
		return append(slices.Clip(findings), bound)
	}
	out := slices.Clone(findings)
	existing := &out[index]
	existing.Title, existing.Evidence = bound.Title, bound.Evidence
	if !existing.contributesToEnforcement() && !existing.contributesToAlertOnly() {
		// A detection-only limit finding would leave the call allowed.
		existing.enforcement = bound.enforcement
		existing.proof = bound.proof
	}
	return out
}

// floorBoundedTruncated raises a verdict a lane decided for an input read up
// to the caps in t to bounded.Floor: at least the unknown tier of the pack,
// never below the verdict. The evaluation-limit finding and the bounded
// reason are added whatever the action, so the audit row names the cap. Run
// it before applyMode, like markOversizeUninspected.
func (v *ToolInspectVerdict) floorBoundedTruncated(t bounded.Truncated, tier bounded.Tier) {
	if v == nil || !t.Any() {
		return
	}
	bound := boundedTruncatedFinding(t, true)
	before := bounded.ParseAction(v.Action)
	after := bounded.Floor(before, t, tier)
	if after > before {
		v.Action = after.String()
		v.Reason = bound.Title
		severity := "MEDIUM"
		if after == bounded.Block {
			severity = "HIGH"
		}
		if guardrailSeverityRank(severity) > guardrailSeverityRank(v.Severity) {
			v.Severity = severity
		}
		if v.Confidence < bound.Confidence {
			v.Confidence = bound.Confidence
		}
	} else if v.Reason == "" {
		v.Reason = bound.Title
	} else {
		v.Reason += "; " + bound.Evidence
	}
	v.Findings = append(v.Findings, bound.RuleID+":"+bound.Title)
	v.DetailedFindings = append(v.DetailedFindings, bound)
}
