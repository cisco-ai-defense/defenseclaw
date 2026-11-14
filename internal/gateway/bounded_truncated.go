// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The one place every reader's truncation reaches the hook decision (the
// bound rule, internal/guardrail/bounded). A reader that hit a cap returns
// its bounded.CapSet beside what it read; its caller judges what was read as
// before and then calls withBoundedTruncation (findings that the profile
// maps) or floorBoundedTruncated (a verdict a lane already decided). Both add
// the evaluation-limit finding (ACTION-COMPOUND-LIMIT) with the audit reason
// "bounded_truncated cap=<kinds>" in its title and evidence, so the audit
// row, the finding events and the agent notice name the cap. No new audit
// action, finding id or telemetry field.
//
// The unknown tier follows the pack (rel-1-0-6:GAP-0675): an alert in the
// default and permissive packs, a managed install's included, and a block in
// the strict pack. The truncation is a floor, not a final verdict: under
// regex_judge a call whose only basis is the limit still goes to the judge
// where one is configured (regexJudgeLocalVerdictDecisive), and the floor
// stands when the judge fails or answers lower (rel-1-0-10:GAP-0320).

// An internal bound misuse (a reader's Counter never bound with NewCounter,
// or bound to another call's Truncated) floors the call it read: the misuse
// mark is in that call's CapSet, its reason names "internal bound misuse",
// and on the trusted-action path it counts once in the parser uncertainty
// metric (no new telemetry field). The process logs each kind once.
func init() { bounded.OnMisuse(logBoundedMisuse) }

var (
	boundedMisuseLogged [3]sync.Once
	boundedMisuses      atomic.Int64
)

func logBoundedMisuse(m bounded.Misuse) {
	boundedMisuses.Add(1)
	if int(m) >= len(boundedMisuseLogged) {
		m = 0
	}
	boundedMisuseLogged[m].Do(func() {
		fmt.Fprintf(os.Stderr, "[guardrail] %s: %s; the call is judged as truncated (a reader bug: please report it)\n",
			bounded.MisuseReason, m)
	})
}

// boundedTruncatedTitle is the ship-authored title of a truncated input. The
// reason (a closed set of cap names) follows it; it carries no input text.
const boundedTruncatedTitle = "Input exceeds policy evaluation limit, judged as unknown"

// boundedTier is the tier a call of connectorName is judged in, from the one
// tier source of the hook routes: strict when the request's pack is strict or
// a member of its profile meet that enforces on the hook path is
// (shareBodyStrictTier, as the shell limit and share-body paths read it),
// else the posture of the connector's pack.
func (a *APIServer) boundedTier(ctx context.Context, connectorName string) bounded.Tier {
	if a.shareBodyStrictTier(ctx, connectorName) {
		return bounded.TierStrict
	}
	cfg := a.decisionConfig(ctx)
	if cfg == nil {
		return bounded.TierDefault
	}
	return bounded.TierOf(cfg.HookPolicyTierForConnector(connectorName))
}

// boundedTruncatedFinding is the evaluation-limit finding of an input read up
// to the caps in set. A call whose projection cannot authorize a block
// (enforcementCapable false) still alerts: a truncated input is never a
// silent allow.
func boundedTruncatedFinding(set bounded.CapSet, enforcementCapable bool) RuleFinding {
	finding := trustedActionLimitFindings(enforcementCapable)[0]
	reason := set.Reason()
	finding.Title = boundedTruncatedTitle + " (" + reason + ")"
	finding.Evidence = reason
	if !enforcementCapable {
		finding.enforcement = findingEnforcementAlertOnly
	}
	return finding
}

// withBoundedReason appends the bounded reason to an evaluation-limit
// finding the call already carries, keeping its own title (an omitted
// operand, a statement budget) and adding the cap.
func withBoundedReason(finding *RuleFinding, reason string) {
	if strings.Contains(finding.Evidence, reason) {
		return
	}
	finding.Title += " (" + reason + ")"
	if finding.Evidence == "" {
		finding.Evidence = reason
	} else {
		finding.Evidence += "; " + reason
	}
}

// boundedLimitIndex is the index of the evaluation-limit finding in
// findings, or -1.
func boundedLimitIndex(findings []RuleFinding) int {
	return slices.IndexFunc(findings, func(finding RuleFinding) bool {
		return canonicalTrustedRuleID(finding.RuleID) == evaluationLimitRuleID
	})
}

// withBoundedTruncation adds the truncation in set to the findings of what
// was read before the caps, which keep deciding on their own: the profile
// maps the result to at least the unknown tier of the pack and never below
// those findings (guardrailActionForProfile). An evaluation-limit finding the
// call already carries is kept, title included, and gains the bounded reason,
// so a call has one limit finding. The caller's slice is not changed. No cap
// hit: findings as they are, without allocation.
func withBoundedTruncation(findings []RuleFinding, set bounded.CapSet, request trustedActionRequest) []RuleFinding {
	if !set.Any() {
		return findings
	}
	if set.Misuse() && request.recordTelemetry != nil {
		request.recordTelemetry(trustedActionTelemetry{ParserUncertaintyCount: 1})
	}
	bound := boundedTruncatedFinding(set, request.EnforcementCapable)
	index := boundedLimitIndex(findings)
	if index < 0 {
		return append(slices.Clip(findings), bound)
	}
	out := slices.Clone(findings)
	existing := &out[index]
	withBoundedReason(existing, bound.Evidence)
	if !existing.contributesToEnforcement() && !existing.contributesToAlertOnly() {
		// A detection-only limit finding would leave the call allowed.
		existing.enforcement = bound.enforcement
		existing.proof = bound.proof
	}
	return out
}

// floorBoundedTruncated raises a verdict a lane decided for an input read up
// to the caps in set to bounded.Floor: at least the unknown tier of the pack,
// never below the verdict. An action name in any case is read (and written
// back in its canonical spelling); a name the floor cannot read is kept as it
// is where the floor alerts and becomes block where the floor blocks. The
// verdict carries one evaluation-limit finding whose severity agrees with
// the floor (MEDIUM and alert-only where the floor alerts, HIGH where it
// blocks). A verdict applyMode already mapped is floored on its raw action
// and mapped again, so the order of the two calls cannot drop the floor.
func (v *ToolInspectVerdict) floorBoundedTruncated(set bounded.CapSet, tier bounded.Tier) {
	if v == nil || !set.Any() {
		return
	}
	mode := v.Mode
	if mode != "" {
		// applyMode ran: floor the raw verdict, then map the mode again. A
		// verdict with a mode but no raw action (a literal an adopter built)
		// is its own raw verdict, so a block is never lowered.
		if v.RawAction != "" {
			v.Action = v.RawAction
		}
		v.WouldBlock = false
	}
	floor := bounded.Unknown(tier)
	bound := boundedTruncatedFinding(set, true)
	bound.Severity = "HIGH"
	if floor == bounded.Alert {
		bound.Severity = "MEDIUM"
		bound.enforcement = findingEnforcementAlertOnly
	}
	before, known := bounded.ParseAction(v.Action)
	after := bounded.Floor(before, set, tier)
	if known || floor == bounded.Block {
		// A name the floor cannot read is kept where the floor alerts (it may
		// name a block); where the floor blocks it becomes the block.
		v.Action = after.String()
	}
	if after > before {
		v.Reason = bound.Title
		if v.Confidence < bound.Confidence {
			v.Confidence = bound.Confidence
		}
	} else if v.Reason == "" {
		v.Reason = bound.Title
	} else {
		v.Reason += "; " + bound.Evidence
	}
	if guardrailSeverityRank(bound.Severity) > guardrailSeverityRank(v.Severity) {
		v.Severity = bound.Severity
	}
	if index := boundedLimitIndex(v.DetailedFindings); index >= 0 {
		withBoundedReason(&v.DetailedFindings[index], bound.Evidence)
		for i, finding := range v.Findings {
			if strings.HasPrefix(finding, evaluationLimitRuleID+":") && !strings.Contains(finding, bound.Evidence) {
				v.Findings[i] = finding + " (" + bound.Evidence + ")"
				break
			}
		}
	} else {
		v.Findings = append(v.Findings, bound.RuleID+":"+bound.Title)
		v.DetailedFindings = append(v.DetailedFindings, bound)
	}
	if mode != "" {
		v.applyMode(mode)
	}
}
