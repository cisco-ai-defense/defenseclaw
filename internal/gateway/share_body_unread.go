// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A hook call reads the script bodies a command runs (an explicit source,
// make, awk -f) and judges what they write. A body on a network share that
// the call budget kept unread (hookpaths.ShareBodyUnread) is unknown: it is
// neither a body that writes nothing nor a named or known protected target.
// A protected file or link the command names, directly or through a value
// the gateway knows, is blocked in every profile by the rules that name it.
// The unknown body is judged by the policy tier of the request, as any
// check the gateway could not finish is: the strict tier (and managed
// strict) keeps the evaluation-limit block, and the default and permissive
// tiers allow the call with a visible alert, so an ordinary script on a slow
// share is never refused (rel-1-0-6:GAP-0482, owner steer 11-05: false
// blocks of balanced move their protective rule to the strict profile).

type shareBodyStrictKey struct{}

// withShareBodyStrict marks ctx with how the request judges an unread share
// body: strict reports whether its policy tier is strict. It is read only
// when a body was left unread, so a hook call that reads none pays nothing
// for the tier lookup.
func withShareBodyStrict(ctx context.Context, strict func() bool) context.Context {
	return context.WithValue(ctx, shareBodyStrictKey{}, strict)
}

// shareBodyStrictFrom reports the mark of withShareBodyStrict; a context
// with none is not strict.
func shareBodyStrictFrom(ctx context.Context) bool {
	strict, _ := ctx.Value(shareBodyStrictKey{}).(func() bool)
	return strict != nil && strict()
}

// shareBodyStrictTier reports whether the request judges an unread share body
// in the strict tier: the tier of the configuration that decides the request
// (strictPolicyTierForHook), or, when proven assignments meet, the tier of any
// member that blocks on the hook path. A meet scans with each member's own rule
// pack but derives its configuration from the base pack, so the derived tier
// alone would let an enforcing strict member lose its block to a default
// member (guardrail_profile_meet.go: the final action is the strongest member
// action). A strict member that only observes contributes at most an alert,
// as everywhere else in the meet.
func (a *APIServer) shareBodyStrictTier(ctx context.Context, connectorName string) bool {
	if a == nil {
		return false
	}
	if a.strictPolicyTierForHook(ctx, connectorName) {
		return true
	}
	if a.scannerCfg != nil && a.scannerCfg.SecureClientIntegration() {
		return false
	}
	resolved := a.resolvedProfile(ctx)
	meet := resolved.evaluationMeet()
	if meet == nil {
		return false
	}
	return slices.ContainsFunc(meet.members, func(member string) bool {
		cfg := resolved.set.profileConfig(member)
		return cfg != nil && configBlocksOn(cfg, connectorName, profilePathHook) &&
			cfg.HookPolicyTierForConnector(connectorName) == config.HookPolicyTierStrict
	})
}

// shareBodyUnreadRuleID is the alert the default and permissive tiers raise
// for an unread share body. It is not the evaluation-limit rule, so a strict
// request that met the alert in a twin dispatch still adds the limit block.
const shareBodyUnreadRuleID = "ACTION-SHARE-BODY-UNREAD"

// shareBodyUnreadFindings is the verdict of a hook call that kept a script
// body on a network share unread: the evaluation-limit finding in the strict
// tier, an alert that never blocks in the others. It adds nothing to findings
// that already carry its verdict. budget and linkBound are why the body was
// left unread (hookpaths.ShareBodyUnreadCauses); they only word the alert.
func shareBodyUnreadFindings(ctx context.Context, findings []RuleFinding, enforcementCapable, budget, linkBound bool) []RuleFinding {
	has := func(ruleID string) bool {
		return slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == ruleID })
	}
	if shareBodyStrictFrom(ctx) {
		if has("ACTION-COMPOUND-LIMIT") {
			return findings
		}
		return append(findings, trustedActionLimitFindings(enforcementCapable)...)
	}
	if has("ACTION-COMPOUND-LIMIT") || has(shareBodyUnreadRuleID) {
		return findings
	}
	title := "Script on a network share was not read: the hook call opens no share on another machine, and a share of this machine did not answer within its wait"
	switch {
	case linkBound && budget:
		title = "Script was not read: a share on its path was not read within the hook call, or its path passes more links than the hook call follows"
	case linkBound:
		title = "Script was not read: its path passes more links than the hook call follows, so a network share on it may not have been asked"
	}
	return append(findings, RuleFinding{
		RuleID: shareBodyUnreadRuleID, Severity: "MEDIUM", Confidence: 1,
		Title: title,
		Proof: advisoryProof,
	})
}

// artifactUnreadRuleID is the alert the default and permissive tiers raise
// for a script a tool call runs that the artifact check left unread or
// unjudged within the hook call: no reader came free, the read did not
// finish within promotedArtifactReadLimit, or the hook budget ended
// (readPromotedArtifactBounded, promotedArtifactFindings). The script is
// unknown, as an unread share body is, and is judged the same way: the
// strict tier (and managed strict) keeps the evaluation-limit block, the
// default and permissive tiers allow the call with this visible alert, so a
// busy or loaded gateway never refuses an ordinary script and never lets a
// blocking one run unflagged (rel-1-0-10:GAP-2171).
const artifactUnreadRuleID = "ACTION-ARTIFACT-UNREAD"

// appendArtifactUnreadFindings adds the answer for an unread script to
// findings, unless they already carry it. enforcementCapable reports
// whether an unread script was a candidate that may block at this boundary;
// it bounds the strict tier's evaluation-limit block as for a read script.
func appendArtifactUnreadFindings(ctx context.Context, findings []RuleFinding, enforcementCapable bool) []RuleFinding {
	has := func(ruleID string) bool {
		return slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == ruleID })
	}
	if has("ACTION-COMPOUND-LIMIT") {
		return findings
	}
	if shareBodyStrictFrom(ctx) {
		limit := trustedActionLimitFindings(enforcementCapable)
		for index := range limit {
			limit[index].Evidence = artifactUnreadReason
			limit[index].Tags = appendUniqueStrings(limit[index].Tags, "artifact-promotion", "experimental")
		}
		return append(findings, limit...)
	}
	if has(artifactUnreadRuleID) {
		return findings
	}
	return append(findings, RuleFinding{
		RuleID: artifactUnreadRuleID, Severity: "MEDIUM", Confidence: 1,
		Title:    "Script the command runs was not read in time: the hook call could not read and check it, so it is reported unchecked",
		Evidence: artifactUnreadReason,
		Tags:     []string{"artifact-promotion", "experimental"},
		Proof:    advisoryProof,
	})
}

// artifactUnreadReason is the evidence of the answer for an unread script.
const artifactUnreadReason = "artifact_unread_in_time"
