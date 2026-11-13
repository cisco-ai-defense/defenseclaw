// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// Regression tests from the independent review of s7/bounded 43cb5673ad
// (lane s7-bndrev, S7/BOUNDED-REVIEW.md, repros R1-R4; R5 is in the bounded
// package). Each failed at that head.

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// R1 (rel-1-0-10:GAP-0319): a verdict that spells block in another case, or
// names an action the floor cannot read, keeps its block.
func TestBoundedReviewR1FloorKeepsNonCanonicalBlock(t *testing.T) {
	for _, action := range []string{"BLOCK", "Block", " block", "deny"} {
		v := &ToolInspectVerdict{Action: action, Severity: "HIGH"}
		v.floorBoundedTruncated(bounded.Of(bounded.Locations), bounded.TierDefault)
		if v.Action != action && v.Action != "block" {
			t.Errorf("%q floored to %q (a block became an alert)", action, v.Action)
		}
	}
}

// R2 (rel-1-0-10:GAP-0318): a managed install with the default or permissive
// pack alerts on a truncated-only call; managed strict blocks.
func TestBoundedReviewR2ManagedDefaultPackAlerts(t *testing.T) {
	request := trustedActionRequest{ManagedInstall: true, EnforcementCapable: true}
	findings := withBoundedTruncation(nil, bounded.Of(bounded.Paths), request)
	if got := guardrailActionForProfile(findings, false, func() bool { return false }, boundedTestActionFor); got != guardrailActionAlert {
		t.Errorf("managed+default truncated-only: %s, want alert", got)
	}
	if got := guardrailActionForProfile(findings, false, func() bool { return true }, boundedTestActionFor); got != guardrailActionBlock {
		t.Errorf("managed+strict truncated-only: %s, want block", got)
	}
	api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "", "permissive")
	api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
	if tier := api.boundedTier(t.Context(), "claudecode"); bounded.Unknown(tier) != bounded.Alert {
		t.Errorf("managed+permissive pack: tier %d unknown=%s, want alert", tier, bounded.Unknown(tier))
	}
}

// R3: the permissive pack is reached as its own tier.
func TestBoundedReviewR3PermissiveTierReached(t *testing.T) {
	api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "", "permissive")
	if tier := api.boundedTier(t.Context(), "claudecode"); tier != bounded.TierPermissive {
		t.Errorf("permissive pack -> tier %d, want TierPermissive", tier)
	}
}

// R4 (rel-1-0-10:GAP-0320): a truncated-only call in the default tier is not
// decisive for regex_judge, on both entry points, and the floor's verdict
// severity agrees with its finding. A strict truncated call blocks, which is
// decisive.
func TestBoundedReviewR4TruncationDoesNotSkipTheJudge(t *testing.T) {
	request := trustedActionRequest{EnforcementCapable: true}
	findings := withBoundedTruncation(nil, bounded.Of(bounded.Paths), request)
	action := guardrailActionForProfile(findings, false, func() bool { return false }, boundedTestActionFor)
	v := &ToolInspectVerdict{Action: action, Severity: HighestSeverity(findings), DetailedFindings: findings}
	if regexJudgeLocalVerdictDecisive(nil, v) {
		t.Errorf("default tier truncated-only call (action %s) is decisive: regex_judge skips the judge", action)
	}
	if regexJudgeEscalatedCritical(nil, v) {
		t.Errorf("default tier truncated-only call is escalated: a judge outage under a closed fail mode would refuse it")
	}
	v2 := &ToolInspectVerdict{Action: "allow", Severity: "LOW"}
	v2.floorBoundedTruncated(bounded.Of(bounded.Items), bounded.TierDefault)
	if regexJudgeLocalVerdictDecisive(nil, v2) || regexJudgeEscalatedCritical(nil, v2) {
		t.Errorf("floored verdict (action %s severity %s) is decisive or escalated", v2.Action, v2.Severity)
	}
	if HighestSeverity(v2.DetailedFindings) != v2.Severity {
		t.Errorf("verdict severity %s but finding severity %s", v2.Severity, HighestSeverity(v2.DetailedFindings))
	}
	strict := &ToolInspectVerdict{Action: "allow"}
	strict.floorBoundedTruncated(bounded.Of(bounded.Items), bounded.TierStrict)
	if !regexJudgeLocalVerdictDecisive(nil, strict) {
		t.Errorf("strict floored verdict %s is not decisive", strict.Action)
	}
	// A proven CRITICAL finding beside the limit is still decisive.
	proven := append(findings, RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL"})
	if !regexJudgeLocalVerdictDecisive(nil, &ToolInspectVerdict{Action: "alert", DetailedFindings: proven}) {
		t.Error("a proven CRITICAL finding beside the limit lost its decisiveness")
	}
}
