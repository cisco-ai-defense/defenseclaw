// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The gateway side of the bound rule: withBoundedTruncation and
// floorBoundedTruncated, mapped by the profile as every hook route maps them,
// give at least the unknown tier and never less than the findings of the part
// read before the cap.
func TestBoundedTruncationMapsToTheUnknownTier(t *testing.T) {
	blockAt := func(severity string) string {
		switch severity {
		case "CRITICAL", "HIGH":
			return guardrailActionBlock
		case "MEDIUM":
			return guardrailActionAlert
		}
		return guardrailActionAllow
	}
	keys := RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL"}
	advisory := RuleFinding{RuleID: "content.note", Severity: "MEDIUM"}
	tiers := []struct {
		name            string
		strict, managed bool
	}{{"default", false, false}, {"strict", true, false}, {"managed", false, true}, {"managed strict", true, true}}
	for _, tier := range tiers {
		request := trustedActionRequest{StrictPolicy: tier.strict, ManagedInstall: tier.managed, EnforcementCapable: true}
		want := bounded.Unknown(boundedRequestTier(request))
		for _, seen := range [][]RuleFinding{nil, {advisory}, {keys}, trustedActionLimitFindings(true)} {
			base := bounded.ParseAction(guardrailActionForProfile(seen, false, func() bool { return tier.strict }, blockAt))
			for _, c := range bounded.Caps() {
				before := slices.Clone(seen)
				findings := withBoundedTruncation(seen, bounded.Of(c), request)
				if len(seen) != len(before) || (len(seen) > 0 && seen[0].Title != before[0].Title) {
					t.Fatalf("%s: the caller's findings changed", tier.name)
				}
				got := bounded.ParseAction(guardrailActionForProfile(findings, false, func() bool { return tier.strict }, blockAt))
				if got < want || got < base {
					t.Errorf("%s cap %s seen=%v: %s, want at least %s and %s", tier.name, c, FindingStrings(seen), got, want, base)
				}
				limits := 0
				for _, f := range findings {
					if f.RuleID == evaluationLimitRuleID {
						limits++
						if f.Evidence != bounded.Of(c).Reason() || !strings.Contains(f.Title, "cap="+c.String()) {
							t.Errorf("%s cap %s: reason not named: %+v", tier.name, c, f)
						}
					}
				}
				if limits != 1 {
					t.Errorf("%s cap %s: %d limit findings, want 1", tier.name, c, limits)
				}
			}
		}
	}
	// Not truncated: the findings as they are.
	if got := withBoundedTruncation([]RuleFinding{keys}, bounded.Truncated{}, trustedActionRequest{}); len(got) != 1 {
		t.Fatalf("untruncated: %v", got)
	}
	// A projection that cannot authorize a block still alerts.
	weak := withBoundedTruncation(nil, bounded.Of(bounded.Paths), trustedActionRequest{StrictPolicy: true})
	if got := guardrailActionForProfile(weak, false, func() bool { return true }, blockAt); got != guardrailActionAlert {
		t.Fatalf("not enforcement capable: %s, want alert", got)
	}
}

func TestFloorBoundedTruncatedVerdict(t *testing.T) {
	for _, tier := range []bounded.Tier{bounded.TierDefault, bounded.TierPermissive, bounded.TierStrict, bounded.TierManaged} {
		for _, action := range []string{"allow", "alert", "confirm", "block"} {
			v := &ToolInspectVerdict{Action: action, Severity: "LOW", Reason: "matched: x", Findings: []string{"x"}}
			v.floorBoundedTruncated(bounded.Of(bounded.Bytes, bounded.Nodes), tier)
			got := bounded.ParseAction(v.Action)
			if got < bounded.Unknown(tier) || got < bounded.ParseAction(action) {
				t.Errorf("tier %d %s: %s", tier, action, v.Action)
			}
			if !strings.Contains(v.Reason, "bounded_truncated cap=bytes,nodes") || len(v.DetailedFindings) != 1 ||
				!strings.HasPrefix(v.Findings[len(v.Findings)-1], evaluationLimitRuleID+":") {
				t.Errorf("tier %d %s: reason or finding missing: %+v", tier, action, v)
			}
		}
	}
	v := &ToolInspectVerdict{Action: "allow"}
	v.floorBoundedTruncated(bounded.Truncated{}, bounded.TierStrict)
	if v.Action != "allow" || len(v.Findings) != 0 {
		t.Fatalf("untruncated verdict changed: %+v", v)
	}
}

// boundedTier reads the tier a verdict-level lane floors with: the pack's
// posture, then a managed install with local rules.
func TestBoundedTierOfTheRequest(t *testing.T) {
	for _, tc := range []struct {
		posture string
		managed bool
		want    bounded.Tier
	}{
		{"default", false, bounded.TierDefault},
		{"strict", false, bounded.TierStrict},
		{"default", true, bounded.TierManaged},
		{"strict", true, bounded.TierStrict},
	} {
		api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "", tc.posture)
		if tc.managed {
			api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
		}
		if got := api.boundedTier(t.Context(), "claudecode"); got != tc.want {
			t.Errorf("%s managed=%t: tier %d, want %d", tc.posture, tc.managed, got, tc.want)
		}
	}
}

func BenchmarkWithBoundedTruncationUntruncated(b *testing.B) {
	findings := []RuleFinding{{RuleID: "x"}}
	request := trustedActionRequest{EnforcementCapable: true}
	b.ReportAllocs()
	for b.Loop() {
		_ = withBoundedTruncation(findings, bounded.Truncated{}, request)
	}
}
