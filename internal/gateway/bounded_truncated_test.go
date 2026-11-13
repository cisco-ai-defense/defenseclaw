// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func boundedTestActionFor(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return guardrailActionBlock
	case "MEDIUM":
		return guardrailActionAlert
	}
	return guardrailActionAllow
}

// The gateway side of the bound rule: withBoundedTruncation, mapped by the
// profile as every hook route maps it, gives at least the unknown tier of the
// pack and never less than the findings of the part read before the cap. A
// managed install is judged by its pack (rel-1-0-10:GAP-0318).
func TestBoundedTruncationMapsToTheUnknownTier(t *testing.T) {
	keys := RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL"}
	advisory := RuleFinding{RuleID: "content.note", Severity: "MEDIUM"}
	tiers := []struct {
		name            string
		strict, managed bool
		want            bounded.Action
	}{
		{"default", false, false, bounded.Alert},
		{"strict", true, false, bounded.Block},
		{"managed default", false, true, bounded.Alert},
		{"managed strict", true, true, bounded.Block},
	}
	for _, tier := range tiers {
		request := trustedActionRequest{StrictPolicy: tier.strict, ManagedInstall: tier.managed, EnforcementCapable: true}
		strict := func() bool { return tier.strict }
		for _, seen := range [][]RuleFinding{nil, {advisory}, {keys}, trustedActionLimitFindings(true)} {
			base, _ := bounded.ParseAction(guardrailActionForProfile(seen, false, strict, boundedTestActionFor))
			for _, c := range bounded.Caps() {
				before := slices.Clone(seen)
				findings := withBoundedTruncation(seen, bounded.Of(c), request)
				if len(seen) != len(before) || (len(seen) > 0 && seen[0].Title != before[0].Title) {
					t.Fatalf("%s: the caller's findings changed", tier.name)
				}
				got, _ := bounded.ParseAction(guardrailActionForProfile(findings, false, strict, boundedTestActionFor))
				if got < tier.want || got < base {
					t.Errorf("%s cap %s seen=%v: %s, want at least %s and %s", tier.name, c, FindingStrings(seen), got, tier.want, base)
				}
				if len(seen) == 0 && got != tier.want {
					t.Errorf("%s cap %s, nothing seen: %s, want exactly %s", tier.name, c, got, tier.want)
				}
				limits := 0
				for _, f := range findings {
					if f.RuleID == evaluationLimitRuleID {
						limits++
						if !strings.Contains(f.Evidence, bounded.Of(c).Reason()) || !strings.Contains(f.Title, "cap="+c.String()) {
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
	// A projection that cannot authorize a block still alerts.
	weak := withBoundedTruncation(nil, bounded.Of(bounded.Paths), trustedActionRequest{StrictPolicy: true})
	if got := guardrailActionForProfile(weak, false, func() bool { return true }, boundedTestActionFor); got != guardrailActionAlert {
		t.Fatalf("not enforcement capable: %s, want alert", got)
	}
}

// An existing limit finding keeps its own title and gains the cap (review
// F10): the audit still says a named operand was left out.
func TestBoundedTruncationKeepsTheExistingTitle(t *testing.T) {
	omitted := withOmittedOperandLimitFinding(nil, true)
	title := omitted[0].Title
	out := withBoundedTruncation(omitted, bounded.Of(bounded.Items), trustedActionRequest{EnforcementCapable: true})
	if len(out) != 1 || !strings.HasPrefix(out[0].Title, title) || !strings.Contains(out[0].Title, "cap=items") ||
		!out[0].omittedOperand {
		t.Fatalf("existing limit finding: %+v, want title %q kept, cap=items added, omitted operand kept", out, title)
	}
	again := withBoundedTruncation(out, bounded.Of(bounded.Items), trustedActionRequest{EnforcementCapable: true})
	if again[0].Title != out[0].Title {
		t.Fatalf("the same reason was added twice: %q", again[0].Title)
	}
}

func TestFloorBoundedTruncatedVerdict(t *testing.T) {
	for _, tier := range []bounded.Tier{bounded.TierDefault, bounded.TierPermissive, bounded.TierStrict} {
		for _, action := range []string{"allow", "alert", "confirm", "block", "BLOCK", "Block", " block", "deny", "Ask"} {
			v := &ToolInspectVerdict{Action: action, Severity: "LOW", Reason: "matched: x", Findings: []string{"x"}}
			v.floorBoundedTruncated(bounded.Of(bounded.Bytes, bounded.Nodes), tier)
			base, known := bounded.ParseAction(action)
			got, _ := bounded.ParseAction(v.Action)
			if got < bounded.Unknown(tier) || got < base {
				t.Errorf("tier %d %q: %q, lowered or below the floor", tier, action, v.Action)
			}
			if !known && v.Action != action {
				t.Errorf("tier %d %q: an unreadable action was rewritten to %q", tier, action, v.Action)
			}
			if action == "allow" && got != bounded.Unknown(tier) {
				t.Errorf("tier %d allow: raised to %s, want %s", tier, v.Action, bounded.Unknown(tier))
			}
			if !strings.Contains(v.Reason, "bounded_truncated cap=bytes,nodes") || len(v.DetailedFindings) != 1 ||
				!strings.HasPrefix(v.Findings[len(v.Findings)-1], evaluationLimitRuleID+":") {
				t.Errorf("tier %d %s: reason or finding missing: %+v", tier, action, v)
			}
			// The verdict and its finding agree (review F3/R4c).
			if want := map[bounded.Action]string{bounded.Alert: "MEDIUM", bounded.Block: "HIGH"}[bounded.Unknown(tier)]; v.DetailedFindings[0].Severity != want ||
				guardrailSeverityRank(v.Severity) < guardrailSeverityRank(want) {
				t.Errorf("tier %d %s: verdict %s, finding %s, want the finding at %s", tier, action, v.Severity, v.DetailedFindings[0].Severity, want)
			}
		}
	}
	// One limit finding: an existing one gains the reason.
	v := &ToolInspectVerdict{Action: "alert", Findings: []string{evaluationLimitRuleID + ":x"},
		DetailedFindings: []RuleFinding{{RuleID: evaluationLimitRuleID, Title: "x", Severity: "MEDIUM"}}}
	v.floorBoundedTruncated(bounded.Of(bounded.Locations), bounded.TierDefault)
	if len(v.DetailedFindings) != 1 || len(v.Findings) != 1 || !strings.Contains(v.Findings[0], "cap=locations") {
		t.Fatalf("a second limit finding was added: %+v", v)
	}
}

// Run after applyMode, the floor is applied to the raw verdict and the mode
// mapped again (review P4: the order is enforced in code).
func TestFloorBoundedTruncatedAfterApplyMode(t *testing.T) {
	for _, mode := range []string{"action", "observe"} {
		before, after := &ToolInspectVerdict{Action: "allow"}, &ToolInspectVerdict{Action: "allow"}
		before.floorBoundedTruncated(bounded.Of(bounded.Paths), bounded.TierStrict)
		before.applyMode(mode)
		after.applyMode(mode)
		after.floorBoundedTruncated(bounded.Of(bounded.Paths), bounded.TierStrict)
		if before.Action != after.Action || before.RawAction != after.RawAction || before.WouldBlock != after.WouldBlock {
			t.Errorf("mode %s: floor then mode %+v, mode then floor %+v", mode, before, after)
		}
	}
}

// boundedTier is the tier of the pack, permissive included, with the one
// tier source of the hook routes: a managed install that runs the default
// pack is in the default tier (rel-1-0-6:GAP-0675, review R2/R3).
func TestBoundedTierOfTheRequest(t *testing.T) {
	for _, tc := range []struct {
		posture string
		managed bool
		want    bounded.Tier
	}{
		{"default", false, bounded.TierDefault},
		{"permissive", false, bounded.TierPermissive},
		{"strict", false, bounded.TierStrict},
		{"default", true, bounded.TierDefault},
		{"permissive", true, bounded.TierPermissive},
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
		if strict := api.shareBodyStrictTier(t.Context(), "claudecode"); strict != (tc.want == bounded.TierStrict) {
			t.Errorf("%s managed=%t: boundedTier and shareBodyStrictTier disagree (strict %t)", tc.posture, tc.managed, strict)
		}
	}
}

// The guardrail proxy maps a limit finding by the pack too: its
// secure-client argument is the Secure Client posture only (review F7).
func TestBoundedProxyPathMapsByThePack(t *testing.T) {
	SetManagedEnterpriseActive(false)
	for posture, want := range map[string]string{"default": guardrailActionAlert, "permissive": guardrailActionAlert, "strict": guardrailActionBlock} {
		gc := &config.GuardrailConfig{RulePackDir: filepath.Join(guardrailPoliciesRoot(t), posture)}
		findings := withBoundedTruncation(nil, bounded.Of(bounded.Bytes), trustedActionRequest{EnforcementCapable: true})
		if got := guardrailActionForGuardrailFindings(gc, "", findings, false); got != want {
			t.Errorf("proxy %s pack: %s, want %s", posture, got, want)
		}
	}
}

// The untruncated paths of both entry points allocate nothing (review P4).
func TestBoundedGatewayUntruncatedAllocatesNothing(t *testing.T) {
	findings := []RuleFinding{{RuleID: "x"}}
	request := trustedActionRequest{EnforcementCapable: true}
	verdict := &ToolInspectVerdict{Action: "allow"}
	if allocs := testing.AllocsPerRun(1000, func() {
		_ = withBoundedTruncation(findings, bounded.CapSet{}, request)
		verdict.floorBoundedTruncated(bounded.CapSet{}, bounded.TierDefault)
	}); allocs != 0 {
		t.Fatalf("untruncated gateway path allocated %.0f times per run", allocs)
	}
}
