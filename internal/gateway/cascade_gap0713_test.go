// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"
)

// rel-1-0-10:GAP-0713. The cascade policy input holds at most
// maxCascadeInputFindings findings. A call whose verdict proved a block from
// more findings than that was an "uninspected" input (the cap) but not a
// proven block, so a policy that lowers everything took it to the unknown
// tier (alert in default and permissive) under a low policy.lowest. The
// verdict read the call in full: its block stands on every surface, pack and
// unknown setting, as it does with no policy. The same block with the
// findings the input holds is still the policy's to lower (by design), and a
// capped allow still ends at the unknown tier.
func TestGAP0713CappedFindingsKeepProvenBlock(t *testing.T) {
	many := func(n int, sev string) []RuleFinding {
		out := make([]RuleFinding, n)
		for i := range out {
			out[i] = RuleFinding{RuleID: fmt.Sprintf("COG-CLAUDE-MD-%d", i), Severity: sev}
		}
		return out
	}
	blockWith := func(n int) func() *ToolInspectVerdict {
		return func() *ToolInspectVerdict {
			v := ruleVerdict("block", "HIGH")
			v.DetailedFindings = many(n, "HIGH")
			return v
		}
	}
	rows := []struct {
		name      string
		verdict   func() *ToolInspectVerdict
		atLeast   string // the final action is at least this
		below     string // when set, the final action is below this
		provenSet bool   // truncated.proven_block of the policy input
	}{
		{name: "capped+block", verdict: blockWith(maxCascadeInputFindings + 1), atLeast: "block", provenSet: true},
		{name: "capped200+block", verdict: blockWith(200), atLeast: "block", provenSet: true},
		{name: "full+block", verdict: blockWith(maxCascadeInputFindings), below: "block"},
		{name: "capped+allow", verdict: func() *ToolInspectVerdict {
			v := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
			v.DetailedFindings = many(maxCascadeInputFindings+1, "LOW")
			return v
		}, atLeast: "alert"},
		{name: "capped+raised-block", verdict: func() *ToolInspectVerdict {
			v := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
			v.DetailedFindings = many(maxCascadeInputFindings+1, "LOW")
			v.markOversizeUninspected()
			return v
		}, atLeast: "alert"},
	}
	for _, posture := range []string{"default", "permissive", "strict"} {
		for _, unk := range []string{"", "alert", "confirm"} {
			extra := ""
			if unk != "" {
				extra = "    unknown: " + unk + "\n"
			}
			for _, lowest := range []string{"log", "allow", "alert"} {
				api := cascadeModuleConfig(t, posture, cascadeAllowAllModule, extra)
				api.scannerCfg.Guardrail.Cascade.Policy.Lowest = lowest
				for _, row := range rows {
					for _, s := range cascadeSurfaces {
						name := posture + "/unknown=" + unk + "/lowest=" + lowest + "/" + row.name + "/" + s.connector + "/" + s.surface
						v := row.verdict()
						flagged := rulesFlagged(v)
						input := api.cascadePolicyInput(t.Context(), api.scannerCfg, api.scannerCfg.ResolveCascade(s.connector),
							s.connector, s.surface, s.event, s.tool, v, flagged, "alert")
						if got := cascadeInputProvenBlock(input); got != row.provenSet {
							t.Errorf("%s: truncated.proven_block=%v, want %v", name, got, row.provenSet)
						}
						got := api.applyCascadeFinal(t.Context(), s.connector, s.surface, s.event, s.tool, row.verdict())
						if row.atLeast != "" && cascadeRank(got.Action) < cascadeRank(row.atLeast) {
							t.Errorf("%s: ended %s, want at least %s (%s)", name, got.Action, row.atLeast, got.Reason)
						}
						if row.below != "" && cascadeRank(got.Action) >= cascadeRank(row.below) {
							t.Errorf("%s: ended %s, want the policy to lower it below %s", name, got.Action, row.below)
						}
					}
				}
			}
		}
	}
}
