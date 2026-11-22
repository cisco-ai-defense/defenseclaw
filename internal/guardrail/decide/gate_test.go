// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package decide

import "testing"

// TestGateRowsHoldThe1010Tiers: the two gate rows carry the tiers the 1.0.10
// readers read from request.StrictPolicy and request.ManagedInstall, and a
// gate row never matches a finding's proof.
func TestGateRowsHoldThe1010Tiers(t *testing.T) {
	for _, c := range []struct {
		row     string
		d       Deployment
		tier    Tier
		enforce bool
	}{
		{RowTieredStrict, PerUser, TierDefault, false}, {RowTieredStrict, PerUser, TierPermissive, false},
		{RowTieredStrict, PerUser, TierStrict, true}, {RowTieredStrict, Managed, TierDefault, false},
		{RowTieredStrict, Managed, TierPermissive, false}, {RowTieredStrict, Managed, TierStrict, true},
		{RowTieredManaged, PerUser, TierDefault, false}, {RowTieredManaged, PerUser, TierPermissive, false},
		{RowTieredManaged, PerUser, TierStrict, true}, {RowTieredManaged, Managed, TierDefault, true},
		{RowTieredManaged, Managed, TierPermissive, true}, {RowTieredManaged, Managed, TierStrict, true},
	} {
		got := Builtin().GateCeiling(c.row, c.d, c.tier)
		if (got == CeilingNone) != c.enforce || !c.enforce && got != CeilingAlert {
			t.Errorf("%s %s %s: ceiling %d, want enforce=%v (else alert)", c.row, c.d, c.tier, got, c.enforce)
		}
	}
	if got := Builtin().GateCeiling("no-such-row", PerUser, TierDefault); got != CeilingNone {
		t.Errorf("unknown gate row: ceiling %d, want none (fail closed)", got)
	}
	for _, p := range []Proof{{}, {Certainty: CertMaybe}, {Certainty: CertMaybe, Reach: ReachAdvisory}, {Kind: KindWrite, Target: TargetState}} {
		if row := Builtin().match(Finding{RuleID: "credential.directory_ticket_request", Proof: p}, SurfaceTool, false); row != nil && row.Gate {
			t.Errorf("proof %v matched gate row %s", p, row.ID)
		}
	}
}
