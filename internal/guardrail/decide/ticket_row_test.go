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

import (
	"slices"
	"testing"
)

// TestTicketRequestRowAsksInDefault (rel-1-0-10:GAP-0067, GAP-0017): the
// ticket-request rule is one rule row of the tier table. The default tier
// confirms it, per-user and managed alike, where the caller can ask, and
// alerts where it cannot; strict blocks it by its HIGH severity and
// permissive alerts. The confirm is a floor's alone (FloorConfirm), so a
// hook that cannot ask turns it into an alert, not a block. A ticket finding
// a reader only recorded or advised keeps that cell, Secure Client keeps the
// levels, and no other rule gets the floor.
func TestTicketRequestRowAsksInDefault(t *testing.T) {
	const ticket = "credential.directory_ticket_request"
	finding := Finding{RuleID: ticket, Severity: SevHigh}
	for _, tc := range []struct {
		name        string
		finding     Finding
		deployment  Deployment
		tier        Tier
		confirmable bool
		secure      bool
		levels      Levels
		want        Action
		floor       bool
	}{
		{"per-user default", finding, PerUser, TierDefault, true, false, TierLevels(TierDefault), Confirm, true},
		{"managed default", finding, Managed, TierDefault, true, false, TierLevels(TierDefault), Confirm, true},
		{"per-user default cannot ask", finding, PerUser, TierDefault, false, false, TierLevels(TierDefault), Alert, false},
		{"upper-case rule id", Finding{RuleID: "CREDENTIAL.DIRECTORY_TICKET_REQUEST", Severity: SevHigh}, PerUser, TierDefault, true, false, TierLevels(TierDefault), Confirm, true},
		{"strict", finding, PerUser, TierStrict, true, false, TierLevels(TierStrict), Block, false},
		{"managed strict", finding, Managed, TierStrict, true, false, TierLevels(TierStrict), Block, false},
		{"permissive", finding, PerUser, TierPermissive, true, false, TierLevels(TierPermissive), Alert, false},
		{"default with the ask armed: the levels confirm", finding, PerUser, TierDefault, true, false,
			Levels{Block: SevCritical, Alert: SevMedium, Confirm: true, ConfirmAt: SevHigh}, Confirm, false},
		{"default, block_at HIGH: the levels block", finding, PerUser, TierDefault, true, false,
			Levels{Block: SevHigh, Alert: SevMedium, ConfirmAt: SevHigh}, Block, false},
		{"secure client: the levels", finding, PerUser, TierDefault, true, true, TierLevels(TierDefault), Alert, false},
		{"recorded ticket finding", Finding{RuleID: ticket, Severity: SevHigh, Proof: Proof{Certainty: CertMaybe}}, PerUser, TierDefault, true, false, TierLevels(TierDefault), Allow, false},
		{"advised ticket finding", Finding{RuleID: ticket, Severity: SevHigh, Proof: Proof{Certainty: CertMaybe, Reach: ReachAdvisory}}, PerUser, TierDefault, true, false, TierLevels(TierDefault), Alert, false},
		{"another HIGH rule", Finding{RuleID: "credential.directory_credential_acquisition", Severity: SevHigh}, PerUser, TierDefault, true, false, TierLevels(TierDefault), Alert, false},
	} {
		tier := tc.tier
		out := Decide(Input{
			Findings: []Finding{tc.finding}, Deployment: tc.deployment, SecureClient: tc.secure,
			Confirmable: tc.confirmable, Levels: tc.levels, Tier: func() Tier { return tier },
		})
		if out.Action != tc.want || out.FloorConfirm != tc.floor {
			t.Errorf("%s: action %v floor-confirm %v, want %v %v", tc.name, out.Action, out.FloorConfirm, tc.want, tc.floor)
		}
		if tc.want != Allow && !slices.Contains(out.RuleIDs, tc.finding.RuleID) {
			t.Errorf("%s: rules %v do not name %s", tc.name, out.RuleIDs, tc.finding.RuleID)
		}
	}
	// guardrail.cascade.unknown confirm is the operator's: it confirms
	// whether or not the caller can ask, and keeps the hook's own fallback.
	for _, confirmable := range []bool{false, true} {
		out := Decide(Input{
			Findings:    []Finding{finding, {RuleID: "ACTION-COMPOUND-LIMIT", Severity: SevLow, Proof: Proof{Kind: KindTruncated, Certainty: CertBound}}},
			Confirmable: confirmable, Levels: TierLevels(TierDefault), Tier: func() Tier { return TierDefault },
			Unknown: func() (Action, bool) { return Confirm, true },
		})
		if out.Action != Confirm || out.FloorConfirm {
			t.Errorf("ticket + unknown confirm, confirmable %v: %v floor-confirm %v, want confirm, not a floor confirm", confirmable, out.Action, out.FloorConfirm)
		}
	}
	// A block among the findings stands over the confirm floor.
	out := Decide(Input{
		Findings:    []Finding{finding, {RuleID: "CMD-CRIT", Severity: SevCritical}},
		Confirmable: true, Levels: TierLevels(TierDefault), Tier: func() Tier { return TierDefault },
	})
	if out.Action != Block || out.FloorConfirm {
		t.Errorf("ticket + CRITICAL: %v floor-confirm %v, want block", out.Action, out.FloorConfirm)
	}
}
