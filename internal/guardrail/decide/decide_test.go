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
	"reflect"
	"slices"
	"strings"
	"testing"
)

func tierFn(t Tier) func() Tier { return func() Tier { return t } }

var (
	stateWrite = Proof{Kind: KindWrite, Target: TargetState, Certainty: CertKnown, Source: "test"}
	keysWrite  = Proof{Kind: KindWrite, Target: TargetAuthorizedKeys, Certainty: CertKnown, Source: "test"}
	truncated  = Proof{Kind: KindTruncated, Certainty: CertBound, Cap: "statements", Source: "test"}
	fault      = Proof{Kind: KindUnread, Certainty: CertBound, Cap: "parser_fault", Source: "test"}
	unverified = Proof{Kind: KindRead, Target: TargetOther, Certainty: CertMaybe, Reach: ReachFS, Source: "test"}
)

func TestDecideRows(t *testing.T) {
	cases := []struct {
		name       string
		findings   []Finding
		tier       Tier
		deployment Deployment
		surface    Surface
		secure     bool
		unknown    Action
		unknownSet bool
		want       Action
		wantRules  []string
	}{
		{name: "no findings", want: Allow},
		{name: "severity only maps by levels", findings: []Finding{{RuleID: "R", Severity: SevHigh}}, want: Alert, wantRules: []string{"R"}},
		{name: "critical blocks default", findings: []Finding{{RuleID: "R", Severity: SevCritical}}, want: Block, wantRules: []string{"R"}},
		{name: "alert ceiling caps a critical", findings: []Finding{{RuleID: "R", Severity: SevCritical, Proof: Proof{}.Advise()}}, want: Alert, wantRules: []string{"R"}},
		{name: "record ceiling never moves", findings: []Finding{{RuleID: "R", Severity: SevCritical, Proof: Proof{}.Record()}}, want: Allow},
		{name: "state write low severity floors alert", findings: []Finding{{RuleID: RuleStateWrite, Severity: SevLow, Proof: stateWrite}}, want: Alert, wantRules: []string{RuleStateWrite}},
		{name: "state write strict blocks", tier: TierStrict, findings: []Finding{{RuleID: RuleStateWrite, Severity: SevLow, Proof: stateWrite}}, want: Block, wantRules: []string{RuleStateWrite}},
		{name: "state write alert ceiling sets no floor", findings: []Finding{{RuleID: RuleStateWrite, Severity: SevLow, Proof: stateWrite.Advise()}}, want: Allow},
		{name: "keys write floors alert in permissive", tier: TierPermissive, findings: []Finding{{RuleID: RuleAuthorizedKeysWrite, Severity: SevMedium, Proof: keysWrite}}, want: Alert, wantRules: []string{RuleAuthorizedKeysWrite}},
		{name: "fault blocks permissive", tier: TierPermissive, findings: []Finding{{RuleID: "F", Severity: SevLow, Proof: fault}}, want: Block, wantRules: []string{"F"}},
		{name: "truncated alone alerts default", findings: []Finding{{RuleID: RuleEvaluationLimit, Severity: SevCritical, Proof: truncated}}, want: Alert, wantRules: []string{RuleEvaluationLimit}},
		{name: "truncated strict maps by levels", tier: TierStrict, findings: []Finding{{RuleID: RuleEvaluationLimit, Severity: SevCritical, Proof: truncated}}, want: Block, wantRules: []string{RuleEvaluationLimit}},
		{name: "truncated beside a proven block", findings: []Finding{{RuleID: RuleEvaluationLimit, Severity: SevCritical, Proof: truncated}, {RuleID: "K", Severity: SevCritical}}, want: Block, wantRules: []string{"K"}},
		{name: "cascade unknown block", unknown: Block, unknownSet: true, findings: []Finding{{RuleID: RuleEvaluationLimit, Severity: SevMedium, Proof: truncated}}, want: Block, wantRules: []string{RuleEvaluationLimit}},
		{name: "cascade unknown alert in strict", tier: TierStrict, unknown: Alert, unknownSet: true, findings: []Finding{{RuleID: RuleEvaluationLimit, Severity: SevCritical, Proof: truncated}}, want: Alert, wantRules: []string{RuleEvaluationLimit}},
		{name: "secure client: truncated maps by levels", secure: true, findings: []Finding{{RuleID: RuleEvaluationLimit, Severity: SevCritical, Proof: truncated}}, want: Block, wantRules: []string{RuleEvaluationLimit}},
		{name: "secure client: no state floor", secure: true, findings: []Finding{{RuleID: RuleStateWrite, Severity: SevLow, Proof: stateWrite}}, want: Allow},
		{name: "managed unverified blocks", deployment: Managed, findings: []Finding{{RuleID: "TOOL-PATH-UNVERIFIED", Severity: SevMedium, Proof: unverified}}, want: Block, wantRules: []string{"TOOL-PATH-UNVERIFIED"}},
		{name: "managed unverified blocks on content under secure client", deployment: Managed, secure: true, surface: SurfaceContent, findings: []Finding{{RuleID: "TOOL-PATH-UNVERIFIED", Severity: SevMedium, Proof: unverified}}, want: Block, wantRules: []string{"TOOL-PATH-UNVERIFIED"}},
		{name: "per-user unverified maps by levels", findings: []Finding{{RuleID: "TOOL-PATH-UNVERIFIED", Severity: SevMedium, Proof: unverified}}, want: Alert, wantRules: []string{"TOOL-PATH-UNVERIFIED"}},
		{name: "content surface: no state floor", surface: SurfaceContent, findings: []Finding{{RuleID: RuleStateWrite, Severity: SevLow, Proof: stateWrite}}, want: Allow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := Input{
				Findings: tc.findings, Surface: tc.surface, Deployment: tc.deployment, SecureClient: tc.secure,
				Levels: TierLevels(tc.tier), Tier: tierFn(tc.tier),
				Unknown: func() (Action, bool) { return tc.unknown, tc.unknownSet },
			}
			got := Decide(in)
			if got.Action != tc.want {
				t.Fatalf("action = %v, want %v", got.Action, tc.want)
			}
			if !slices.Equal(got.RuleIDs, tc.wantRules) {
				t.Fatalf("rules = %v, want %v", got.RuleIDs, tc.wantRules)
			}
		})
	}
}

// The tier is read only for a row whose cells differ by tier, and once.
func TestDecideReadsTierLazily(t *testing.T) {
	reads := 0
	tier := func() Tier { reads++; return TierStrict }
	Decide(Input{Findings: []Finding{{Severity: SevHigh}, {Severity: SevLow, Proof: fault}}, Levels: TierLevels(TierDefault), Tier: tier})
	if reads != 0 {
		t.Fatalf("tier read %d times for findings that need no tier", reads)
	}
	Decide(Input{Findings: []Finding{{Severity: SevLow, Proof: stateWrite}, {Severity: SevLow, Proof: stateWrite}}, Levels: TierLevels(TierDefault), Tier: tier})
	if reads != 1 {
		t.Fatalf("tier read %d times, want 1", reads)
	}
}

func TestLevels(t *testing.T) {
	l := Levels{Block: SevCritical, Alert: SevMedium, Confirm: true, ConfirmAt: SevHigh}
	for sev, want := range map[Severity]Action{SevNone: Allow, SevLow: Allow, SevMedium: Alert, SevHigh: Confirm, SevCritical: Block} {
		if got := l.ActionFor(sev); got != want {
			t.Errorf("ActionFor(%v) = %v, want %v", sev, got, want)
		}
	}
}

func TestColumnRoundTrip(t *testing.T) {
	for _, tier := range []Tier{TierDefault, TierPermissive, TierStrict} {
		data, err := MarshalColumn(Builtin().ColumnOf(tier))
		if err != nil {
			t.Fatal(err)
		}
		col, err := ParseColumn(data)
		if err != nil {
			t.Fatalf("%v: %v\n%s", tier, err, data)
		}
		if col.Tier != tier {
			t.Fatalf("tier = %v, want %v", col.Tier, tier)
		}
		if got := Builtin().WithColumn(col); !reflect.DeepEqual(got.Rows, Builtin().Rows) {
			t.Fatalf("%v column does not round-trip", tier)
		}
	}
}

func TestParseColumnRejects(t *testing.T) {
	for name, text := range map[string]string{
		"version":       "version: 2\ntier: default\n",
		"tier by name":  "version: 1\ntier: strict-old\n",
		"unknown row":   "version: 1\ntier: default\nrows:\n  - id: nope\n    per_user: {floor: alert}\n    managed: {floor: alert}\n",
		"twice":         "version: 1\ntier: default\nrows:\n  - id: truncated\n    per_user: {floor: alert, levels: false}\n    managed: {floor: alert, levels: false}\n  - id: truncated\n    per_user: {floor: alert, levels: false}\n    managed: {floor: alert, levels: false}\n",
		"bad floor":     "version: 1\ntier: default\nrows:\n  - id: truncated\n    per_user: {floor: deny-ish}\n    managed: {floor: alert}\n",
		"silent allow":  "version: 1\ntier: default\nrows:\n  - id: truncated\n    per_user: {floor: allow, levels: false}\n    managed: {floor: alert}\n",
		"bad severity":  "version: 1\ntier: default\nrows:\n  - id: truncated\n    per_user: {floor: alert, severity: HUGE}\n    managed: {floor: alert}\n",
		"unknown field": "version: 1\ntier: default\nposture: strict\n",
	} {
		if _, err := ParseColumn([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "tiers.yaml") {
			t.Errorf("%s: error %q does not name tiers.yaml", name, err)
		}
	}
}

func TestRuleFor(t *testing.T) {
	if got := RuleFor(stateWrite); got != RuleStateWrite {
		t.Fatalf("state write names %q", got)
	}
	if got := RuleFor(keysWrite); got != RuleAuthorizedKeysWrite {
		t.Fatalf("keys write names %q", got)
	}
	if got := RuleFor(Proof{Kind: KindRead, Target: TargetState}); got != "" {
		t.Fatalf("state read names %q", got)
	}
	if got := RuleFor(Proof{Kind: KindWrite, Target: TargetState, Certainty: CertMaybe, Reach: ReachName}); got != "" {
		t.Fatalf("maybe state write names %q", got)
	}
}

func TestProofString(t *testing.T) {
	for p, want := range map[Proof]string{
		stateWrite: "write/state/known",
		truncated:  "truncated/none/bound(statements)",
		unverified: "read/other/maybe(R-FS)",
	} {
		if got := p.String(); got != want {
			t.Errorf("%#v = %q, want %q", p, got, want)
		}
	}
	for k := KindUnspecified; k < kindCount; k++ {
		if got, ok := ParseKind(k.String()); !ok || got != k {
			t.Errorf("ParseKind(%q) = %v %v", k, got, ok)
		}
	}
	for c := TargetNone; c < targetCount; c++ {
		if got, ok := ParseTarget(c.String()); !ok || got != c {
			t.Errorf("ParseTarget(%q) = %v %v", c, got, ok)
		}
	}
}
