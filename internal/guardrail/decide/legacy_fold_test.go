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

// DET111 ruling A: a known effects-lane finding takes the tier of the
// 1.0.10 rule naming the same protected set in the call.
func TestFoldsIntoLegacy(t *testing.T) {
	effect := func(p Proof) Finding {
		p.Source = SourceEffects
		return Finding{RuleID: "effect.protected_target_restricted", Severity: SevCritical, Proof: p}
	}
	knownWrite := func(target TargetClass) Proof {
		return Proof{Kind: KindWrite, Target: target, Certainty: CertKnown}
	}
	legacy := func(id string, sev Severity) Finding { return Finding{RuleID: id, Severity: sev} }
	knownProtected := func(p Proof) Finding {
		p.Source = SourceEffects
		return Finding{RuleID: RuleFor(p), Severity: SevHigh, Proof: p}
	}
	stateLegacy := Finding{RuleID: "tamper.detector_state_write", Severity: SevLow,
		Proof: Proof{Kind: KindWrite, Target: TargetState, Certainty: CertKnown, Source: "gateway:TAMPER.DETECTOR_STATE_WRITE"}}
	cases := []struct {
		name string
		f    Finding
		call []Finding
		want bool
	}{
		{"npmrc write beside PATH-NPMRC", effect(knownWrite(TargetCredential)), []Finding{legacy("PATH-NPMRC", SevMedium)}, true},
		{"advisory npmrc write beside PATH-NPMRC", effect(knownWrite(TargetCredential).Advise()), []Finding{legacy("PATH-NPMRC", SevMedium)}, true},
		{"state delete beside tamper.detector_state_write", effect(Proof{Kind: KindDelete, Target: TargetState, Certainty: CertKnown}), []Finding{stateLegacy}, true},
		{"keys append beside persistence.ssh_authorized_keys_command", effect(Proof{Kind: KindAppend, Target: TargetAuthorizedKeys, Certainty: CertKnown}),
			[]Finding{legacy("persistence.ssh_authorized_keys_command", SevCritical)}, true},
		{"other home key read beside PATH-SSH-KEY", effect(Proof{Kind: KindRead, Target: TargetOtherHomeCredential, Certainty: CertKnown, Set: SetSSHPrivateKey}),
			[]Finding{legacy("PATH-SSH-KEY", SevCritical)}, true},
		// a spelling only the effect lane resolves: no 1.0.10 finding names the set
		{"variant with no legacy finding stands", effect(knownWrite(TargetCredential)), []Finding{legacy("SOME-OTHER-RULE", SevHigh)}, false},
		{"variant alone stands", effect(knownWrite(TargetAuthorizedKeys)), nil, false},
		// the legacy rule names another set
		{"keys write beside PATH-NPMRC stands", effect(knownWrite(TargetAuthorizedKeys)), []Finding{legacy("PATH-NPMRC", SevMedium)}, false},
		{"state write beside PATH-NPMRC stands", effect(knownWrite(TargetState)), []Finding{legacy("PATH-NPMRC", SevMedium)}, false},
		{"key read beside PATH-NPMRC stands (file class differs)", effect(Proof{Kind: KindRead, Target: TargetCredential, Certainty: CertKnown, Set: SetSSHPrivateKey}),
			[]Finding{legacy("PATH-NPMRC", SevMedium)}, false},
		// only a known effect folds; a reach or a record is not the lane's grade of the set
		{"maybe effect does not fold", effect(Proof{Kind: KindWrite, Target: TargetCredential, Certainty: CertMaybe, Reach: ReachName}), []Finding{legacy("PATH-NPMRC", SevMedium)}, false},
		{"recorded effect does not fold", effect(knownWrite(TargetCredential).Record()), []Finding{legacy("PATH-NPMRC", SevMedium)}, false},
		// only the effect lane folds: a 1.0.10 reader never loses its finding
		{"legacy reader finding never folds", Finding{RuleID: "PATH-SSH-DIR", Severity: SevHigh, Proof: Proof{Kind: KindWrite, Target: TargetCredential, Certainty: CertKnown, Source: "gateway:PATH-SSH-DIR"}},
			[]Finding{legacy("PATH-NPMRC", SevMedium)}, false},
		// another effect finding is not a 1.0.10 rule naming the set
		{"effect beside an effect", effect(knownWrite(TargetState)), []Finding{{RuleID: "tamper.detector_state_write", Proof: Proof{Source: SourceEffects}}}, false},
		// a Known protected write finding is an effects-lane finding: the
		// effect lane raise beside it stands (R-NOLOSS); it still folds into a
		// 1.0.10 finding naming its set
		{"effect beside a known hook config write stands", effect(knownWrite(TargetHookConfig)), []Finding{knownProtected(knownWrite(TargetHookConfig))}, false},
		{"known state write beside its legacy finding folds", knownProtected(knownWrite(TargetState)), []Finding{stateLegacy}, true},
	}
	for _, c := range cases {
		if got := FoldsIntoLegacy(c.f, c.call); got != c.want {
			t.Errorf("%s: FoldsIntoLegacy = %v, want %v", c.name, got, c.want)
		}
	}
}
