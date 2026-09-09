// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package scoring

import "testing"

// TestNoSingleHostPlaneTacticReachesHigh is the calibration contract the whole
// host plane rests on. Every one of these has a legitimate explanation for an
// agent doing the job it was asked to do, and a detector that pages on one
// step gets turned off within a week. If a weight is raised past the High
// boundary this test is the deliberate gate it has to pass through.
func TestNoSingleHostPlaneTacticReachesHigh(t *testing.T) {
	t.Parallel()
	for signalID, weight := range hostPlaneWeights {
		if severity := SeverityFor(weight); severity == SeverityHigh || severity == SeverityCritical {
			t.Errorf("%s alone scores %d (%s); no single host-plane tactic may reach high",
				signalID, weight, severity)
		}
	}
}

// TestProgressionBeatsTheSumOfItsParts pins the reason the chain bonus exists.
func TestProgressionBeatsTheSumOfItsParts(t *testing.T) {
	t.Parallel()
	// Reading a credential is a lead.
	lead := Total([]Signal{{ID: "agent_credential_access", Weight: WeightCredentialAccess}})
	if got := SeverityFor(lead); got != SeverityMedium {
		t.Fatalf("a lone credential read = %d (%s), want medium", lead, got)
	}
	// Reading a credential, then minting an identity, then reaching a paste
	// site is an incident.
	chain := Total([]Signal{
		{ID: "agent_credential_access", Weight: WeightCredentialAccess},
		{ID: "agent_identity_creation", Weight: WeightIdentityCreation},
		{ID: "agent_public_exfil_surface", Weight: WeightPublicExfilSurface},
		{ID: "agent_kill_chain", Weight: WeightKillChain},
	})
	if got := SeverityFor(chain); got != SeverityCritical {
		t.Fatalf("a three-stage chain = %d (%s), want critical", chain, got)
	}
}

// TestUnattributedEgressCannotClearTheFloorAlone pins the deliberate weakness
// of a single unnamed TLS peer, and the escalation that repetition earns.
func TestUnattributedEgressCannotClearTheFloorAlone(t *testing.T) {
	t.Parallel()
	if WeightUnattributedEgress >= DefaultMinRiskToReport {
		t.Fatalf("a single unattributed peer scores %d, which clears the %d floor on its own",
			WeightUnattributedEgress, DefaultMinRiskToReport)
	}
	if WeightUnattributedEgressEscalated < DefaultMinRiskToReport {
		t.Fatalf("repeated unattributed egress scores %d, below the %d floor; a real provider "+
			"connection whose attribution keeps missing would never surface",
			WeightUnattributedEgressEscalated, DefaultMinRiskToReport)
	}
}

// TestCorroborationIsAttenuationNotSuppression pins the symmetry between
// approval-by-declaration and accounted-for-by-evidence.
func TestCorroborationIsAttenuationNotSuppression(t *testing.T) {
	t.Parallel()
	attenuated := int(float64(WeightLocalRuntimeProcess) * CorroboratedWeightScale)
	if attenuated != WeightSanctionedEgress {
		t.Fatalf("an inventoried local runtime scores %d, want %d: approved by declaration and "+
			"accounted for by evidence must read the same", attenuated, WeightSanctionedEgress)
	}
	if attenuated == 0 {
		t.Fatal("corroboration suppressed the finding entirely; it must stay in the inventory")
	}
}

// TestDisagreementEscalatesByOneBand pins that an inventory accounting for
// none of what the runtime plane sees raises rather than lowers the score.
func TestDisagreementEscalatesByOneBand(t *testing.T) {
	t.Parallel()
	base := Total([]Signal{
		{ID: "local_model_runtime", Weight: WeightLocalRuntimeProcess},
		{ID: "inference_heartbeat", Weight: WeightInferenceHeartbeat},
	})
	escalated := Total([]Signal{
		{ID: "local_model_runtime", Weight: WeightLocalRuntimeProcess},
		{ID: "inference_heartbeat", Weight: WeightInferenceHeartbeat},
		{ID: "uninventoried_local_model", Weight: WeightUninventoriedLocalModel},
	})
	if SeverityFor(base) != SeverityHigh {
		t.Fatalf("base local inference = %d (%s), want high", base, SeverityFor(base))
	}
	if SeverityFor(escalated) != SeverityCritical {
		t.Fatalf("uninventoried local inference = %d (%s), want critical",
			escalated, SeverityFor(escalated))
	}
}

func TestSeverityBands(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		score int
		want  Severity
	}{
		{0, SeverityInfo}, {14, SeverityInfo},
		{15, SeverityLow}, {29, SeverityLow},
		{30, SeverityMedium}, {49, SeverityMedium},
		{50, SeverityHigh}, {74, SeverityHigh},
		{75, SeverityCritical}, {100, SeverityCritical},
	} {
		if got := SeverityFor(test.score); got != test.want {
			t.Errorf("SeverityFor(%d) = %s, want %s", test.score, got, test.want)
		}
	}
}

func TestTotalCapsAtMaxScore(t *testing.T) {
	t.Parallel()
	// Signals are evidence, not a budget: past the cap, more evidence does not
	// make an incident more severe.
	signals := make([]Signal, 0, 8)
	for id, weight := range hostPlaneWeights {
		signals = append(signals, Signal{ID: id, Weight: weight})
	}
	if got := Total(signals); got != MaxScore {
		t.Fatalf("Total(every host-plane signal) = %d, want the %d cap", got, MaxScore)
	}
	if got := Total(nil); got != 0 {
		t.Fatalf("Total(nil) = %d, want 0", got)
	}
}

// TestConfidenceWeightingDoesNotPenaliseDirectObservation pins that a sniffed
// DNS answer keeps its full weight while an indirect guess is scaled down.
func TestConfidenceWeightingDoesNotPenaliseDirectObservation(t *testing.T) {
	t.Parallel()
	const base = 50
	for _, test := range []struct {
		name       string
		confidence float64
		want       int
	}{
		{"sniffed DNS answer", 0.95, base},
		{"certain", 1.0, base},
		{"exactly at the floor", ConfidenceFullWeightFloor, base},
		{"catalog cache hit", 0.75, 38},
		{"PTR guess", 0.6, 30},
		{"no attribution", 0, 0},
	} {
		if got := ConfidenceWeighted(base, test.confidence); got != test.want {
			t.Errorf("%s: ConfidenceWeighted(%d, %v) = %d, want %d",
				test.name, base, test.confidence, got, test.want)
		}
	}
}
