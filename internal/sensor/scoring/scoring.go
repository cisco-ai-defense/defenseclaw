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

// Package scoring turns observed signals into a scored, banded finding.
//
// Signals are additive, the sum is capped at 100, and the result is banded
// into a severity. Nothing here fires on a single weak observation, which is
// what keeps the false-positive rate liveable.
//
// The weights are a reviewed calibration, not arbitrary numbers. Two
// properties are load-bearing and are pinned by tests:
//
//   - No single host-plane tactic reaches High on its own. Every one of them
//     has a legitimate explanation for an agent doing the job it was asked to
//     do, and a detector that pages on one step is turned off within a week.
//   - The chain bonus exists because progression is worth more than the sum of
//     its parts.
package scoring

import "math"

// Severity is the band a score falls into.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Band thresholds. DefaultMinRiskToReport sits at the Medium boundary, so the
// default posture reports Medium and above.
const (
	ThresholdCritical = 75
	ThresholdHigh     = 50
	ThresholdMedium   = 30
	ThresholdLow      = 15

	// DefaultMinRiskToReport is the floor a finding must clear to be emitted.
	DefaultMinRiskToReport = 30

	// MaxScore caps the additive sum. Signals are evidence, not a budget:
	// past this point more evidence does not make an incident more severe.
	MaxScore = 100
)

// SeverityFor bands a score.
func SeverityFor(score int) Severity {
	switch {
	case score >= ThresholdCritical:
		return SeverityCritical
	case score >= ThresholdHigh:
		return SeverityHigh
	case score >= ThresholdMedium:
		return SeverityMedium
	case score >= ThresholdLow:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Plane A and B weights.
const (
	WeightInferenceHeartbeat  = 25
	WeightModelResidentMemory = 10
	WeightLocalRuntimeProcess = 30
	WeightLocalRuntimeClient  = 35

	// WeightUnattributedEgress is deliberately weak: most fleeting, unnamed
	// connections are noise, so on its own it can never clear the default
	// reporting floor.
	WeightUnattributedEgress = 12

	// WeightUnattributedEgressEscalated applies once the same process has
	// shown UnattributedEgressRepeatThreshold unnamed public TLS peers across
	// polls. Repetition is the corroboration a single sighting lacked.
	// Without this, a real provider connection whose IP attribution keeps
	// missing -- a thin SDK client hitting an address the catalog has not
	// cached -- could repeat forever and never produce a finding.
	WeightUnattributedEgressEscalated = 34

	// UnattributedEgressRepeatThreshold is the per-process repeat count at
	// which that escalation applies.
	UnattributedEgressRepeatThreshold = 3

	WeightGatewayBypass = 25

	// WeightSanctionedEgress is approved-path AI use. Deliberately
	// informational: it belongs in the inventory, but on its own it is not a
	// finding an analyst should chase.
	WeightSanctionedEgress = 15
)

// Plane C weights, all gated on agent lineage.
const (
	WeightCredentialAccess = 30
	// WeightIdentityCreation is the highest single-step weight. It converts a
	// transient foothold into durable access and, unlike the others, has
	// essentially no benign explanation once agent lineage is established.
	WeightIdentityCreation    = 45
	WeightPrivilegeEscalation = 40
	WeightPersistence         = 35
	WeightConfigPersistence   = 30
	WeightEncodedPayload      = 25
	WeightPublicExfilSurface  = 35
	WeightLocalMCPServer      = 20

	// WeightKillChain is awarded once when a session has moved through enough
	// distinct stages to be a chain rather than a coincidence.
	WeightKillChain = 25

	// KillChainMinStages is how many distinct in-order stages make a chain.
	KillChainMinStages = 3
)

// Correlation weights, applied when the inventory snapshot has something to
// say about the same subject.
const (
	// CorroboratedWeightScale halves a local-inference weight the inventory
	// independently accounts for. A halving rather than a suppression, for the
	// same reason WeightSanctionedEgress is 15 rather than 0: the finding still
	// belongs in the inventory, it just stops being something to chase. At this
	// scale a bare local-runtime process lands on exactly
	// WeightSanctionedEgress, which is the intended symmetry -- approved by
	// declaration and accounted for by evidence should read the same.
	CorroboratedWeightScale = 0.5

	// WeightUninventoriedLocalModel is added when a fresh inventory accounts
	// for none of what the runtime plane is watching.
	//
	// This is the disagreement case, and it is the more interesting reading.
	// The model_file detector walks the filesystem; sustained inference on a
	// host where that walk found no model artifact means the weights are not
	// somewhere a scanner can see them. Sized to move a corroboratable finding
	// up one band rather than to dominate it: the underlying observation is
	// still the local-inference evidence, and this only says nothing else
	// explains it.
	WeightUninventoriedLocalModel = 20

	// WeightUninventoriedMCPServer is the mirror of the above, and the reason
	// the MCP match is worth making at all. A declared MCP server is ordinary;
	// one that appears in no configuration discovery can find is the opposite,
	// because an MCP server is how an agent reaches the filesystem, a database,
	// or a cloud API.
	WeightUninventoriedMCPServer = 25
)

// ConfidenceFullWeightFloor is the attribution confidence at or above which a
// category-matched egress weight is applied in full.
//
// A DNS-sniffed answer (0.95) is a direct observation of what the process
// actually resolved, not an inference, so rounding must not cost it severity.
// Only genuinely indirect attribution -- a catalog-cache hit (0.75) or a PTR
// guess (0.6), either of which can point at a stale or shared address -- falls
// below this floor and is scaled down.
const ConfidenceFullWeightFloor = 0.9

// ConfidenceWeighted scales a category weight by attribution confidence.
func ConfidenceWeighted(baseWeight int, confidence float64) int {
	if confidence >= ConfidenceFullWeightFloor {
		return baseWeight
	}
	if confidence <= 0 {
		return 0
	}
	return int(math.Round(float64(baseWeight) * confidence))
}

// hostPlaneWeights is every Plane C signal weight, keyed by signal id.
var hostPlaneWeights = map[string]int{
	"agent_credential_access":    WeightCredentialAccess,
	"agent_identity_creation":    WeightIdentityCreation,
	"agent_privilege_escalation": WeightPrivilegeEscalation,
	"agent_persistence":          WeightPersistence,
	"agent_config_persistence":   WeightConfigPersistence,
	"agent_encoded_payload":      WeightEncodedPayload,
	"agent_public_exfil_surface": WeightPublicExfilSurface,
	"agent_local_mcp_server":     WeightLocalMCPServer,
}

// HostPlaneWeight returns the base weight for a Plane C signal id.
func HostPlaneWeight(signalID string) (int, bool) {
	weight, ok := hostPlaneWeights[signalID]
	return weight, ok
}

// Signal is one weighted observation contributing to a finding.
type Signal struct {
	ID     string
	Title  string
	Detail string
	Weight int
}

// Total sums signals and caps at MaxScore.
func Total(signals []Signal) int {
	sum := 0
	for _, signal := range signals {
		sum += signal.Weight
	}
	if sum > MaxScore {
		return MaxScore
	}
	if sum < 0 {
		return 0
	}
	return sum
}
