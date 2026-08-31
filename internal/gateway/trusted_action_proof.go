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

package gateway

import (
	"strings"
)

// findingProofKind is a closed set of code-owned proof authorities. A rule
// pack, command string, or remote payload cannot select one of these values.
type findingProofKind uint8

const (
	findingProofNone findingProofKind = iota
	findingProofActionFactsSemantic
	findingProofExactCodeGuard
	findingProofExactFallback
	findingProofParserShadow
)

// findingProof is deliberately value-free. It records neither argv nor shell
// source, paths, URLs, prompt text, model output, or matched evidence. Exact
// pins and completeness are checked by the constructors and collapsed to the
// authority bit before the record is attached to a finding.
type findingProof struct {
	kind          findingProofKind
	ruleID        string
	authoritative bool
}

// actionFactsSemanticProofInput describes the independent conditions which
// must all hold before a CEL/ActionFacts match can authorize enforcement.
type actionFactsSemanticProofInput struct {
	FactsAuthoritative  bool
	EnforcementEligible bool
	ProjectionComplete  bool
	EvaluationComplete  bool
	Matched             bool
}

func newActionFactsSemanticFindingProof(
	ruleID string,
	input actionFactsSemanticProofInput,
) findingProof {
	return newFindingProof(
		findingProofActionFactsSemantic,
		ruleID,
		input.FactsAuthoritative &&
			input.EnforcementEligible &&
			input.ProjectionComplete &&
			input.EvaluationComplete &&
			input.Matched,
	)
}

// newExactCodeGuardFindingProof is for a code-owned exact scanner result. A
// catalog regex or a caller-supplied rule ID is not an exact CodeGuard proof.
func newExactCodeGuardFindingProof(
	ruleID string,
	trustedBoundary bool,
	scanComplete bool,
	exactUnsafeMatch bool,
) findingProof {
	return newFindingProof(
		findingProofExactCodeGuard,
		ruleID,
		trustedBoundary && scanComplete && exactUnsafeMatch,
	)
}

// newExactFallbackFindingProof is for bounded code-owned fallback parsers.
// Incomplete outer structure or a non-enforcement-eligible projection can
// retain a visible finding, but can never authorize it.
func newExactFallbackFindingProof(
	ruleID string,
	factsAuthoritative bool,
	enforcementEligible bool,
	structureComplete bool,
	exactMatch bool,
) findingProof {
	return newFindingProof(
		findingProofExactFallback,
		ruleID,
		factsAuthoritative && enforcementEligible && structureComplete && exactMatch,
	)
}

func newParserShadowFindingProof(ruleID string) findingProof {
	return newFindingProof(findingProofParserShadow, ruleID, false)
}

func newFindingProof(
	kind findingProofKind,
	ruleID string,
	authoritative bool,
) findingProof {
	normalizedRuleID := strings.TrimSpace(ruleID)
	if normalizedRuleID == "" || normalizedRuleID != ruleID {
		authoritative = false
	}
	return findingProof{
		kind:          kind,
		ruleID:        normalizedRuleID,
		authoritative: authoritative,
	}
}

func (f RuleFinding) withTrustedActionProof(proof findingProof) RuleFinding {
	f.proof = proof
	return f
}

func (p findingProof) authorizes(ruleID string) bool {
	if !p.authoritative || p.ruleID == "" || p.ruleID != ruleID {
		return false
	}
	switch p.kind {
	case findingProofActionFactsSemantic,
		findingProofExactCodeGuard,
		findingProofExactFallback:
		return true
	default:
		return false
	}
}

// applyTrustedActionProofBoundary is the final pure action-boundary gate. It
// returns an independent slice and never removes a finding. Unsupported raw
// regex, parser-shadow, PARTIAL, INVALID, and unpinned results remain visible
// as detection-only findings. Existing detection/audit findings remain so.
func applyTrustedActionProofBoundary(
	findings []RuleFinding,
	enforcementCapable bool,
) []RuleFinding {
	if len(findings) == 0 {
		return nil
	}
	gated := append([]RuleFinding(nil), findings...)
	for index := range gated {
		finding := &gated[index]
		if !enforcementCapable {
			finding.enforcement = findingEnforcementDetectionOnly
			continue
		}
		if finding.enforcement == findingEnforcementDetectionOnly {
			continue
		}
		if finding.proof.authorizes(finding.RuleID) {
			finding.enforcement = findingEnforcementAllowed
			continue
		}
		finding.enforcement = findingEnforcementDetectionOnly
	}
	return gated
}
