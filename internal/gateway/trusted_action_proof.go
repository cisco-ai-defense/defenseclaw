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

	"github.com/defenseclaw/defenseclaw/internal/asrruntime"
)

// findingProofKind is a closed set of code-owned proof authorities. A rule
// pack, command string, or remote payload cannot select one of these values.
type findingProofKind uint8

const (
	findingProofNone findingProofKind = iota
	findingProofActionFactsSemantic
	findingProofExactCodeGuard
	findingProofExactFallback
	findingProofASR
	findingProofRepositoryPolicy
	findingProofJudge
	findingProofParserShadow
)

// findingProof is deliberately value-free. It records neither argv nor shell
// source, paths, URLs, prompt text, model output, or matched evidence. Exact
// pins and completeness are checked by the constructors and collapsed to the
// authority bit before the record is attached to a finding.
type findingProof struct {
	kind            findingProofKind
	ruleID          string
	authoritative   bool
	promoteAdvisory bool
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
		false,
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
		false,
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
		false,
	)
}

// actionSemanticsProofInput contains the value-free authority signals around
// one ASR evaluation. Result.Semantics is never retained in findingProof.
type actionSemanticsProofInput struct {
	CandidateAuthoritative bool
	Correlated             bool
	SemanticsMatched       bool
	Result                 asrruntime.Result
	RuntimePins            asrruntime.Pins
	RuntimeCanAuthorize    bool
}

func newActionSemanticsFindingProof(
	ruleID string,
	input actionSemanticsProofInput,
) findingProof {
	return newActionSemanticsFindingProofForPins(
		ruleID,
		input,
		pinnedActionSemanticsProofPins(),
		asrruntime.PinnedParityAttested,
	)
}

func newActionSemanticsFindingProofForPins(
	ruleID string,
	input actionSemanticsProofInput,
	expectedPins asrruntime.Pins,
	parityAttested bool,
) findingProof {
	authoritative := input.CandidateAuthoritative &&
		input.Correlated &&
		input.SemanticsMatched &&
		input.Result.Status == asrruntime.StatusComplete &&
		input.Result.Authoritative &&
		input.RuntimeCanAuthorize &&
		parityAttested &&
		completeActionSemanticsPins(expectedPins) &&
		input.RuntimePins == expectedPins &&
		input.Result.Pins == input.RuntimePins
	return newFindingProof(findingProofASR, ruleID, authoritative, false)
}

func pinnedActionSemanticsProofPins() asrruntime.Pins {
	return asrruntime.Pins{
		SchemaVersion:          asrruntime.PinnedSchemaVersion,
		CatalogVersion:         asrruntime.PinnedCatalogVersion,
		CatalogDigest:          asrruntime.PinnedCatalogDigest,
		EvaluatorABI:           asrruntime.PinnedEvaluatorABI,
		SemanticContractDigest: asrruntime.PinnedSemanticContractDigest,
		ConformanceDigest:      asrruntime.PinnedConformanceDigest,
	}
}

func completeActionSemanticsPins(pins asrruntime.Pins) bool {
	return nonemptyProofToken(pins.SchemaVersion) &&
		nonemptyProofToken(pins.CatalogVersion) &&
		nonemptyProofToken(pins.CatalogDigest) &&
		nonemptyProofToken(pins.EvaluatorABI) &&
		nonemptyProofToken(pins.SemanticContractDigest) &&
		nonemptyProofToken(pins.ConformanceDigest)
}

func nonemptyProofToken(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

// newRepositoryPolicyFindingProof is the only constructor which may promote
// a shipped advisory. The active repository policy must be authoritative,
// match the current repository scope, and explicitly forbid this exact rule.
// The allowlist is intentionally limited to the two advisory Git behaviors.
func newRepositoryPolicyFindingProof(
	ruleID string,
	policyAuthoritative bool,
	repositoryScopeMatched bool,
	explicitlyForbidden bool,
) findingProof {
	authoritative := trustedRepositoryAdvisoryRule(ruleID) &&
		policyAuthoritative && repositoryScopeMatched && explicitlyForbidden
	return newFindingProof(
		findingProofRepositoryPolicy,
		ruleID,
		authoritative,
		authoritative,
	)
}

func trustedRepositoryAdvisoryRule(ruleID string) bool {
	switch ruleID {
	case "integrity.git_hooks_bypass", "source.git_remote_tamper":
		return true
	default:
		return false
	}
}

// newJudgeFindingProof is reserved for an authenticated, complete judge lane
// which returned an explicit deny. Incomplete, advisory, or unauthenticated
// judge results remain visible but non-authoritative.
func newJudgeFindingProof(
	ruleID string,
	authenticated bool,
	evaluationComplete bool,
	explicitDeny bool,
) findingProof {
	return newFindingProof(
		findingProofJudge,
		ruleID,
		authenticated && evaluationComplete && explicitDeny,
		false,
	)
}

func newParserShadowFindingProof(ruleID string) findingProof {
	return newFindingProof(findingProofParserShadow, ruleID, false, false)
}

func newFindingProof(
	kind findingProofKind,
	ruleID string,
	authoritative bool,
	promoteAdvisory bool,
) findingProof {
	if ruleID == "" || strings.TrimSpace(ruleID) != ruleID {
		authoritative = false
		promoteAdvisory = false
	}
	return findingProof{
		kind:            kind,
		ruleID:          ruleID,
		authoritative:   authoritative,
		promoteAdvisory: promoteAdvisory,
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
		findingProofExactFallback,
		findingProofASR,
		findingProofRepositoryPolicy,
		findingProofJudge:
		return true
	default:
		return false
	}
}

func (p findingProof) authorizesAdvisoryPromotion(ruleID string) bool {
	return p.kind == findingProofRepositoryPolicy &&
		p.promoteAdvisory &&
		trustedRepositoryAdvisoryRule(ruleID) &&
		p.authorizes(ruleID)
}

// applyTrustedActionProofBoundary is the final pure action-boundary gate. It
// returns an independent slice and never removes a finding. Unsupported raw
// regex, parser-shadow, PARTIAL, INVALID, and unpinned results remain visible
// as detection-only findings. Existing detection/audit findings remain so;
// only an exact active repository policy may promote a shipped Git advisory.
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
			if finding.proof.authorizesAdvisoryPromotion(finding.RuleID) {
				finding.enforcement = findingEnforcementAllowed
			}
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
