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
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

const (
	trustedActionDispatchTimeout = 50 * time.Millisecond
	trustedActionDispatchMaxCost = uint64(24_000_000)
)

// trustedActionRequest is private so a remote payload cannot assert that an
// arbitrary body is a trusted or enforcement-capable action. Only adapters
// that have already established a typed server-side boundary construct it.
type trustedActionRequest struct {
	Input              actionfacts.Input
	LegacyText         string
	Connector          string
	EnforcementCapable bool
}

func dispatchTrustedAction(
	parent context.Context,
	request trustedActionRequest,
) []RuleFinding {
	if ManagedEnterpriseActive() {
		return nil
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, trustedActionDispatchTimeout)
	defer cancel()

	generation := snapshotRulePackGeneration(request.Connector)
	options := ruleScanOptions{includeToolCallOnly: true}
	if generation == nil || len(generation.semanticRules) == 0 {
		return applyBoundaryEnforcement(
			scanRuleGeneration(generation, request.LegacyText, request.Input.Tool, options),
			request.EnforcementCapable,
		)
	}

	facts := actionfacts.Analyze(request.Input)
	if !facts.Authoritative() {
		return applyBoundaryEnforcement(
			scanRuleGeneration(generation, request.LegacyText, request.Input.Tool, options),
			request.EnforcementCapable,
		)
	}
	fullProjection, projectionCode := semantic.Project(facts)
	if projectionCode != semantic.ProjectionOK {
		return applyBoundaryEnforcement(
			scanRuleGeneration(generation, request.LegacyText, request.Input.Tool, options),
			request.EnforcementCapable,
		)
	}

	excluded := make(map[string]struct{})
	semanticFindings := make([]RuleFinding, 0, len(generation.semanticRules))
	var enforcementFacts actionfacts.Facts
	var enforcementProjection *semanticpb.Facts
	enforcementProjected := false
	var consumedCost uint64
	fallbackAllOwners := false

	for _, candidate := range generation.semanticRules {
		if ctx.Err() != nil ||
			consumedCost >= trustedActionDispatchMaxCost {
			break
		}
		if !candidate.owner.eligible(facts) {
			if candidate.owner.suppressFallback != nil &&
				candidate.owner.suppressFallback(facts) {
				excludeSemanticOwner(excluded, candidate.owner, false)
			}
			continue
		}
		result, evalCode := candidate.program.EvalBool(ctx, fullProjection)
		consumedCost += result.Cost
		if consumedCost > trustedActionDispatchMaxCost {
			break
		}
		if evalCode != semantic.EvalOK {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if !result.Matched {
			excludeSemanticOwner(excluded, candidate.owner, false)
			continue
		}

		if !enforcementProjected {
			enforcementFacts = facts.EnforcementProjection()
			enforcementProjection, projectionCode = semantic.Project(enforcementFacts)
			enforcementProjected = true
		}
		if projectionCode != semantic.ProjectionOK {
			fallbackAllOwners = true
			break
		}
		enforcementResult, enforcementCode := candidate.program.EvalBool(
			ctx,
			enforcementProjection,
		)
		consumedCost += enforcementResult.Cost
		if consumedCost > trustedActionDispatchMaxCost {
			break
		}
		if enforcementCode != semantic.EvalOK {
			if ctx.Err() != nil {
				break
			}
			continue
		}

		excludeSemanticOwner(excluded, candidate.owner, true)
		finding := RuleFinding{
			RuleID:      candidate.rule.ID,
			Title:       candidate.rule.Title,
			Severity:    candidate.rule.Severity,
			Confidence:  candidate.rule.Confidence,
			Tags:        append([]string(nil), candidate.rule.Tags...),
			enforcement: findingEnforcementAllowed,
		}
		if !request.EnforcementCapable ||
			!enforcementFacts.EnforcementEligible() ||
			!enforcementResult.Matched {
			finding.enforcement = findingEnforcementDetectionOnly
		}
		semanticFindings = append(
			semanticFindings,
			adjustConfidence(request.Input.Tool, finding),
		)
	}
	if fallbackAllOwners {
		clear(excluded)
		semanticFindings = semanticFindings[:0]
	}

	options.excludedRuleIDs = excluded
	legacyFindings := scanRuleGeneration(
		generation,
		request.LegacyText,
		request.Input.Tool,
		options,
	)
	findings := append(semanticFindings, legacyFindings...)
	return applyBoundaryEnforcement(findings, request.EnforcementCapable)
}

func excludeSemanticOwner(
	excluded map[string]struct{},
	owner semanticOwner,
	matched bool,
) {
	for _, ruleID := range owner.claimedIDs(matched) {
		excluded[ruleID] = struct{}{}
	}
}

func applyBoundaryEnforcement(
	findings []RuleFinding,
	enforcementCapable bool,
) []RuleFinding {
	if enforcementCapable {
		return findings
	}
	for index := range findings {
		findings[index].enforcement = findingEnforcementDetectionOnly
	}
	return findings
}

func enforceableRuleFindings(findings []RuleFinding) []RuleFinding {
	enforceable := make([]RuleFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.contributesToEnforcement() {
			enforceable = append(enforceable, finding)
		}
	}
	return enforceable
}

func trustedSameHostHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Clean(home)
}
