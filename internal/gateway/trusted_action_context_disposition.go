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
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// applyTrustedActionContextDisposition is the trusted-action-only disposition
// boundary for content literals and selected advisory rules. It deliberately
// is not called by prompt, tool-result, or completion scanners: those scan
// untrusted content at a different boundary and retain their existing policy.
//
// The function returns an owned findings slice and never promotes a finding
// that an earlier boundary already marked detection-only. Its only authority
// input is ActionFacts derived from the current action.
func applyTrustedActionContextDisposition(
	generation *compiledRulePackCategories,
	facts actionfacts.Facts,
	findings []RuleFinding,
) []RuleFinding {
	adjusted := append([]RuleFinding(nil), findings...)
	// Detection sees the complete action, while authorization considers only
	// commands and redirects statically proven to execute. A harmless preview
	// sibling must not erase proof for an independent executing mutation.
	enforcementFacts := facts.EnforcementProjection()
	for index := range adjusted {
		finding := adjusted[index]

		if trustedActionSensitivePathRule(finding.RuleID) {
			switch trustedActionClassifySensitivePathRisk(enforcementFacts, finding.RuleID) {
			case trustedActionSensitivePathUncertain:
				// Preserve the finding's original severity so parser coverage
				// uncertainty remains visible, but never let incomplete facts
				// authorize enforcement.
				finding.enforcement = findingEnforcementDetectionOnly
			case trustedActionSensitivePathMutation,
				trustedActionSensitivePathReadEgress:
				// A typed mutation or read-to-external-network flow remains a
				// security finding. Do not promote a finding that another
				// boundary already made detection-only.
				finding = finding.withTrustedActionProof(
					trustedActionContextFindingProof(finding.RuleID, enforcementFacts),
				)
			case trustedActionSensitivePathRead:
				finding = trustedActionAdvisoryFinding(finding)
			default:
				// A path-shaped string without a matching, command-owned path
				// fact is a harmless reference, not a filesystem action.
				finding = trustedActionAuditFinding(finding)
			}
			adjusted[index] = finding
			continue
		}

		if trustedActionShippedGitAdvisoryRule(
			generation,
			finding.RuleID,
		) {
			// Shipped git remote changes and hook-bypass switches are useful
			// advisory evidence, but repositories legitimately use both. A
			// custom rule retains its original enforcement disposition.
			finding = trustedActionAdvisoryFinding(finding)
			adjusted[index] = finding
			continue
		}

		category, rule, _ := trustedActionCatalogRule(
			generation,
			finding.RuleID,
		)
		if !trustedReadOnlyArgumentDataFinding(category, finding) {
			continue
		}
		if !trustedActionContentFindingHasRiskPair(enforcementFacts, rule) {
			// Literal secret/PII material in an action remains visible for
			// local audit, but cannot alert or block without command-local
			// proof of external egress or an active sensitive-path write.
			adjusted[index] = trustedActionAuditFinding(finding)
			continue
		}
		adjusted[index] = finding.withTrustedActionProof(
			trustedActionContextFindingProof(finding.RuleID, enforcementFacts),
		)
	}
	return adjusted
}

func trustedActionContextFindingProof(
	ruleID string,
	facts actionfacts.Facts,
) findingProof {
	// Callers invoke this only after the typed risk classifier has completed
	// and matched the same rule against this execution-only projection. The
	// remaining two booleans are therefore boundary postconditions, while the
	// Facts methods retain authority and eligibility as independent checks.
	return newActionFactsSemanticFindingProof(
		ruleID,
		actionFactsSemanticProofInput{
			FactsAuthoritative:  facts.Authoritative(),
			EnforcementEligible: facts.EnforcementEligible(),
			ProjectionComplete:  true,
			EvaluationComplete:  true,
			Matched:             true,
		},
	)
}

type trustedActionSensitivePathRisk uint8

const (
	trustedActionSensitivePathReference trustedActionSensitivePathRisk = iota
	trustedActionSensitivePathUncertain
	trustedActionSensitivePathRead
	trustedActionSensitivePathMutation
	trustedActionSensitivePathReadEgress
)

type trustedActionSensitivePathMatcher func(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool

type trustedActionSensitivePathRuleMatcher struct {
	ruleIDs []string
	matcher trustedActionSensitivePathMatcher
}

// trustedActionSensitivePathRuleMatchers is the single membership and matcher
// catalog for trusted sensitive-path findings. Keep aliases grouped when they
// intentionally share identical path semantics.
var trustedActionSensitivePathRuleMatchers = []trustedActionSensitivePathRuleMatcher{
	{
		ruleIDs: []string{"PATH-ENV-FILE"},
		matcher: matchesContextualEnvironmentFile,
	},
	{
		ruleIDs: []string{"PATH-SSH-KEY", "PATH-WIN-SSH-KEY"},
		matcher: trustedActionPathValueMatcher(matchesSSHPrivateKey),
	},
	{
		ruleIDs: []string{"PATH-SSH-DIR"},
		matcher: trustedActionSSHDirectoryMatcher,
	},
	{
		ruleIDs: []string{"PATH-ETC-SHADOW"},
		matcher: trustedActionExactPathMatcher("/etc/shadow"),
	},
	{
		ruleIDs: []string{"PATH-ETC-PASSWD"},
		matcher: trustedActionExactPathMatcher("/etc/passwd"),
	},
	{
		ruleIDs: []string{"PATH-AWS-CREDS", "PATH-WIN-AWS-CREDS"},
		matcher: trustedActionPathValueMatcher(matchesAWSCredentials),
	},
	{
		ruleIDs: []string{"PATH-KUBE", "PATH-WIN-KUBE-CONFIG"},
		matcher: trustedActionPathValueMatcher(matchesKubeConfig),
	},
	{
		ruleIDs: []string{"PATH-DOCKER", "PATH-NPMRC", "PATH-PYPIRC"},
		matcher: trustedActionPathValueMatcher(matchesPackageCredentialFile),
	},
	{
		ruleIDs: []string{
			"PATH-GIT-CREDS", "PATH-NETRC", "PATH-WIN-GIT-CREDS",
			"PATH-WIN-NETRC",
		},
		matcher: trustedActionPathValueMatcher(matchesGitCredentialFile),
	},
	{
		ruleIDs: []string{"PATH-PROC-ENVIRON"},
		matcher: trustedActionPathValueMatcher(matchesProcEnviron),
	},
	{
		ruleIDs: []string{"SECRETS.CLOUD_CREDENTIAL_READ"},
		matcher: matchesContextualCloudCredentialFile,
	},
	{
		ruleIDs: []string{"SECRETS.BROWSER_SESSION_STORE_READ"},
		matcher: matchesContextualBrowserSessionStore,
	},
	{
		ruleIDs: []string{"SECRETS.WORKLOAD_IDENTITY_TOKEN_READ"},
		matcher: trustedActionPathValueMatcher(matchesWorkloadIdentityToken),
	},
}

func trustedActionPathValueMatcher(
	matcher func(string) bool,
) trustedActionSensitivePathMatcher {
	return func(_ actionfacts.Facts, candidate actionfacts.PathFact) bool {
		return matcher(semanticPathValue(candidate))
	}
}

func trustedActionExactPathMatcher(
	expected string,
) trustedActionSensitivePathMatcher {
	return func(_ actionfacts.Facts, candidate actionfacts.PathFact) bool {
		return strings.TrimRight(semanticPathValue(candidate), "/") == expected
	}
}

func trustedActionSSHDirectoryMatcher(
	_ actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := strings.ToLower(strings.Trim(semanticPathValue(candidate), "/"))
	return value == ".ssh" || strings.HasSuffix(value, "/.ssh") ||
		strings.Contains(value, "/.ssh/")
}

func trustedActionSensitivePathMatcherForRule(
	ruleID string,
) (trustedActionSensitivePathMatcher, bool) {
	ruleID = canonicalTrustedRuleID(ruleID)
	for _, binding := range trustedActionSensitivePathRuleMatchers {
		if slices.Contains(binding.ruleIDs, ruleID) {
			return binding.matcher, binding.matcher != nil
		}
	}
	return nil, false
}

func trustedActionSensitivePathRule(ruleID string) bool {
	_, ok := trustedActionSensitivePathMatcherForRule(ruleID)
	return ok
}

func trustedActionClassifySensitivePathRisk(
	facts actionfacts.Facts,
	ruleID string,
) trustedActionSensitivePathRisk {
	// Partial outer shell expressions may expose useful shadow facts, but they
	// never authorize a path alert or block.
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return trustedActionSensitivePathUncertain
	}

	risk := trustedActionSensitivePathReference
	for _, candidate := range facts.Paths {
		if !trustedActionPathMatchesRule(facts, candidate, ruleID) {
			continue
		}
		switch candidate.Access {
		case actionfacts.PathAccessWrite,
			actionfacts.PathAccessAppend,
			actionfacts.PathAccessDelete:
			if trustedActionExecutingCommand(facts, candidate.CommandID) {
				return trustedActionSensitivePathMutation
			}
		case actionfacts.PathAccessRead:
			if !trustedActionExecutingCommand(facts, candidate.CommandID) {
				continue
			}
			if trustedActionCommandProvesExternalEgress(
				facts,
				candidate.CommandID,
			) {
				return trustedActionSensitivePathReadEgress
			}
			risk = trustedActionSensitivePathRead
		}
	}
	return risk
}

func trustedActionPathMatchesRule(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
	ruleID string,
) bool {
	matcher, ok := trustedActionSensitivePathMatcherForRule(ruleID)
	return ok && matcher(facts, candidate)
}

func trustedActionContentFindingHasRiskPair(
	facts actionfacts.Facts,
	rule *PatternRule,
) bool {
	if rule == nil || rule.Pattern == nil ||
		!facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	for _, command := range facts.Commands {
		if !trustedActionExecutingCommand(facts, command.ID) ||
			!trustedActionContentRuleMatchesCommand(*rule, command) {
			continue
		}
		if trustedActionCommandProvesExternalEgress(facts, command.ID) ||
			trustedActionCommandWritesSensitivePath(facts, command.ID) {
			return true
		}
	}
	return false
}

func trustedActionContentRuleMatchesCommand(
	rule PatternRule,
	command actionfacts.CommandFact,
) bool {
	if !command.ArgvComplete || len(command.Argv) == 0 {
		return false
	}
	candidates := make([]string, 0, len(command.Argv)+1)
	candidates = append(candidates, command.Argv...)
	candidates = append(candidates, strings.Join(command.Argv, " "))
	for _, candidate := range candidates {
		if firstAcceptedRuleMatch(rule, candidate) != nil {
			return true
		}
		normalized := normalizeShell(candidate)
		if normalized != candidate &&
			firstAcceptedRuleMatch(rule, normalized) != nil {
			return true
		}
	}
	return false
}

func trustedActionCommandWritesSensitivePath(
	facts actionfacts.Facts,
	commandID int64,
) bool {
	for _, candidate := range facts.Paths {
		if candidate.CommandID == commandID &&
			(candidate.Access == actionfacts.PathAccessWrite ||
				candidate.Access == actionfacts.PathAccessAppend) &&
			matchesActiveSensitivePath(facts, candidate) {
			return true
		}
	}
	return false
}

func trustedActionCommandProvesExternalEgress(
	facts actionfacts.Facts,
	commandID int64,
) bool {
	return hasExternalUpload(facts, commandID) &&
		hasDataFlowFrom(
			facts,
			commandID,
			actionfacts.DataProcess,
			actionfacts.DataNetwork,
		)
}

func trustedActionExecutingCommand(
	facts actionfacts.Facts,
	commandID int64,
) bool {
	if commandID == 0 {
		return false
	}
	for _, command := range facts.Commands {
		if command.ID == commandID {
			return command.Kind == actionfacts.CommandKindProcess &&
				command.Effect == actionfacts.EffectExecute &&
				command.ArgvComplete
		}
	}
	return false
}

func trustedActionAuditFinding(finding RuleFinding) RuleFinding {
	finding.enforcement = findingEnforcementDetectionOnly
	finding.disposition = findingDispositionAudit
	finding.Severity = trustedActionLowerSeverity(finding.Severity, "LOW")
	return finding
}

func trustedActionAdvisoryFinding(finding RuleFinding) RuleFinding {
	finding.enforcement = findingEnforcementDetectionOnly
	finding.disposition = findingDispositionAdvisory
	finding.Severity = trustedActionLowerSeverity(finding.Severity, "MEDIUM")
	return finding
}

func trustedActionLowerSeverity(current, ceiling string) string {
	rank := func(severity string) int {
		switch strings.ToUpper(strings.TrimSpace(severity)) {
		case "CRITICAL":
			return 4
		case "HIGH":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	}
	if rank(current) > rank(ceiling) {
		return ceiling
	}
	return current
}

func trustedActionShippedGitAdvisoryRule(
	generation *compiledRulePackCategories,
	ruleID string,
) bool {
	switch canonicalTrustedRuleID(ruleID) {
	case "INTEGRITY.GIT_HOOKS_BYPASS", "SOURCE.GIT_REMOTE_TAMPER":
	default:
		return false
	}

	category, active, ok := trustedActionCatalogRule(generation, ruleID)
	if !ok {
		return false
	}
	defaultCategory, shipped, ok := trustedActionCatalogRuleInCategories(
		defaultRuleCategories,
		ruleID,
	)
	return ok && category == defaultCategory &&
		trustedActionSamePatternRule(*active, *shipped)
}

func trustedActionCatalogRule(
	generation *compiledRulePackCategories,
	ruleID string,
) (string, *PatternRule, bool) {
	if generation == nil {
		return "", nil, false
	}
	return trustedActionCatalogRuleInCategories(generation.categories, ruleID)
}

func trustedActionCatalogRuleInCategories(
	categories []ruleCategory,
	ruleID string,
) (string, *PatternRule, bool) {
	for categoryIndex := range categories {
		category := &categories[categoryIndex]
		for ruleIndex := range category.Rules {
			rule := &category.Rules[ruleIndex]
			if rule.ID == ruleID {
				return category.Name, rule, true
			}
		}
	}
	return "", nil, false
}

func trustedActionSamePatternRule(left, right PatternRule) bool {
	leftPattern := ""
	if left.Pattern != nil {
		leftPattern = left.Pattern.String()
	}
	rightPattern := ""
	if right.Pattern != nil {
		rightPattern = right.Pattern.String()
	}
	return left.ID == right.ID &&
		leftPattern == rightPattern &&
		left.Expression == right.Expression &&
		left.ToolCallOnly == right.ToolCallOnly &&
		left.Title == right.Title &&
		left.Severity == right.Severity &&
		left.Confidence == right.Confidence &&
		slices.Equal(left.Tags, right.Tags)
}
