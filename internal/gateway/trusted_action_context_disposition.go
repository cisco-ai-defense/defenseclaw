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

// trustedRepositoryPolicyProof is trusted, server-owned policy context. Rule
// IDs in this proof were explicitly forbidden by repository policy; they must
// never be populated from tool arguments or model-produced text.
//
// A slice keeps the boundary immutable by convention and makes the value easy
// to copy with the action request. The number of repository rules is bounded
// by the rule-pack loader, so a linear lookup is preferable to accepting a
// caller-owned mutable map here.
type trustedRepositoryPolicyProof struct {
	ForbiddenRuleIDs []string
}

func (p trustedRepositoryPolicyProof) forbids(ruleID string) bool {
	ruleID = canonicalTrustedRuleID(ruleID)
	for _, candidate := range p.ForbiddenRuleIDs {
		if canonicalTrustedRuleID(candidate) == ruleID {
			return true
		}
	}
	return false
}

// applyTrustedActionContextDisposition is the trusted-action-only disposition
// boundary for content literals and selected advisory rules. It deliberately
// is not called by prompt, tool-result, or completion scanners: those scan
// untrusted content at a different boundary and retain their existing policy.
//
// The function returns an owned findings slice and never promotes a finding
// that an earlier boundary already marked detection-only. Its only authority
// input is ActionFacts plus explicit server-owned repository-policy proof.
func applyTrustedActionContextDisposition(
	generation *compiledRulePackCategories,
	facts actionfacts.Facts,
	findings []RuleFinding,
	repositoryPolicy trustedRepositoryPolicyProof,
) []RuleFinding {
	adjusted := append([]RuleFinding(nil), findings...)
	for index := range adjusted {
		finding := adjusted[index]

		if trustedActionSensitivePathRule(finding.RuleID) {
			switch trustedActionClassifySensitivePathRisk(facts, finding.RuleID) {
			case trustedActionSensitivePathMutation,
				trustedActionSensitivePathReadEgress:
				// A typed mutation or read-to-external-network flow remains a
				// security finding. Do not promote a finding that another
				// boundary already made detection-only.
				finding = finding.withTrustedActionProof(
					trustedActionContextFindingProof(finding.RuleID, facts),
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
		) && !repositoryPolicy.forbids(finding.RuleID) {
			// Shipped git remote changes and hook-bypass switches are useful
			// advisory evidence, but repositories legitimately use both. A
			// custom rule or explicit repository-policy proof retains its
			// original enforcement disposition.
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
		if !trustedActionContentFindingHasRiskPair(facts, rule) {
			// Literal secret/PII material in an action remains visible for
			// local audit, but cannot alert or block without command-local
			// proof of external egress or an active sensitive-path write.
			adjusted[index] = trustedActionAuditFinding(finding)
			continue
		}
		adjusted[index] = finding.withTrustedActionProof(
			trustedActionContextFindingProof(finding.RuleID, facts),
		)
	}
	return adjusted
}

func trustedActionContextFindingProof(
	ruleID string,
	facts actionfacts.Facts,
) findingProof {
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
	trustedActionSensitivePathRead
	trustedActionSensitivePathMutation
	trustedActionSensitivePathReadEgress
)

func trustedActionSensitivePathRule(ruleID string) bool {
	switch canonicalTrustedRuleID(ruleID) {
	case "PATH-ENV-FILE", "PATH-SSH-DIR", "PATH-SSH-KEY",
		"PATH-WIN-SSH-KEY", "PATH-ETC-SHADOW", "PATH-ETC-PASSWD",
		"PATH-AWS-CREDS", "PATH-WIN-AWS-CREDS",
		"PATH-KUBE", "PATH-WIN-KUBE-CONFIG",
		"PATH-DOCKER", "PATH-NPMRC", "PATH-PYPIRC",
		"PATH-GIT-CREDS", "PATH-NETRC", "PATH-WIN-GIT-CREDS",
		"PATH-WIN-NETRC", "PATH-PROC-ENVIRON",
		"SECRETS.CLOUD_CREDENTIAL_READ",
		"SECRETS.BROWSER_SESSION_STORE_READ",
		"SECRETS.WORKLOAD_IDENTITY_TOKEN_READ":
		return true
	default:
		return false
	}
}

func trustedActionClassifySensitivePathRisk(
	facts actionfacts.Facts,
	ruleID string,
) trustedActionSensitivePathRisk {
	// Partial outer shell expressions may expose useful shadow facts, but they
	// never authorize a path alert or block.
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return trustedActionSensitivePathReference
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
	switch canonicalTrustedRuleID(ruleID) {
	case "PATH-ENV-FILE":
		return matchesContextualEnvironmentFile(facts, candidate)
	case "PATH-SSH-KEY", "PATH-WIN-SSH-KEY":
		return matchesSSHPrivateKey(semanticPathValue(candidate))
	case "PATH-SSH-DIR":
		value := strings.ToLower(strings.Trim(semanticPathValue(candidate), "/"))
		return value == ".ssh" || strings.HasSuffix(value, "/.ssh") ||
			strings.Contains(value, "/.ssh/")
	case "PATH-ETC-SHADOW":
		return strings.TrimRight(semanticPathValue(candidate), "/") == "/etc/shadow"
	case "PATH-ETC-PASSWD":
		return strings.TrimRight(semanticPathValue(candidate), "/") == "/etc/passwd"
	case "PATH-AWS-CREDS", "PATH-WIN-AWS-CREDS":
		return matchesAWSCredentials(semanticPathValue(candidate))
	case "PATH-KUBE", "PATH-WIN-KUBE-CONFIG":
		return matchesKubeConfig(semanticPathValue(candidate))
	case "PATH-DOCKER", "PATH-NPMRC", "PATH-PYPIRC":
		return matchesPackageCredentialFile(semanticPathValue(candidate))
	case "PATH-GIT-CREDS", "PATH-NETRC", "PATH-WIN-GIT-CREDS",
		"PATH-WIN-NETRC":
		return matchesGitCredentialFile(semanticPathValue(candidate))
	case "PATH-PROC-ENVIRON":
		return matchesProcEnviron(semanticPathValue(candidate))
	case "SECRETS.CLOUD_CREDENTIAL_READ":
		return matchesContextualCloudCredentialFile(facts, candidate)
	case "SECRETS.BROWSER_SESSION_STORE_READ":
		return matchesContextualBrowserSessionStore(facts, candidate)
	case "SECRETS.WORKLOAD_IDENTITY_TOKEN_READ":
		return matchesWorkloadIdentityToken(semanticPathValue(candidate))
	default:
		return false
	}
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
