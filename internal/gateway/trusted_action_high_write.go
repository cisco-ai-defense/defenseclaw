// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// provedHighWriteFindings joins a native action's resolved write target to a
// HIGH or CRITICAL catalog rule whose expression names a write access. The
// target is an ActionFacts path, not a regex hit on arbitrary tool text. A
// missing active-file inventory cannot turn that resolved write into an
// advisory finding (GAP-0768). The same proof covers POSIX and PowerShell.
func provedHighWriteFindings(
	ctx context.Context,
	request trustedActionRequest,
	findings []RuleFinding,
) ([]RuleFinding, bool) {
	if !request.EnforcementCapable {
		return findings, false
	}
	generation := snapshotRulePackGenerationFor(ctx, request.Connector)
	if generation == nil {
		return findings, false
	}
	facts := actionfacts.Analyze(request.Input)
	proved := append([]RuleFinding(nil), findings...)
	blocked := false
	for _, target := range facts.Paths {
		if target.Access != actionfacts.PathAccessWrite &&
			target.Access != actionfacts.PathAccessAppend &&
			target.Access != actionfacts.PathAccessDelete ||
			!target.Absolute || target.Resolved == "" {
			continue
		}
		command, found := integrityCommandByID(facts, target.CommandID)
		if !found || command.Effect != actionfacts.EffectExecute {
			continue
		}
		for _, category := range generation.categories {
			for _, rule := range category.Rules {
				if !highWriteCatalogRule(rule) || !highWriteRuleMatchesTarget(rule, target.Resolved) {
					continue
				}
				proof := newActionFactsSubgraphFindingProof(rule.ID, true, true)
				if !proof.authorizes(rule.ID) {
					continue
				}
				index := slices.IndexFunc(proved, func(finding RuleFinding) bool {
					return finding.RuleID == rule.ID
				})
				if index >= 0 {
					proved[index].enforcement = findingEnforcementAllowed
					proved[index].proof = proof
				} else {
					name := path.Base(strings.ReplaceAll(target.Resolved, `\`, "/"))
					proved = append(proved, adjustConfidence(request.Input.Tool, RuleFinding{
						RuleID: rule.ID, Title: rule.Title, Severity: rule.Severity,
						Confidence: rule.Confidence, Evidence: name,
						Tags:       append([]string(nil), rule.Tags...),
						LineNumber: 1, enforcement: findingEnforcementAllowed,
						proof: proof,
					}))
				}
				blocked = true
			}
		}
	}
	return proved, blocked
}

// An active instruction file may be loaded by a session that predates this
// gateway process. Its in-memory load event is unavailable after a restart,
// so a proved write to one of the catalog's instruction filenames must still
// enforce that catalog rule. AGENTS.md intentionally has no general regex in
// the rule pack; this exact basename check supplies its lost-session proof.
func highWriteRuleMatchesTarget(rule PatternRule, resolved string) bool {
	name := path.Base(strings.ReplaceAll(resolved, `\`, "/"))
	var instruction string
	switch rule.ID {
	case "COG-AGENTS-MD":
		instruction = "AGENTS.md"
	case "COG-CLAUDE-MD":
		instruction = "CLAUDE.md"
	case "COG-SOUL":
		instruction = "SOUL.md"
	case "COG-IDENTITY":
		instruction = "IDENTITY.md"
	case "COG-MEMORY":
		instruction = "MEMORY.md"
	case "COG-TOOLS-MD":
		instruction = "TOOLS.md"
	case "COG-GATEWAY-JSON":
		instruction = "gateway.json"
	}
	if instruction != "" {
		return strings.EqualFold(name, instruction)
	}
	return rule.Pattern.MatchString(resolved)
}

func highWriteCatalogRule(rule PatternRule) bool {
	if rule.Pattern == nil ||
		!strings.EqualFold(rule.Severity, "HIGH") &&
			!strings.EqualFold(rule.Severity, "CRITICAL") {
		return false
	}
	return strings.Contains(rule.Expression, "PATH_ACCESS_WRITE") ||
		strings.Contains(rule.Expression, "PATH_ACCESS_APPEND") ||
		strings.Contains(rule.Expression, "PATH_ACCESS_DELETE")
}
