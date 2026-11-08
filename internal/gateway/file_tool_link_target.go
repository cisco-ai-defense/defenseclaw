// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// fileToolLinkTargetFacts keeps the exact file operation of every connector
// attached to both the name the file tool received and the file reached
// through an existing link, so a link gets the path verdict the name of its
// target gets, whatever the connector or body shape (GAP-0797). The resolved
// target the hook client reports is preferred; a per-user gateway can also
// resolve a path locally when that evidence is absent. Only file tools that
// follow their final path reach this function.
func fileToolLinkTargetFacts(facts actionfacts.Facts, request trustedActionRequest) actionfacts.Facts {
	if !actionfacts.PathTool(request.Input.Tool) || !facts.Authoritative() || !facts.EnforcementEligible() {
		return facts
	}
	originalPaths := len(facts.Paths)
	for index := 0; index < originalPaths; index++ {
		candidate := facts.Paths[index]
		switch candidate.Access {
		case actionfacts.PathAccessRead, actionfacts.PathAccessWrite, actionfacts.PathAccessAppend:
		default:
			continue
		}
		spelling := candidate.Resolved
		if !filepath.IsAbs(spelling) {
			continue
		}
		physical := ""
		for _, key := range []string{candidate.Resolved, candidate.Normalized, candidate.Value} {
			if target := request.ResolvedWriteTargets[key]; filepath.IsAbs(target) {
				physical = target
				break
			}
		}
		if physical == "" && !request.SkipLocalFilesystemResolution {
			physical, _ = request.targetMemo.ResolveWriteTarget(spelling)
		}
		if !filepath.IsAbs(physical) || filepath.Clean(physical) == filepath.Clean(spelling) {
			continue
		}
		linked := candidate
		linked.Value = physical
		linked.Normalized = physical
		linked.Resolved = physical
		linked.Linked = true
		facts.Paths = append(facts.Paths, linked)
	}
	return facts
}

// The rule scan sees only the call's lexical arguments. These typed file
// facts supply the exact resolved target too, so a link receives the same
// path rule as a direct file call. The usual typed path and proof filters
// still decide whether each finding can enforce.
func fileToolLinkTargetFindings(
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
	options ruleScanOptions,
) []RuleFinding {
	if !actionfacts.PathTool(request.Input.Tool) || !facts.Authoritative() || !facts.EnforcementEligible() {
		return nil
	}
	var findings []RuleFinding
	for _, candidate := range facts.Paths {
		switch candidate.Access {
		case actionfacts.PathAccessRead, actionfacts.PathAccessWrite, actionfacts.PathAccessAppend:
		default:
			continue
		}
		if !filepath.IsAbs(candidate.Resolved) {
			continue
		}
		for _, finding := range scanRuleGeneration(
			generation, candidate.Resolved, request.Input.Tool, options,
		) {
			if trustedActionSensitivePathRule(finding.RuleID) {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}
