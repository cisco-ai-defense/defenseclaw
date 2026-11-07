// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// copilotSharedLocalLinkedCall reports a Local call whose path operands are
// followed to the file a link reaches: a file tool, or a shell command. A
// shell command is followed only for the files it writes.
func copilotSharedLocalLinkedCall(request trustedActionRequest) (followed, shell bool) {
	if !request.CopilotSharedLocalFile {
		return false, false
	}
	if actionfacts.PathTool(request.Input.Tool) {
		return true, false
	}
	_, shell = trustedBashCommandInput(request.Input)
	return shell, shell
}

// copilotSharedLocalLinkedAccess is the access a followed path carries: read,
// write or append for a file tool, and only write or append for a shell
// command.
func copilotSharedLocalLinkedAccess(access actionfacts.PathAccess, shell bool) bool {
	switch access {
	case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend:
		return true
	case actionfacts.PathAccessRead:
		return !shell
	default:
		return false
	}
}

// copilotSharedLocalFileFacts keeps the exact file operation attached to both
// the name the Local tool received and the file reached through an existing
// link. The hook resolved target is preferred; a per-user gateway can also
// resolve a path locally when that evidence is absent. A file tool follows
// its final path; a shell command writes through the same link, so its write
// targets are judged by the exact system-file rules like a file tool.
func copilotSharedLocalFileFacts(facts actionfacts.Facts, request trustedActionRequest) actionfacts.Facts {
	followed, shell := copilotSharedLocalLinkedCall(request)
	if !followed || !facts.Authoritative() || !facts.EnforcementEligible() {
		return facts
	}
	originalPaths := len(facts.Paths)
	for index := 0; index < originalPaths; index++ {
		candidate := facts.Paths[index]
		if !copilotSharedLocalLinkedAccess(candidate.Access, shell) {
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
		facts.Paths = append(facts.Paths, linked)
	}
	return facts
}

// The rule scan sees only the call's lexical arguments. These typed file
// facts supply the exact resolved target too, so a link receives the same
// path rule as a direct file call. The usual typed path and proof filters
// still decide whether each finding can enforce.
func copilotSharedLocalPathFindings(
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
	options ruleScanOptions,
) []RuleFinding {
	followed, shell := copilotSharedLocalLinkedCall(request)
	if !followed || !facts.Authoritative() || !facts.EnforcementEligible() {
		return nil
	}
	var findings []RuleFinding
	for _, candidate := range facts.Paths {
		if !copilotSharedLocalLinkedAccess(candidate.Access, shell) {
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
