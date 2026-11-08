// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// fileToolLinkTargetFacts keeps the exact file operation of every connector
// attached to both the name the call received and the file reached through
// an existing link, so a link gets the path verdict the name of its target
// gets, whatever the connector or body shape (GAP-0797). The resolved target
// the hook client reports is preferred; a per-user gateway can also resolve a
// path locally when that evidence is absent. The class is the write target
// of an operation that follows its final path: every path of a typed file
// tool, and every file an apply_patch envelope names whether the connector
// sends it as its own tool or as a shell command with a here-document
// (GAP-0831). Other shell commands are not part of this class. The file a
// link reaches is spelled like every other path fact: a Windows physical
// path (back slashes, extended prefix) is judged in the slash form the path
// rules read (GAP-0855).
func fileToolLinkTargetFacts(facts actionfacts.Facts, request trustedActionRequest) actionfacts.Facts {
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return facts
	}
	typed := actionfacts.PathTool(request.Input.Tool)
	if !typed && !hasApplyPatchCommand(facts) {
		return facts
	}
	originalPaths := len(facts.Paths)
	for index := 0; index < originalPaths; index++ {
		candidate := facts.Paths[index]
		if !linkTargetCandidate(facts, candidate, typed) {
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
		linked := actionfacts.LinkedPathFact(candidate, physical)
		if linked.Resolved == candidate.Resolved {
			continue
		}
		facts.Paths = append(facts.Paths, linked)
	}
	return facts
}

// linkTargetCandidate reports whether a path fact is a file operation that
// follows its final path and so reaches the file a link names: the read,
// write or append of a typed file tool, or a path of an apply_patch command.
func linkTargetCandidate(facts actionfacts.Facts, candidate actionfacts.PathFact, typed bool) bool {
	switch candidate.Access {
	case actionfacts.PathAccessRead, actionfacts.PathAccessWrite, actionfacts.PathAccessAppend:
	default:
		return false
	}
	return typed || applyPatchCommandPath(facts, candidate)
}

// windowsActiveHomeMutation reports a typed write or append whose resolved
// target is a drive-letter path inside the active home. The rule scan reads
// the call as the tool sent it, with the path's separators escaped, so the
// rules never see that path in the spelling the typed facts give it; the
// target is scanned here instead, on every platform the hook decision can run.
func windowsActiveHomeMutation(candidate actionfacts.PathFact, home string) bool {
	if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
		return false
	}
	return actionfacts.DriveLetterPath(candidate.Resolved) &&
		activeHomeAsTilde(candidate.Resolved, home) != candidate.Resolved
}

// windowsUserPath splits a drive-letter path under a Users folder, in any
// letter case, into the drive, the account name and the rest.
var windowsUserPath = regexp.MustCompile(`(?i)^([a-z]:)/users/([^/]+)/(.+)$`)

// typedTargetRuleText is the text the path rules read for the typed target of
// a file operation. A Windows path names the same file in any letter case,
// while the rules name each home folder and credential file in one: the home
// is spelled ~ (or its Users folder in the case the rules read) and the names
// below it are read in lower case, which is how the rules write them. Other
// paths are read as given, with the active home respelled.
func typedTargetRuleText(resolved, home string) string {
	text := activeHomeAsTilde(resolved, home)
	if !actionfacts.DriveLetterPath(resolved) {
		return text
	}
	if rest, ok := strings.CutPrefix(text, "~/"); ok {
		return "~/" + strings.ToLower(rest)
	}
	if match := windowsUserPath.FindStringSubmatch(text); match != nil {
		return match[1] + "/Users/" + match[2] + "/" + strings.ToLower(match[3])
	}
	return text
}

// hasApplyPatchCommand reports an apply_patch command in the parsed action,
// whichever tool carried the shell text.
func hasApplyPatchCommand(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Executable == "apply_patch" {
			return true
		}
	}
	return false
}

func applyPatchCommandPath(facts actionfacts.Facts, candidate actionfacts.PathFact) bool {
	for _, command := range facts.Commands {
		if command.ID == candidate.CommandID {
			return command.Executable == "apply_patch"
		}
	}
	return false
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
	typed := actionfacts.PathTool(request.Input.Tool)
	if !facts.Authoritative() || !facts.EnforcementEligible() || !typed && !hasApplyPatchCommand(facts) {
		return nil
	}
	var findings []RuleFinding
	for _, candidate := range facts.Paths {
		if !linkTargetCandidate(facts, candidate, typed) {
			continue
		}
		if !filepath.IsAbs(candidate.Resolved) && !windowsActiveHomeMutation(candidate, request.Input.ActiveHome) {
			continue
		}
		for _, finding := range scanRuleGeneration(
			generation, typedTargetRuleText(candidate.Resolved, request.Input.ActiveHome), request.Input.Tool, options,
		) {
			if trustedActionSensitivePathRule(finding.RuleID) {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}
