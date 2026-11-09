// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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
		spelling, placed, reported := linkTargetSpelling(request, candidate)
		if spelling == "" {
			continue
		}
		physical := ""
		for _, key := range []string{spelling, candidate.Resolved, candidate.Normalized, candidate.Value} {
			if target := request.ResolvedWriteTargets[key]; filepath.IsAbs(target) {
				physical = target
				break
			}
		}
		if physical == "" && !reported && !request.SkipLocalFilesystemResolution {
			physical, _ = request.targetMemo.ResolveWriteTarget(spelling)
		}
		if !filepath.IsAbs(physical) {
			physical = spelling
		}
		if filepath.Clean(physical) == filepath.Clean(spelling) && !placed {
			continue
		}
		linked := actionfacts.LinkedPathFact(candidate, physical)
		if linked.Resolved == candidate.Resolved {
			continue
		}
		// A path that was only placed in the working directory names the
		// file itself, not a link to another one.
		linked.Linked = filepath.Clean(physical) != filepath.Clean(spelling)
		if placed && linked.Flavor != actionfacts.PathFlavorWindows {
			// The path is now an absolute one of the host that placed it.
			linked.Flavor = actionfacts.PathFlavorPOSIX
		}
		facts.Paths = append(facts.Paths, linked)
	}
	return facts
}

// linkTargetSpelling is the absolute spelling a path fact names. A relative
// path is placed in the working directory of the call: the one the gateway
// received, else the one the managed hook client ran the call in. A managed
// gateway behind ProtectHome cannot resolve a project in the home of the
// user, so it receives none of its own; the path stayed relative to nothing
// and was never followed to the file a link reaches, where the absolute
// spelling of the same link was (IB17). placed is true for a relative path,
// which had no absolute fact until now. reported is true when the directory
// is only the one the client reported, outside the home and project root the
// gateway may walk: the spelling then only looks up the evidence the client
// keyed by it and is never walked locally, so a known protected target
// blocks wherever the project lives (GAP-0831). The spelling is empty when
// no working directory places it.
func linkTargetSpelling(request trustedActionRequest, candidate actionfacts.PathFact) (spelling string, placed, reported bool) {
	// A rooted Windows spelling names the file Windows opens for it, whatever
	// the analysis could resolve: it is never an operand relative to the
	// working directory (a device or share prefix, a name with trailing
	// spaces, a folder followed by "..").
	if opened, ok := windowsHostPathOfFact(candidate); ok {
		return opened, false, false
	}
	if filepath.IsAbs(candidate.Resolved) {
		return candidate.Resolved, false, false
	}
	// Without a working directory the analysis keeps a literal relative
	// path as written and leaves it unresolved, with the flavor of a typed
	// file tool unknown. A path with shell syntax in it, or one the analysis
	// refused, is not a literal one.
	if candidate.Flavor != actionfacts.PathFlavorPOSIX && candidate.Flavor != actionfacts.PathFlavorUnknown ||
		candidate.Absolute || candidate.Resolved != "" ||
		candidate.Normalized == "" || candidate.Value == "" ||
		strings.HasPrefix(candidate.Value, "~") || strings.ContainsAny(candidate.Value, "$`\x00") {
		return "", false, false
	}
	cwd := request.Input.CWD
	if !filepath.IsAbs(cwd) {
		var ok bool
		if cwd, ok = protectedHomeClientDirectory(request); !ok {
			if cwd, ok = protectedHomeReportedDirectory(request); !ok {
				return "", false, false
			}
			reported = true
		}
	}
	return hookpaths.OperandPath(candidate.Value, cwd), true, reported
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

// typedTargetRuleText is the text the path rules read for the typed target of
// a file operation. A Windows path is read as the path Windows opens for it
// (windowsOpenedPath, windowsRuleText), whatever spelling the call used; the
// rules name each home folder and credential file in one letter case, while
// Windows reads them in any, so the names below a home are read in lower case.
// Other paths are read as given, with the active home respelled.
func typedTargetRuleText(resolved, home string, verbatim bool) string {
	if opened, ok, _ := windowsOpenedPath(resolved, verbatim); ok {
		return windowsRuleText(opened, home)
	}
	if pathCaseFoldHost && filepath.IsAbs(resolved) {
		return caseFoldedPOSIXRuleText(resolved, home)
	}
	return activeHomeAsTilde(resolved, home)
}

// typedTargetCandidateText is typedTargetRuleText for a path fact, with
// false for a path that is neither a rooted Windows spelling nor absolute.
// A Windows spelling the analysis left unresolved (a trailing dot, a data
// stream) is read by its normalized form: the file it opens is the same.
func typedTargetCandidateText(candidate actionfacts.PathFact, home string) (string, bool) {
	spelling := pathFactSpelling(candidate)
	if !windowsRootedSpelling(spelling) && !filepath.IsAbs(candidate.Resolved) {
		return "", false
	}
	return typedTargetRuleText(spelling, home, windowsVerbatimOperand(candidate.Value)), true
}

// windowsNameFold spells a Windows name in the lower case the rules write.
// Windows compares names through upper case, so a letter that is not ASCII
// but upper-cases or case-folds to an ASCII letter (long s, Kelvin sign,
// dotless i) names the same file as that letter. strings.ToLower alone leaves
// those letters as they are, and the ASCII-only rule expressions miss them.
func windowsNameFold(name string) string {
	ascii := true
	for index := 0; index < len(name) && ascii; index++ {
		ascii = name[index] < utf8.RuneSelf
	}
	if ascii {
		return strings.ToLower(name)
	}
	return strings.Map(func(r rune) rune {
		if r < unicode.MaxASCII {
			return unicode.ToLower(r)
		}
		if upper := unicode.ToUpper(r); upper < unicode.MaxASCII {
			return unicode.ToLower(upper)
		}
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			if folded < unicode.MaxASCII {
				return unicode.ToLower(folded)
			}
		}
		return unicode.ToLower(r)
	}, name)
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
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		!typed && !hasApplyPatchCommand(facts) && !pathCaseFoldHost {
		return nil
	}
	var findings []RuleFinding
	for _, candidate := range facts.Paths {
		// On a case-folding host every path of the action is also read in
		// the spelling the rules write, whatever the command or access:
		// ~/.NETRC is the file ~/.netrc names.
		if !linkTargetCandidate(facts, candidate, typed) && !pathCaseFoldHost {
			continue
		}
		text, ok := typedTargetCandidateText(candidate, request.Input.ActiveHome)
		if !ok {
			continue
		}
		for _, finding := range scanRuleGeneration(generation, text, request.Input.Tool, options) {
			// A case-folding host reads the path rules that have no
			// path proof (AWS config, GnuPG, /etc/shadow) in any letter case
			// too: the exact-case spelling gets their finding from the call text.
			if trustedActionSensitivePathRule(finding.RuleID) ||
				pathCaseFoldHost && strings.HasPrefix(finding.RuleID, "PATH-") {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}
