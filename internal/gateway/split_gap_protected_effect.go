// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A POSIX call the per-command split cannot flatten (actionfacts.SimpleCommands
// gives a "parse" gap: in an action that defines a function, a command whose
// name is not static, `f(){ $y; }`, `"$@"`, `$r ~`, `$(echo return)`,
// `eval "$c"`, `eval [ ... ]`) has none of its statements judged alone, and
// the whole-action reading of such a partial call does not judge the files it
// touches. `f(){ cd /tmp; "$@"; }; f cd && X` from the home was a clean allow
// for X a write, an append, a delete or a read of a protected home file
// (substrate-1:GAP-0693, GAP-0694, GAP-0695, GAP-0698), though the
// whole-action facts hold that file. So every path effect of the call's facts
// is judged by its effect twin (pathEffectTwin), in the call's folder:
//   - every twin that is a finding the pack enforces gives the unknown tier
//     (an alert in default, a block in strict): the part of the call that
//     was not read may do anything with that file;
//   - an operand spelled from the root or the home (/x, ~/x) names that file
//     whatever folder the call is in, so an exact twin's findings are the
//     call's as well, as they are for the same statement in a call the split
//     reads;
//   - a relative operand is read in every folder the walk says the call may
//     be in, which over-approximates the folders a dynamic command may move
//     to, so its file is a candidate, not a proof, and a change of a file's
//     mode or owner is judged by the twin that changes the file, which says
//     only that the file is protected: neither adds the finding of the file
//     itself (rel-1-0-10:GAP-0871).
// A call whose effects touch only ordinary files stays as the whole-action
// reading judged it.

// pathEffect is the plain statement that judges one path effect of a call
// alone: prefix, followed by the file as one shell word.
type pathEffect struct {
	prefix string
	// exact: the statement is the effect itself, not only a twin that says
	// the file is protected against a change (a mode or owner change, chmod,
	// chown, chgrp: no plain statement is that change of every file). A link
	// a call makes is a write of the link's name; the file it points at is
	// not touched (actionfacts classifyPOSIXLink).
	exact bool
	// operands: the statement takes any number of files as operands, so the
	// files whose twin only decides the unknown tier are judged together.
	operands bool
}

// pathEffectTwin is the one map from a path-fact effect to its judgment for
// a call part that was not read: the split-gap twins (splitGapEffectTwins)
// and the unresolved-folder tier (unresolvedFolderOperand) both use it. ok
// is false for an access that touches no file's content or place (execute,
// list, connect).
func pathEffectTwin(access actionfacts.PathAccess) (effect pathEffect, ok bool) {
	switch access {
	case actionfacts.PathAccessWrite:
		return pathEffect{prefix: "echo x > ", exact: true}, true
	case actionfacts.PathAccessAppend:
		return pathEffect{prefix: "echo x >> ", exact: true}, true
	case actionfacts.PathAccessDelete:
		return pathEffect{prefix: "rm -f -- ", exact: true, operands: true}, true
	case actionfacts.PathAccessRead:
		return pathEffect{prefix: "cat -- ", exact: true, operands: true}, true
	case actionfacts.PathAccessMetadata:
		return pathEffect{prefix: "echo x > "}, true
	}
	return pathEffect{}, false
}

// splitGapUnreadPart reports a statement of the per-command split that the
// split could not read on its own (a parse gap), so the path effects of the
// call are judged by their twins (withSplitGapEffects).
func splitGapUnreadPart(simple actionfacts.SimpleCommand) bool {
	return simple.EvaluationFailure == "parse"
}

// splitGapEffectTitle and splitGapEffectReason are that unknown-tier finding.
const (
	splitGapEffectTitle  = "Part of this command could not be read on its own, and the command touches a file that may be protected"
	splitGapEffectReason = "split_gap_protected_effect"
)

// splitGapEffectProbeCap bounds the effect twins judged for one call. A call
// with more distinct targets is read by its text as well
// (hookpaths.BoundCallMayNameProtected).
const splitGapEffectProbeCap = 32

// splitGapEffectTwin is the effect twin of one file a call touches.
type splitGapEffectTwin struct {
	text string
	// proof: the twin is the effect itself and the operand names the file
	// from the root or the home, so its findings are the call's.
	proof bool
}

// splitGapEffectTwins adds to twins the effect twin of each file the facts of
// a POSIX call touch, in its resolved absolute spelling, and reports whether
// there were more than splitGapEffectProbeCap of them. The files of an
// operand twin that only decides the unknown tier share one statement
// (`cat -- A B`), of at most splitGapEffectProbeCap files as well, so a call
// that reads many files costs one bounded twin per kind.
func splitGapEffectTwins(facts actionfacts.Facts, twins []splitGapEffectTwin) (_ []splitGapEffectTwin, over bool) {
	var shared []string
	words := map[string][]string{}
	for _, candidate := range facts.Paths {
		effect, ok := pathEffectTwin(candidate.Access)
		if !ok {
			continue
		}
		resolved := filepath.ToSlash(candidate.Resolved)
		if !strings.HasPrefix(resolved, "/") || strings.HasPrefix(resolved, "/dev/") || strings.ContainsAny(resolved, "$`\n") {
			continue
		}
		word := splitGapShellWord(resolved)
		proof := effect.exact && !candidate.OtherFolderReading() && !candidate.UnresolvedFolder() &&
			(strings.HasPrefix(candidate.Value, "/") || strings.HasPrefix(candidate.Value, "~"))
		if !proof && effect.operands {
			if !slices.Contains(shared, effect.prefix) {
				shared = append(shared, effect.prefix)
			}
			if slices.Contains(words[effect.prefix], word) {
				continue
			}
			if len(words[effect.prefix]) == splitGapEffectProbeCap {
				over = true
				break
			}
			words[effect.prefix] = append(words[effect.prefix], word)
			continue
		}
		twin := splitGapEffectTwin{text: effect.prefix + word, proof: proof}
		if at := slices.IndexFunc(twins, func(seen splitGapEffectTwin) bool { return seen.text == twin.text }); at >= 0 {
			twins[at].proof = twins[at].proof || twin.proof
			continue
		}
		if len(twins) == splitGapEffectProbeCap {
			over = true
			break
		}
		twins = append(twins, twin)
	}
	for _, prefix := range shared {
		if len(twins) == splitGapEffectProbeCap {
			return twins, true
		}
		twins = append(twins, splitGapEffectTwin{text: prefix + strings.Join(words[prefix], " ")})
	}
	return twins, over
}

// splitGapShellWord is path as one shell word: as it is when it holds only
// characters a shell reads literally, else single-quoted.
func splitGapShellWord(path string) string {
	if strings.IndexFunc(path, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+@%,:=", r))
	}) < 0 {
		return path
	}
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// withSplitGapEffects adds to findings the judgment of the files a call with
// a parse gap in its split touches: the unknown tier when a twin is a finding
// the pack enforces, and the findings of an exact twin of a file its operand
// spells.
func withSplitGapEffects(ctx context.Context, request trustedActionRequest, generation *compiledRulePackCategories,
	budget *trustedActionBudget, facts actionfacts.Facts, wholeCommand string, findings []RuleFinding) []RuleFinding {
	if facts.Parse.Dialect != actionfacts.DialectPOSIX {
		return findings
	}
	twins, over := splitGapEffectTwins(facts, nil)
	if !over && (strings.Contains(wholeCommand, "~") || strings.Contains(wholeCommand, "HOME")) {
		// The facts of a partial call hold no path of a word spelled from
		// the home (~/.bashrc, $HOME/.bashrc): the twin that spells it as
		// the path under the active home does. It may itself be partial, so
		// it is read only to add findings (actionfacts.HomeSpelledTwin).
		if spelled, ok := actionfacts.HomeSpelledTwin(request.Input); ok {
			twins, over = splitGapEffectTwins(spelled, twins)
		}
	}
	unknown := over && hookpaths.BoundCallMayNameProtected(wholeCommand, request.Input.CWD, request.Input.ActiveHome)
	for _, twin := range twins {
		child := request
		child.Input.Command, child.Input.Args, child.Input.Argv = twin.text, nil, nil
		child.LegacyText = twin.text
		child.conflictSource = nil
		child.record, child.recordTelemetry = nil, nil
		child.simpleCommandPass = true
		parent := request.Input
		parent.Command = wholeCommand
		child.parentPatch = &parent
		child.generation, child.budget = generation, budget
		childFindings := dispatchTrustedAction(ctx, child)
		if twin.proof {
			findings = withSimpleCommandFindings(findings, childFindings)
		}
		unknown = unknown || slices.ContainsFunc(childFindings, splitGapEnforcedFinding)
	}
	if unknown {
		findings = withUnknownFinding(findings, unknownReasonFinding(splitGapEffectTitle, splitGapEffectReason, request.EnforcementCapable))
	}
	return findings
}

// splitGapEnforcedFinding is a finding of an effect twin that the pack
// enforces, other than the evaluation limit, at MEDIUM or above
// (persistence.shell_profile_write is MEDIUM: an alert in default, a block
// in strict).
func splitGapEnforcedFinding(finding RuleFinding) bool {
	if finding.dataWordRecord || canonicalTrustedRuleID(finding.RuleID) == evaluationLimitRuleID {
		return false
	}
	if !finding.contributesToEnforcement() && !finding.contributesToAlertOnly() {
		return false
	}
	return finding.Severity == "MEDIUM" || finding.Severity == "HIGH" || finding.Severity == "CRITICAL"
}
