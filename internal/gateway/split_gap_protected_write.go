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
// `eval "$c"`, `eval [ ... ]`) has none of its statements judged alone. The
// whole-action reading of such a partial call does not judge its writes, so
// `f(){ cd /tmp; "$@"; }; f cd && echo x >> .bashrc` from the home was a
// clean allow (substrate-1:GAP-0693, GAP-0694, GAP-0695), though the
// whole-action facts hold the file it writes. Each file those facts write or
// append to is judged as its plain write alone (`echo x > FILE`), in the
// call's folder:
//   - an operand spelled from the root or the home (/x, ~/x) names that file
//     whatever folder the call is in, so the findings of its plain write are
//     the call's, as they are for the same statement in a call the split reads;
//   - a relative operand is read in every folder the walk says the call may
//     be in, which over-approximates the folders a dynamic command may move
//     to, so its file is a candidate, not a proof: a plain write the pack
//     alerts on or blocks gives the unknown tier (an alert in default, a
//     block in strict), never the finding of the file itself.
// A call that writes only ordinary files stays as the whole-action reading
// judged it.

// splitGapWriteTitle and splitGapWriteReason are that unknown-tier finding.
const (
	splitGapWriteTitle  = "Part of this command could not be read on its own, and the command writes a file that may be protected"
	splitGapWriteReason = "split_gap_protected_write"
)

// splitGapWriteProbeCap bounds the plain writes judged for one call. A call
// with more distinct write targets is read by its text as well
// (hookpaths.BoundCallMayNameProtected).
const splitGapWriteProbeCap = 32

// splitGapWriteTwin is the plain write of one file a call writes.
type splitGapWriteTwin struct {
	text string
	// spelled: the operand names the file from the root or the home.
	spelled bool
}

// splitGapWriteTwins adds to twins the plain write of each file the facts
// of a POSIX call write or append to, in its resolved absolute spelling, and
// reports whether there were more than splitGapWriteProbeCap of them.
func splitGapWriteTwins(facts actionfacts.Facts, twins []splitGapWriteTwin) (_ []splitGapWriteTwin, over bool) {
	for _, candidate := range facts.Paths {
		operator := ""
		switch candidate.Access {
		case actionfacts.PathAccessWrite:
			operator = " > "
		case actionfacts.PathAccessAppend:
			operator = " >> "
		default:
			continue
		}
		resolved := filepath.ToSlash(candidate.Resolved)
		if !strings.HasPrefix(resolved, "/") || strings.HasPrefix(resolved, "/dev/") || strings.ContainsAny(resolved, "$`\n") {
			continue
		}
		twin := splitGapWriteTwin{
			text: "echo x" + operator + splitGapShellWord(resolved),
			spelled: !candidate.OtherFolderReading() && !candidate.UnresolvedFolder() &&
				(strings.HasPrefix(candidate.Value, "/") || strings.HasPrefix(candidate.Value, "~")),
		}
		if at := slices.IndexFunc(twins, func(seen splitGapWriteTwin) bool { return seen.text == twin.text }); at >= 0 {
			twins[at].spelled = twins[at].spelled || twin.spelled
			continue
		}
		if len(twins) == splitGapWriteProbeCap {
			return twins, true
		}
		twins = append(twins, twin)
	}
	return twins, false
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

// withSplitGapWrites adds to findings the judgment of the files a call with a
// parse gap in its split writes: the findings of the plain write of a file
// its operand spells, and the unknown tier when the plain write of a file a
// relative operand may be is a finding the pack enforces.
func withSplitGapWrites(ctx context.Context, request trustedActionRequest, generation *compiledRulePackCategories,
	budget *trustedActionBudget, facts actionfacts.Facts, wholeCommand string, findings []RuleFinding) []RuleFinding {
	if facts.Parse.Dialect != actionfacts.DialectPOSIX {
		return findings
	}
	twins, over := splitGapWriteTwins(facts, nil)
	if !over && (strings.Contains(wholeCommand, "~") || strings.Contains(wholeCommand, "HOME")) {
		// The facts of a partial call hold no path of a word spelled from
		// the home (~/.bashrc, $HOME/.bashrc): the twin that spells it as
		// the path under the active home does. It may itself be partial, so
		// it is read only to add findings (actionfacts.HomeSpelledTwin).
		if spelled, ok := actionfacts.HomeSpelledTwin(request.Input); ok {
			twins, over = splitGapWriteTwins(spelled, twins)
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
		if twin.spelled {
			findings = withSimpleCommandFindings(findings, childFindings)
			continue
		}
		unknown = unknown || slices.ContainsFunc(childFindings, splitGapEnforcedWriteFinding)
	}
	if unknown {
		findings = withUnknownFinding(findings, unknownReasonFinding(splitGapWriteTitle, splitGapWriteReason, request.EnforcementCapable))
	}
	return findings
}

// splitGapEnforcedWriteFinding is a finding of a plain write that the pack
// enforces, other than the evaluation limit, at MEDIUM or above
// (persistence.shell_profile_write is MEDIUM: an alert in default, a block
// in strict).
func splitGapEnforcedWriteFinding(finding RuleFinding) bool {
	if finding.dataWordRecord || canonicalTrustedRuleID(finding.RuleID) == evaluationLimitRuleID {
		return false
	}
	if !finding.contributesToEnforcement() && !finding.contributesToAlertOnly() {
		return false
	}
	return finding.Severity == "MEDIUM" || finding.Severity == "HIGH" || finding.Severity == "CRITICAL"
}
