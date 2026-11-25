// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path"
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
//   - a relative operand is a candidate, not a proof: it adds the tier, never
//     the finding of the file itself (rel-1-0-10:GAP-0871). A change of a
//     file's mode or owner is judged by the call's own command on that file
//     (a benign chmod +x of a project's git hook stays as benign as its
//     plain spelling: substrate-1:GAP-0703);
//   - the call is read twice: as the walk places it, and as rel 740c0de8fd
//     placed it (actionfacts Facts.WithMoverCallsUnread), where a call of a
//     function whose body moves the folder leaves the folder unresolved. The
//     walk reads such a body (rel-1-0-10:GAP-1144), but the part it did not
//     read may undo or redo any cd of the body: `f(){ cd /tmp && "$@"; }; f
//     cd && cd .aws && rm credentials`, whose walk places the operand in
//     /tmp/.aws, removes the home's file (substrate-1:GAP-0702, GAP-0711).
//     rel's reading keeps the folder the call started in and judges the
//     operand by the unresolved-folder tier (withUnresolvedFolderTier), so
//     the call is never judged below rel, with no list of folders to guess;
//   - many files are judged in a few shared statements per effect, not by a
//     broader reading of the call's text (substrate-1:GAP-0704, GAP-0712).
// A call whose effects touch only ordinary files stays as the whole-action
// reading judged it.

// pathEffect is the plain statement that judges one path effect of a call
// alone, as the pack judges the same effect spelled plainly.
type pathEffect struct {
	// prefix: the exact twin of one file, prefix followed by the file as one
	// shell word: the effect itself (a link a call makes is a write of the
	// link's name; the file it points at is not touched, actionfacts
	// classifyPOSIXLink).
	prefix string
	// shared: the same effect as a statement that takes any number of files
	// as operands (cat -- A B, tee -- A B), the twin of the files whose twin
	// only decides the unknown tier.
	shared string
	// own: no plain statement is the effect on every file (a mode or owner
	// change, chmod, chown, chgrp: chmod +x of a git hook arms it, chmod 600
	// of a key guards it), so the twin is the call's own command on the
	// file, beside the same command on an ordinary file (splitGapOwnPrefix),
	// and it only decides the unknown tier.
	own bool
}

// pathEffectTwin is the one map from a path-fact effect to its judgment for
// a call part that was not read (splitGapTwinSet). ok is false for an access
// that touches no file's content or place (execute, list, connect).
func pathEffectTwin(access actionfacts.PathAccess) (effect pathEffect, ok bool) {
	switch access {
	case actionfacts.PathAccessWrite:
		return pathEffect{prefix: "echo x > ", shared: "tee -- "}, true
	case actionfacts.PathAccessAppend:
		return pathEffect{prefix: "echo x >> ", shared: "tee -a -- "}, true
	case actionfacts.PathAccessDelete:
		return pathEffect{prefix: "rm -f -- ", shared: "rm -f -- "}, true
	case actionfacts.PathAccessRead:
		return pathEffect{prefix: "cat -- ", shared: "cat -- "}, true
	case actionfacts.PathAccessMetadata:
		return pathEffect{own: true}, true
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

// splitGapEffectProbeCap bounds the twins judged for one call: at most
// that many exact twins (past them a file joins the shared twins), and at
// most that many times as many files per effect in the shared twins. A call
// past the bound is read by its text as well
// (hookpaths.BoundCallMayNameProtected); every call of at most 256 path facts
// (actionfacts maxPathFacts), in both of its readings, stays inside it.
const splitGapEffectProbeCap = 32

// splitGapSharedTwinFiles is the most files one shared twin names: half the
// path facts a statement may hold, so a twin is never cut short, and few
// statements per effect (judging a twin costs about as much per statement as
// per file).
const splitGapSharedTwinFiles = 128

// splitGapEffectTwin is the effect twin of one file a call touches.
type splitGapEffectTwin struct {
	text string
	// proof: the twin is the effect itself and the operand names the file
	// from the root or the home, so its findings are the call's.
	proof bool
	// neutral: for a command's own twin, the same command on an ordinary
	// file in the folder of the files it changes (splitGapOwnPrefix).
	neutral string
}

// splitGapOwnKey is one own-command twin: the command's words without the
// files it changes, and the folder of those files.
type splitGapOwnKey struct{ prefix, folder string }

// splitGapTwinSet collects the twins of the files the facts of a POSIX call
// touch (add), and gives them as statements (statements).
type splitGapTwinSet struct {
	exact    []splitGapEffectTwin
	shared   []string
	words    map[string][]string
	seen     map[[2]string]bool
	own      []splitGapOwnKey
	ownFiles map[splitGapOwnKey][]string
	over     bool
}

// add adds the twins of every path effect of facts, each file in its
// resolved absolute spelling. A file whose twin only decides the unknown
// tier joins the shared twin of its effect, and a file whose mode or owner a
// command changes joins the twin of that command in its folder, so a call
// that touches many files costs a few bounded statements per effect, never a
// broader reading of its text.
func (set *splitGapTwinSet) add(facts actionfacts.Facts) {
	prefixes := map[int64]string{}
	for _, candidate := range facts.Paths {
		effect, ok := pathEffectTwin(candidate.Access)
		spelled := filepath.ToSlash(candidate.Resolved)
		if !ok || !splitGapPlainPath(spelled) {
			continue
		}
		word := splitGapShellWord(spelled)
		if effect.own {
			prefix, seen := prefixes[candidate.CommandID]
			if !seen {
				prefix = splitGapOwnPrefix(facts, candidate.CommandID)
				prefixes[candidate.CommandID] = prefix
			}
			if prefix != "" {
				set.addOwn(splitGapOwnKey{prefix: prefix, folder: path.Dir(spelled)}, word)
			}
			continue
		}
		proof := !candidate.OtherFolderReading() && !candidate.UnresolvedFolder() &&
			(strings.HasPrefix(candidate.Value, "/") || strings.HasPrefix(candidate.Value, "~"))
		if proof && set.addExact(effect.prefix+word) {
			continue
		}
		set.addWord(effect.shared, word)
	}
}

// addOwn adds a file to the own-command twin of key.
func (set *splitGapTwinSet) addOwn(key splitGapOwnKey, word string) {
	if set.ownFiles == nil {
		set.ownFiles = map[splitGapOwnKey][]string{}
	}
	files, seen := set.ownFiles[key]
	if !seen {
		set.own = append(set.own, key)
	}
	if !slices.Contains(files, word) {
		set.ownFiles[key] = append(files, word)
	}
}

// addExact adds the exact twin text of a file the operand spells, and
// reports false when the exact twins are full.
func (set *splitGapTwinSet) addExact(text string) bool {
	if at := slices.IndexFunc(set.exact, func(seen splitGapEffectTwin) bool { return seen.text == text }); at >= 0 {
		return true
	}
	if len(set.exact) == splitGapEffectProbeCap {
		return false
	}
	set.exact = append(set.exact, splitGapEffectTwin{text: text, proof: true})
	return true
}

// addWord adds a file to the shared twin of an effect.
func (set *splitGapTwinSet) addWord(shared, word string) {
	if set.words == nil {
		set.words, set.seen = map[string][]string{}, map[[2]string]bool{}
	}
	if set.seen[[2]string{shared, word}] {
		return
	}
	if len(set.words[shared]) == splitGapEffectProbeCap*splitGapEffectProbeCap {
		set.over = true
		return
	}
	if !slices.Contains(set.shared, shared) {
		set.shared = append(set.shared, shared)
	}
	set.words[shared] = append(set.words[shared], word)
	set.seen[[2]string{shared, word}] = true
}

// statements are the twins to judge: the exact twins, and each own-command
// and shared twin in statements of at most splitGapSharedTwinFiles files.
func (set *splitGapTwinSet) statements() []splitGapEffectTwin {
	twins := slices.Clone(set.exact)
	for _, key := range set.own {
		neutral := key.prefix + " " + splitGapShellWord(path.Join(key.folder, splitGapOwnTwinNeutral))
		for chunk := range slices.Chunk(set.ownFiles[key], splitGapSharedTwinFiles) {
			twins = append(twins, splitGapEffectTwin{text: key.prefix + " " + strings.Join(chunk, " "), neutral: neutral})
		}
	}
	for _, shared := range set.shared {
		for chunk := range slices.Chunk(set.words[shared], splitGapSharedTwinFiles) {
			twins = append(twins, splitGapEffectTwin{text: shared + strings.Join(chunk, " ")})
		}
	}
	return twins
}

// splitGapPlainPath reports an absolute spelling a twin may judge: not a
// device, and with no word a shell would expand.
func splitGapPlainPath(spelled string) bool {
	return strings.HasPrefix(spelled, "/") && !strings.HasPrefix(spelled, "/dev/") && !strings.ContainsAny(spelled, "$`\n")
}

// splitGapOwnTwinNeutral is the name of the ordinary file beside a file a
// command's own twin changes.
const splitGapOwnTwinNeutral = "split-gap-twin.txt"

// splitGapOwnPrefix is the own twin of the mode or owner changes
// (pathEffect.own) the command id of the call makes: its words without the
// files it changes. The twin is that prefix on the files of one folder, in
// their resolved spelling, and its neutral the prefix on an ordinary file
// of that folder. The change is a finding of a file only when the twin is
// one and its neutral is not: a world-writable mode outside the folder the
// command runs in (CMD-CHMOD-WORLD on chmod 777 /tmp/x) is one of any file,
// while chown of a credentials file or chmod 644 of a key is one of that
// file, and chmod +x of a project's git hook is none (substrate-1:GAP-0703).
// Every such command of the call is judged, many of one shape in one twin
// (substrate-1:GAP-0712). It is "" for a command whose words are not all
// known.
func splitGapOwnPrefix(facts actionfacts.Facts, id int64) string {
	at := slices.IndexFunc(facts.Commands, func(command actionfacts.CommandFact) bool { return command.ID == id })
	if at < 0 || !facts.Commands[at].ArgvComplete || len(facts.Commands[at].Argv) == 0 {
		return ""
	}
	var words []string
	for i, word := range facts.Commands[at].Argv {
		if strings.ContainsAny(word, "\n") {
			return ""
		}
		if i > 0 && slices.ContainsFunc(facts.Paths, func(candidate actionfacts.PathFact) bool {
			effect, _ := pathEffectTwin(candidate.Access)
			return effect.own && candidate.CommandID == id && candidate.Value == word
		}) {
			continue
		}
		words = append(words, splitGapShellWord(word))
	}
	return strings.Join(words, " ")
}

// splitGapShellWord is path as one shell word: as it is when it holds only
// characters a shell reads literally, else single-quoted.
func splitGapShellWord(path string) string {
	if strings.IndexFunc(path, func(r rune) bool { return !shellLiteralRune(r, "/._-+@%,:=") }) < 0 {
		return path
	}
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// splitGapJudged is what the reading of a sandbox call's twins placed as the
// host places it leaves for the reading placed in the guest's folder
// (withSandboxGuestSplitGapEffects): each twin text it judged, true when it
// added that twin's findings (an exact twin), and whether it decided the
// unknown tier. A copy-mode call spells its absolute operands the same in
// both placements, and both judge them lexically: before, the guest reading
// judged each such twin a second time within the call's one budget, so a
// call of many absolute operands spent the budget the laptop leaves for its
// later twins (substrate-1 GAP-0725).
type splitGapJudged struct {
	texts   map[string]bool
	unknown bool
}

// judgedBefore reports a twin the host-placed reading already judged as
// this reading would judge it: the same text, added as an exact twin when
// this one is, and naming no folder (guestFolderMayChangeJudgment), so the
// working directory of its child request changes nothing.
func (j *splitGapJudged) judgedBefore(request trustedActionRequest, twin splitGapEffectTwin) bool {
	if j == nil {
		return false
	}
	proof, ok := j.texts[twin.text]
	if !ok || twin.proof && !proof {
		return false
	}
	input := request.Input
	input.Command, input.Args, input.Argv = twin.text, nil, nil
	return !guestFolderMayChangeJudgment(actionfacts.Analyze(input))
}

// withSplitGapEffects adds to findings the judgment of the files a call with
// a parse gap in its split touches: the unknown tier when a twin is a finding
// the pack enforces, and the findings of an exact twin of a file its operand
// spells. prior is the host-placed reading's record for the guest-placed
// reading of the same call (nil otherwise); the record returned is for the
// guest-placed reading, and is kept only for a lexical sandbox call that
// reading follows.
func withSplitGapEffects(ctx context.Context, request trustedActionRequest, generation *compiledRulePackCategories,
	budget *trustedActionBudget, facts actionfacts.Facts, wholeCommand string, findings []RuleFinding, prior *splitGapJudged) ([]RuleFinding, *splitGapJudged) {
	if facts.Parse.Dialect != actionfacts.DialectPOSIX {
		return findings, nil
	}
	var record *splitGapJudged
	if prior == nil && request.SandboxGuestCWD != "" && request.Input.CWD != request.SandboxGuestCWD && request.SkipLocalFilesystemResolution {
		// The guest reading judges lexically; a host reading that reads
		// this host's files is another judgment, and is not shared.
		record = &splitGapJudged{texts: make(map[string]bool)}
	}
	var set splitGapTwinSet
	// Both readings of the call: as the walk places it, and as rel placed
	// it, with a mover call leaving the folder unresolved.
	windowsShellCWD := request.Input.MovedWindowsShellCWD
	unread, moverRead := facts.WithMoverCallsUnread(windowsShellCWD)
	set.add(facts)
	if moverRead {
		set.add(unread)
	}
	if !set.over && (strings.Contains(wholeCommand, "~") || strings.Contains(wholeCommand, "HOME")) {
		// The facts of a partial call hold no path of a word spelled from
		// the home (~/.bashrc, $HOME/.bashrc): the twin that spells it as
		// the path under the active home does. It may itself be partial, so
		// it is read only to add findings (actionfacts.HomeSpelledTwin).
		if spelled, ok := actionfacts.HomeSpelledTwin(request.Input); ok {
			set.add(spelled)
			if spelledUnread, ok := spelled.WithMoverCallsUnread(windowsShellCWD); ok {
				set.add(spelledUnread)
			}
		}
	}
	twins := set.statements()
	unknown := prior != nil && prior.unknown ||
		set.over && hookpaths.BoundCallMayNameProtected(wholeCommand, request.Input.CWD, request.Input.ActiveHome)
	judge := func(text string) []RuleFinding {
		child := request
		child.Input.Command, child.Input.Args, child.Input.Argv = text, nil, nil
		child.LegacyText = text
		child.conflictSource = nil
		child.record, child.recordTelemetry = nil, nil
		child.simpleCommandPass = true
		parent := request.Input
		parent.Command = wholeCommand
		child.parentPatch = &parent
		child.generation, child.budget = generation, budget
		return dispatchTrustedAction(ctx, child)
	}
	for _, twin := range twins {
		if unknown && !twin.proof {
			// The tier is decided; only an exact twin still adds findings.
			continue
		}
		if prior.judgedBefore(request, twin) {
			continue
		}
		childFindings := judge(twin.text)
		if record != nil {
			record.texts[twin.text] = record.texts[twin.text] || twin.proof
		}
		if twin.proof {
			findings = withSimpleCommandFindings(findings, childFindings)
		}
		if unknown || !slices.ContainsFunc(childFindings, splitGapEnforcedFinding) {
			continue
		}
		unknown = twin.neutral == "" || !slices.ContainsFunc(judge(twin.neutral), splitGapEnforcedFinding)
	}
	if !unknown && moverRead {
		// rel's reading: an operand after a mover call, in a folder the call
		// does not give, that may be a named protected file there. It reads
		// rel's access kinds only (unresolvedFolderOperand); a mode or owner
		// change was judged by its own twins above, in both readings
		// (substrate-1:GAP-0714).
		findings = withUnresolvedFolderTier(findings, request, unread, false)
	}
	if unknown {
		findings = withUnknownFinding(findings, unknownReasonFinding(splitGapEffectTitle, splitGapEffectReason, request.EnforcementCapable))
	}
	if record != nil {
		record.unknown = unknown
	}
	return findings, record
}

// splitGapEnforcedFinding is a finding of an effect twin that the pack
// enforces, other than the evaluation limit, at MEDIUM or above
// (persistence.shell_profile_write is MEDIUM: an alert in default, a block
// in strict).
func splitGapEnforcedFinding(finding RuleFinding) bool {
	if finding.boundRecord || canonicalTrustedRuleID(finding.RuleID) == evaluationLimitRuleID {
		return false
	}
	if !finding.contributesToEnforcement() && !finding.contributesToAlertOnly() {
		return false
	}
	return finding.Severity == "MEDIUM" || finding.Severity == "HIGH" || finding.Severity == "CRITICAL"
}
