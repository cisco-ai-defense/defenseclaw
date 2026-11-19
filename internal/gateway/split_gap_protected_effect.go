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
//   - a relative operand is read in every folder it may land in
//     (splitGapFolders): the folder the call starts in, the home and every
//     folder the walk reads one of the call's relative operands in. The
//     walk's own folder is no proof after a part it did not read: that part
//     may undo or redo any cd, so `f(){ cd /tmp && "$@"; }; f cd && rm
//     .aws/credentials`, whose facts place the operand only in /tmp, removes
//     the home's file (substrate-1:GAP-0702). So its file is a candidate, not
//     a proof, and a change of a file's mode or owner is judged by the call's
//     own command in that folder (a benign chmod +x of a project's git hook
//     stays as benign as its plain spelling: substrate-1:GAP-0703): neither
//     adds the finding of the file itself (rel-1-0-10:GAP-0871);
//   - many files are judged in a few shared statements per effect, not by a
//     broader reading of the call's text (substrate-1:GAP-0704).
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
	// of a key guards it), so the twin is the call's own command run in the
	// folder, beside the same command on an ordinary file (splitGapOwnTwin),
	// and it only decides the unknown tier.
	own bool
}

// pathEffectTwin is the one map from a path-fact effect to its judgment for
// a call part that was not read: the split-gap twins (splitGapTwinSet)
// and the unresolved-folder tier (unresolvedFolderOperand) both use it. ok
// is false for an access that touches no file's content or place (execute,
// list, connect).
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
// that many exact twins (past them a file joins the shared twins), at most
// that many own-command twins, and at most that many times as many files per
// effect in the shared twins. A call past the bound is read by its text as
// well (hookpaths.BoundCallMayNameProtected); every call of at most 256 path
// facts (actionfacts maxPathFacts) in four folders stays inside it.
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
	// folder: the folder the twin runs in, when it is not the call's own.
	folder string
	// neutral: for a command's own twin, the same command on an ordinary
	// file beside each file it changes (splitGapOwnTwin).
	neutral string
}

// splitGapTwinSet collects the twins of the files the facts of a POSIX call
// touch (add), and gives them as statements (statements).
type splitGapTwinSet struct {
	exact, own []splitGapEffectTwin
	shared     []string
	words      map[string][]string
	seen       map[[2]string]bool
	over       bool
}

// add adds the twins of every path effect of facts, each file in its
// resolved absolute spelling and, for a relative operand, in every folder of
// splitGapFolders. A file whose twin only decides the unknown tier joins the
// shared twin of its effect, so a call that reads or writes many files costs
// a few bounded statements per effect, never a broader reading of its text.
func (set *splitGapTwinSet) add(facts actionfacts.Facts) {
	folders := splitGapFolders(facts)
	for _, candidate := range facts.Paths {
		effect, ok := pathEffectTwin(candidate.Access)
		if !ok || effect.own {
			continue
		}
		proof := !candidate.OtherFolderReading() && !candidate.UnresolvedFolder() &&
			(strings.HasPrefix(candidate.Value, "/") || strings.HasPrefix(candidate.Value, "~"))
		for _, spelled := range splitGapSpellings(candidate, folders) {
			word := splitGapShellWord(spelled)
			if proof && set.addExact(effect.prefix+word) {
				continue
			}
			set.addWord(effect.shared, word)
		}
	}
	for _, command := range facts.Commands {
		text, neutral, ok := splitGapOwnTwin(facts, command)
		if !ok {
			continue
		}
		for _, folder := range folders {
			twin := splitGapEffectTwin{text: text, folder: folder, neutral: neutral}
			if slices.Contains(set.own, twin) {
				continue
			}
			if len(set.own) == splitGapEffectProbeCap {
				set.over = true
				return
			}
			set.own = append(set.own, twin)
		}
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

// statements are the twins to judge: the exact and own-command twins, and
// each shared twin in statements of at most splitGapSharedTwinFiles files.
func (set *splitGapTwinSet) statements() []splitGapEffectTwin {
	twins := slices.Concat(set.exact, set.own)
	for _, shared := range set.shared {
		for chunk := range slices.Chunk(set.words[shared], splitGapSharedTwinFiles) {
			twins = append(twins, splitGapEffectTwin{text: shared + strings.Join(chunk, " ")})
		}
	}
	return twins
}

// splitGapSpellings are the absolute spellings a twin judges a path fact
// in: its resolved spelling and, for a relative operand, its spelling in
// each folder. A spelling that is no plain absolute path is not judged.
func splitGapSpellings(candidate actionfacts.PathFact, folders []string) []string {
	spellings := []string{filepath.ToSlash(candidate.Resolved)}
	if unresolvedFolderOperand(candidate) {
		for _, folder := range folders {
			spellings = append(spellings, path.Join(folder, filepath.ToSlash(candidate.Value)))
		}
	}
	return slices.DeleteFunc(spellings, func(spelled string) bool { return !splitGapPlainPath(spelled) })
}

// splitGapPlainPath reports an absolute spelling a twin may judge: not a
// device, and with no word a shell would expand.
func splitGapPlainPath(spelled string) bool {
	return strings.HasPrefix(spelled, "/") && !strings.HasPrefix(spelled, "/dev/") && !strings.ContainsAny(spelled, "$`\n")
}

// splitGapOwnTwinNeutral is the name of the ordinary file beside a file a
// command's own twin changes.
const splitGapOwnTwinNeutral = "split-gap-twin.txt"

// splitGapOwnTwin is the twin of the mode or owner changes (pathEffect.own)
// a command of the call makes: the command itself, judged in each folder of
// splitGapFolders as its plain spelling run there is, and neutral, the same
// command on an ordinary file beside each file it changes. The change is a
// finding of the file only when the command is one there and its neutral
// is not: a world-writable mode outside the folder the command runs in
// (CMD-CHMOD-WORLD on chmod 777 /tmp/x) is one of any file, while chown of
// a credentials file or chmod 644 of a key is one of that file, and chmod
// +x of a project's git hook is none (substrate-1:GAP-0703). ok is false
// for a command that makes no such change or whose words are not all known.
func splitGapOwnTwin(facts actionfacts.Facts, command actionfacts.CommandFact) (text, neutral string, ok bool) {
	if !command.ArgvComplete || len(command.Argv) == 0 {
		return "", "", false
	}
	words := make([]string, len(command.Argv))
	neutrals := make([]string, len(command.Argv))
	for i, word := range command.Argv {
		if strings.ContainsAny(word, "\n") {
			return "", "", false
		}
		words[i] = splitGapShellWord(word)
		neutrals[i] = words[i]
		if i > 0 && slices.ContainsFunc(facts.Paths, func(candidate actionfacts.PathFact) bool {
			effect, _ := pathEffectTwin(candidate.Access)
			return effect.own && candidate.CommandID == command.ID && candidate.Value == word
		}) {
			neutrals[i] = splitGapShellWord(path.Join(path.Dir(word), splitGapOwnTwinNeutral))
			ok = true
		}
	}
	if !ok {
		return "", "", false
	}
	return strings.Join(words, " "), strings.Join(neutrals, " "), true
}

// splitGapFolders are the folders a relative operand of a call with a parse
// gap may land in: the folder the call starts in, the active home, and each
// folder the walk reads one of the call's relative operands in (a mover's
// target, the folder after a cd). The part the split did not read may move
// the shell to any of them before any operand.
func splitGapFolders(facts actionfacts.Facts) []string {
	var folders []string
	add := func(folder string) {
		if folder = path.Clean(filepath.ToSlash(folder)); path.IsAbs(folder) && !slices.Contains(folders, folder) {
			folders = append(folders, folder)
		}
	}
	add(facts.CWD)
	add(facts.ActiveHome)
	for _, candidate := range facts.Paths {
		value := path.Clean(filepath.ToSlash(candidate.Value))
		if !unresolvedFolderOperand(candidate) || value == "." || value == ".." || strings.HasPrefix(value, "../") {
			continue
		}
		if folder, ok := strings.CutSuffix(filepath.ToSlash(candidate.Resolved), "/"+value); ok {
			add(folder + "/")
		}
	}
	return folders
}

// splitGapShellWord is path as one shell word: as it is when it holds only
// characters a shell reads literally, else single-quoted.
func splitGapShellWord(path string) string {
	if strings.IndexFunc(path, func(r rune) bool { return !shellLiteralRune(r, "/._-+@%,:=") }) < 0 {
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
	var set splitGapTwinSet
	set.add(facts)
	if !set.over && (strings.Contains(wholeCommand, "~") || strings.Contains(wholeCommand, "HOME")) {
		// The facts of a partial call hold no path of a word spelled from
		// the home (~/.bashrc, $HOME/.bashrc): the twin that spells it as
		// the path under the active home does. It may itself be partial, so
		// it is read only to add findings (actionfacts.HomeSpelledTwin).
		if spelled, ok := actionfacts.HomeSpelledTwin(request.Input); ok {
			set.add(spelled)
		}
	}
	twins := set.statements()
	unknown := set.over && hookpaths.BoundCallMayNameProtected(wholeCommand, request.Input.CWD, request.Input.ActiveHome)
	judge := func(text, folder string) []RuleFinding {
		child := request
		child.Input.Command, child.Input.Args, child.Input.Argv = text, nil, nil
		if folder != "" {
			child.Input.CWD = folder
		}
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
		childFindings := judge(twin.text, twin.folder)
		if twin.proof {
			findings = withSimpleCommandFindings(findings, childFindings)
		}
		if unknown || !slices.ContainsFunc(childFindings, splitGapEnforcedFinding) {
			continue
		}
		unknown = twin.neutral == "" || !slices.ContainsFunc(judge(twin.neutral, twin.folder), splitGapEnforcedFinding)
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
