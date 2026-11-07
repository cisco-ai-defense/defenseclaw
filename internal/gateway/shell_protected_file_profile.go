// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shellProtectedFileRules is the class of rules that decide whether a shell
// command writes, appends, copies, moves, renames, links, extracts or
// otherwise materializes content into one of the protected files of the user:
// the SSH authorized-keys and control files (hookpaths), shell startup
// profiles and active Git hooks. A finding of the class is judged by what the
// call provably does (shellFileMark). A call that writes a protected file it
// names, directly, by a value it assigns, through a link on disk or through
// a link or copy it makes, is blocked in every profile (the Wave-3 rule). A
// call that makes a link, copies or extracts a tree, or that the hook client
// could not place, keeps the rating of the rule pack. Any other finding, in
// which no operand names or reaches a protected file (owner decision
// 2026-11-06, rel-1-0-6:GAP-0675, detections round #1189), is a visible alert
// in the default and permissive profiles, per-user and managed, and a block
// in the strict profile, managed strict included.
//
// DefenseClaw self-protection is not in this class and keeps blocking in
// every profile: its state, configuration, plugins and bridges
// (tamper.detector_state_write and the active-state owners), turning its
// hooks off or changing the hook settings of an agent, rule-pack tamper, agent
// instruction files (COG-*), native write and edit tools, MCP and skill
// admission and the fail modes.
var shellProtectedFileRules = map[string]bool{
	"PERSISTENCE.SSH_AUTHORIZED_KEYS_COMMAND": true,
	"PATH-SSH-DIR":                    true,
	"PERSISTENCE.SHELL_PROFILE_WRITE": true,
	"PERSISTENCE.GIT_HOOK_WRITE":      true,
}

// shellFileMark says how sure the readers are of a finding of the class.
type shellFileMark uint8

const (
	// shellFileNone: not a finding of the class, or not on a shell command.
	shellFileNone shellFileMark = iota
	// shellFileUnproven: a reader suspects a protected target; nothing the
	// command names proves it. The balanced and permissive profiles warn.
	shellFileUnproven
	// shellFileKept: a reader suspects a protected target and the call makes
	// a link, copies one, or leaves a link operation unread, so a name in it
	// may reach a protected file whatever its words say. The finding keeps
	// the rating of the rule pack in every profile, as before GAP-0675.
	shellFileKept
	// shellFileProven: the call writes a protected file at a target it
	// names (shellWritesProvenProtectedFile). Every profile blocks it.
	shellFileProven
)

// shellProtectedFileRule reports a rule of the shell-command protected-file
// class.
func shellProtectedFileRule(ruleID string) bool {
	return shellProtectedFileRules[canonicalTrustedRuleID(ruleID)]
}

// trustedShellCommandInput reports an action that runs a shell command now:
// the command text or argv of a shell or execution tool. A native write or
// edit tool, an apply_patch envelope and a stored command payload are not
// shell commands here; they keep their enforcement in every profile. An
// envelope a shell call runs or feeds is judged by its directive targets
// (shellWritesProvenProtectedFile), not by the words of the call.
func trustedShellCommandInput(input actionfacts.Input) bool {
	if actionfacts.ApplyPatchTool(input.Tool) {
		return false
	}
	return input.Command != "" || len(input.Argv) > 0 ||
		actionfacts.IsImmediateShellExecutionTool(input.Tool)
}

// markShellProtectedFileFindings records, on the findings of one trusted
// action, which belong to the shell-command protected-file class. It only
// labels them; the profile decides what they do (profileClassFindings).
// The label is set afresh at every level of a nested dispatch (a statement,
// a child or a twin of the call): the outermost call, which runs last, has
// the whole command and decides.
//
// The class is the findings the readers could not prove. Proof is evidence
// about the mutable target, never about the words of the call: a mutated
// path of the command structure (also after the links on disk are followed),
// a copy, move or link operand that names a protected file or is, or holds,
// a link on disk that reaches one, a link of the command to a protected name,
// an apply_patch envelope directive, a target the managed hook client
// resolved, or the evidence the finding producer itself found (a write
// through an existing link). A call so proven is not in the class: it keeps
// its block in every profile (owner steer, Wave-3 rule: a protected file or
// link named directly or through a known value stays blocked). A protected
// name in a comment, in text the call only prints or writes elsewhere, or in
// a value the call overwrites proves nothing. A call that may reach the
// DefenseClaw state is self-protection, not the class either: the
// protected-write owners also report a write that reaches the state through
// a link, and such a finding keeps its block in every profile
// (rel-1-0-6:GAP-0675 review 1 M3a). Both checks run only when a finding of
// the class is present, and each answer over-matches: a false answer only
// keeps the block the call had before GAP-0675. A native write or edit tool is
// not in the class either.
func markShellProtectedFileFindings(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !slices.ContainsFunc(findings, func(f RuleFinding) bool { return shellProtectedFileRule(f.RuleID) }) {
		return findings
	}
	// A level below (a twin, a child, a statement) may have proven the write
	// where the whole call is written in a way its own facts cannot read (a
	// value assigned earlier, a shell -c body): the proof stays.
	mark := shellFileNone
	if trustedShellCommandInput(request.Input) {
		switch {
		case shellCallProvedOrdinary(request, actionfacts.Analyze(request.Input)):
			// Every variable target of the call holds an ordinary value at its
			// write; a level below that read the first value is wrong.
			mark = shellFileUnproven
		case slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.shellFile == shellFileProven }) ||
			request.shellProof != nil && *request.shellProof ||
			shellWritesProvenProtectedFile(request):
			mark = shellFileProven
			if request.shellProof != nil {
				*request.shellProof = true
			}
		case shellCommandMayReachState(request):
			// Self-protection, not the class.
		case shellCallUnresolved(request):
			mark = shellFileKept
		default:
			mark = shellFileUnproven
		}
	}
	for index := range findings {
		if shellProtectedFileRule(findings[index].RuleID) {
			findings[index].shellFile = mark
		}
	}
	return findings
}

// markRecoveredParseOrdinary labels the over-limit finding of a call whose
// recovered parse the user-side hook could not bound (hookpaths
// shell-parse-bound) as unproven when nothing in the call reaches a file that
// is protected or owned: no word has a dot-folder or a protected name, the
// call makes no link and no word of it is a link on disk, and it cannot reach
// the DefenseClaw state. The default and permissive profiles then warn;
// strict blocks as before (rel-1-0-6:GAP-0534 closes through GAP-0675).
func markRecoveredParseOrdinary(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !trustedShellCommandInput(request.Input) || shellCommandMayReachState(request) ||
		shellCallMakesOrCopiesLinks(request) || commandNamesOwnedPath(request.Input) ||
		commandWordIsLink(request.Input) {
		return findings
	}
	for index := range findings {
		findings[index].shellFile = shellFileUnproven
	}
	return findings
}

// ownedPathName finds a word of a command that is a dot-folder or dotfile,
// the place a startup file, the SSH folder, a Git folder or an agent or
// DefenseClaw folder sits in.
var ownedPathName = regexp.MustCompile(`(?i)(^|[\s"\x27=:/\\(])\.[a-z0-9_][a-z0-9_.-]*([/\\"\x27\s);]|$)`)

// commandNamesOwnedPath reports a command with a word that could be a
// protected or DefenseClaw-owned file: a dot-folder or dotfile, or a name of
// the protected class (protectedOperandName), anywhere in its text.
func commandNamesOwnedPath(input actionfacts.Input) bool {
	text := input.Command
	if text == "" {
		text = string(input.Args)
	}
	if ownedPathName.MatchString(text) || strings.Contains(strings.ToLower(text), "authorized_keys") {
		return true
	}
	for _, word := range strings.Fields(strings.NewReplacer(";", " ", "(", " ", ")", " ", "\"", " ", "\x27", " ").Replace(text)) {
		if protectedOperandName(word, true) {
			return true
		}
	}
	return false
}

// commandWordIsLink reports a word of the command that names a link on disk,
// to anywhere: a file the call removes or writes may be a link to a file it
// does not name. One readlink per word, on at most stateLinkWordsMax words.
func commandWordIsLink(input actionfacts.Input) bool {
	command, ok := trustedBashCommandInput(input)
	if !ok {
		command = input.Command
	}
	return commandWordLinks(command, input.CWD, input.ActiveHome, func(string) bool { return true })
}

// shellCallProvedOrdinary reports a call the local gateway proves ordinary the
// way the user-side hook does: every write target is a variable that holds an
// ordinary value at its write (a value an earlier assignment left is dead).
func shellCallProvedOrdinary(request trustedActionRequest, facts actionfacts.Facts) bool {
	input := request.Input
	command, ok := trustedBashCommandInput(input)
	if !ok || request.ProtectedHomeHook || !trustedPOSIXShellCall(input, facts) ||
		request.Connector != "claudecode" && request.Connector != "codex" {
		return false
	}
	// The hook proof knows the authorized-keys files only: a path fact that
	// names a startup profile, a Git hook or an SSH file is not cleared by it.
	for _, path := range facts.Paths {
		if protectedOperandName(path.Value, false) || protectedOperandName(path.Normalized, false) ||
			protectedOperandName(path.Resolved, false) {
			return false
		}
	}
	// A value the call assigns can name such a file too (dst=~/.bashrc).
	words := strings.FieldsFunc(shellCommentText.ReplaceAllString(command, " "), func(r rune) bool {
		return strings.ContainsRune(" \t\n;&|()<>={}$\"\x27", r)
	})
	for _, word := range words {
		if protectedOperandName(word, false) {
			return false
		}
	}
	return hookpaths.ProvedOrdinaryVariableTargets(command, input.CWD, facts.ActiveHome)
}

// shellWritesProvenProtectedFile reports a shell call that mutates a
// protected file of the user (an authorized-keys or SSH control file, an SSH
// private key, a shell startup profile or an active Git hook) at a target the
// call proves, whatever the profile: a mutated path of the command structure
// (a literal or a value the command assigns), that path after the links on
// disk are followed, a target the hook client resolved, or a directive target
// of an apply_patch envelope the call runs or feeds. The finding producer adds
// its own proof (a write through an existing link, or a copy of one). A word
// the readers cannot place, a pattern, text in a comment or data, and a value
// that was overwritten prove nothing here; such a finding stays in the class.
func shellWritesProvenProtectedFile(request trustedActionRequest) bool {
	input := request.Input
	facts := actionfacts.Analyze(input)
	// The hookpaths reading of the command resolves the values it assigns and
	// sees a value that is overwritten: its protected-target decision is the
	// proof, and a call whose variable targets it proves ordinary has no
	// other: the analysis below reads the first value a variable took.
	if command, ok := trustedBashCommandInput(input); ok {
		if shellCallProvedOrdinary(request, facts) {
			return false
		}
		if request.targetMemo.ActionCommandDecisionWithDialectAndGlobFacts(command, input.CWD, input.ActiveHome, input.DialectHint, clientGlobFacts(request)) == hookpaths.ProtectedTargetDecision {
			return true
		}
	}
	for _, path := range facts.Paths {
		command, ok := integrityCommandByID(facts, path.CommandID)
		// A link to a protected file is a protected name taken, whichever
		// operand the readers call the write.
		if !ok || !shellCommandChangesPath(command, path) && programBaseName(command.Program) != "ln" {
			continue
		}
		if protectedFilePath(facts, path) {
			return true
		}
		if resolved, ok := request.targetMemo.ResolveWriteTarget(placedPath(path, facts.CWD)); ok {
			path.Resolved = resolved
			if protectedFilePath(facts, path) {
				return true
			}
		}
	}
	// A change below the SSH folder or a Git hooks folder of the active home,
	// or at a name the readers leave as a pattern, can reach a protected file
	// whatever the file is called.
	for _, path := range facts.Paths {
		command, ok := integrityCommandByID(facts, path.CommandID)
		if !ok || !shellCommandChangesPath(command, path) && !fileMovingProgram(command.Program) {
			continue
		}
		if relative, ok := activeHomeRelative(facts, path); ok &&
			(relative == ".ssh" || strings.HasPrefix(relative, ".ssh/") || strings.Contains(relative, ".git/hooks")) {
			return true
		}
		if strings.ContainsAny(path.Value, "*?[") && path.Access != actionfacts.PathAccessRead {
			return true
		}
	}
	// A mutated operand, or the target a link of the command points at, that
	// is itself a protected name (a link of the command to the SSH folder, a
	// write below it after a copy, a startup profile). Only operands count,
	// never a comment, a quoted data word or a value the command overwrites.
	// A copy, move or link names its source operand as well: moving a file of
	// that name into a place the command cannot read is the write.
	sourceCWD := facts.CWD
	if !filepath.IsAbs(sourceCWD) {
		sourceCWD = request.ResolvedWriteTargets[hookpaths.CWDKey]
	}
	// A name the managed hook client resolved to an ordinary file, in a call
	// that makes no link, is a decoy: the folder it sits in is not the SSH folder.
	linkFree := false
	if command, ok := trustedBashCommandInput(input); ok {
		made := hookpaths.CommandLinksWithFacts(input.Tool, command, sourceCWD, input.ActiveHome, request.ResolvedWriteTargets)
		linkFree = made.Known() && !made.HasAliases()
	}
	for _, path := range facts.Paths {
		command, ok := integrityCommandByID(facts, path.CommandID)
		if !ok || !protectedOperandName(path.Value, false) && !protectedOperandName(path.Normalized, false) &&
			!protectedOperandName(path.Resolved, false) {
			continue
		}
		if resolved := request.ResolvedWriteTargets[placedPath(path, sourceCWD)]; linkFree && resolved != "" &&
			!protectedFilePath(facts, actionfacts.PathFact{Resolved: resolved, Absolute: true}) {
			continue
		}
		if shellCommandChangesPath(command, path) || fileMovingProgram(command.Program) {
			return true
		}
	}
	for _, command := range facts.Commands {
		for index, word := range command.Argv {
			if programBaseName(word) != "ln" {
				continue
			}
			for _, operand := range command.Argv[index+1 : len(command.Argv)-1] {
				if !strings.HasPrefix(operand, "-") && protectedOperandName(operand, true) {
					return true
				}
			}
			break
		}
	}
	// A copy or move source that is, or holds, a link on disk that reaches a
	// protected file: the copy carries the link, and a write through its new
	// name is the write (the managed hook client reads the source links for a
	// gateway that cannot see the home).
	for _, path := range facts.Paths {
		command, ok := integrityCommandByID(facts, path.CommandID)
		if !ok || path.Access != actionfacts.PathAccessRead || !fileMovingProgram(command.Program) {
			continue
		}
		for _, target := range hookpaths.CopySourceLinkTargets(placedPath(path, sourceCWD), request.ResolvedWriteTargets) {
			form := target
			if resolved, ok := request.targetMemo.ResolveWriteTarget(target); ok {
				form = resolved
			}
			if protectedFilePath(facts, actionfacts.PathFact{Resolved: form, Absolute: true}) ||
				protectedFilePath(facts, actionfacts.PathFact{Resolved: target, Absolute: true}) {
				return true
			}
		}
	}
	// A name the command copies from a link on disk that reaches a protected
	// file (the copy carries the link): a write through its new name is the
	// write. The links are read as the managed hook client read them for a
	// gateway that cannot see the home, else from the disk.
	if command, ok := trustedBashCommandInput(input); ok {
		cwd := facts.CWD
		if !filepath.IsAbs(cwd) {
			cwd = request.ResolvedWriteTargets[hookpaths.CWDKey]
		}
		links := hookpaths.CommandLinksWithFacts(input.Tool, command, cwd, input.ActiveHome, request.ResolvedWriteTargets)
		operands, _, _ := hookpaths.ShellWriteOperands(command, cwd, input.ActiveHome)
		placed, _ := hookpaths.ShellDirectoryWriteOperands(command, cwd, input.ActiveHome, request.ResolvedWriteTargets, false, request.ProtectedHomeHook)
		for _, operand := range placed {
			operands = append(operands, operand.Path)
		}
		for _, operand := range operands {
			// A name a link the command makes reaches a protected file by.
			if linked, ok := links.Target(hookpaths.OperandPath(operand, cwd)); ok &&
				protectedFilePath(facts, actionfacts.PathFact{Resolved: linked, Absolute: true}) {
				return true
			}
			for _, target := range links.CopiedLinkTargets(hookpaths.OperandPath(operand, cwd), request.ResolvedWriteTargets) {
				if protectedFilePath(facts, actionfacts.PathFact{Resolved: target, Absolute: true}) {
					return true
				}
			}
		}
	}
	// The managed hook client resolved the call to a protected target.
	if request.ProtectedHomeHook && request.ResolvedWriteTargets[hookpaths.ActionDecisionKey] == hookpaths.ProtectedTargetDecision {
		return true
	}
	for _, target := range request.ResolvedWriteTargets {
		if protectedFilePath(facts, actionfacts.PathFact{Resolved: target, Absolute: true}) {
			return true
		}
	}
	targets, _ := hookpaths.ApplyPatchLexicalCommandTargets(input.Tool, input.Args, input.Command, facts.CWD, facts.ActiveHome)
	for _, target := range targets {
		for _, form := range []string{target, request.ResolvedWriteTargets[hookpaths.OperandPath(target, facts.CWD)]} {
			if form != "" && protectedFilePath(facts, actionfacts.PathFact{Resolved: form, Absolute: true}) {
				return true
			}
		}
		if resolved, ok := request.targetMemo.ResolveWriteTarget(hookpaths.OperandPath(target, facts.CWD)); ok &&
			protectedFilePath(facts, actionfacts.PathFact{Resolved: resolved, Absolute: true}) {
			return true
		}
	}
	return false
}

// shellCommandChangesPath reports a command that changes the path it
// names: a write, an append, a copy or move target, a delete, or a change of
// its mode, owner or other metadata. A read or a listing never does.
func shellCommandChangesPath(command actionfacts.CommandFact, path actionfacts.PathFact) bool {
	if integrityCommandMutatesPath(command, path) {
		return true
	}
	if command.Effect != actionfacts.EffectExecute {
		return false
	}
	switch path.Access {
	case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete, actionfacts.PathAccessMetadata:
		return true
	}
	return false
}

// shellCallUnresolved reports a shell call that the user-side hook could not
// place, makes a link, or moves,
// extracts or copies a tree in a way that may keep one, with its link reading
// unfinished (hookpaths.Links.Known): a name in it may then reach a protected
// file that its words do not show. The call keeps the rating of the rule pack
// (shellFileKept); a call that cannot alias files is judged by its words. A
// plain copy takes the content of a link, never the link.
func shellCallUnresolved(request trustedActionRequest) bool {
	// The user-side hook could not place a write of the call (an evaluated
	// or sourced value, a form it does not model): nothing proves it ordinary.
	switch request.ResolvedWriteTargets[hookpaths.UnprovenReasonKey] {
	case "trap", "function", "dynamic-command", "eval-source", "interpreter-path", "interpreter-argument", "shell-parse", "nested-shell":
		return true
	}
	return shellCallMakesOrCopiesLinks(request) || shellCallRunsUnseenCode(request.Input) ||
		request.ProtectedHomeHook && shellCallPlacementUnclear(request)
}

// shellCallRunsUnseenCode reports a call that sources a file, evaluates text,
// or hands a patch envelope to apply_patch through a computed word: code or
// targets no reader of the call can see.
func shellCallRunsUnseenCode(input actionfacts.Input) bool {
	command, ok := trustedBashCommandInput(input)
	if !ok {
		return false
	}
	command = shellCommentText.ReplaceAllString(command, " ")
	if sourceOrEvalWord.MatchString(command) {
		return true
	}
	return strings.Contains(command, "apply_patch") &&
		(strings.Contains(command, "$(") || strings.Contains(command, "`"))
}

var (
	// directoryChangeWord finds a word that moves the working directory of
	// the call (cd, pushd, popd, or a -C option).
	directoryChangeWord = regexp.MustCompile(`(^|[\s;&|(])(cd|pushd|popd)([\s;&|)]|$)|\s-C[\s=]`)
	// linkMakingWord finds ln or mklink as a command word, also in a shell
	// body the readers of the call do not enter.
	linkMakingWord = regexp.MustCompile(`(^|[\s;&|(])(ln|mklink)([\s;&|)]|$)`)
	// forWordList finds the word list of a for loop.
	forWordList = regexp.MustCompile(`\bfor\s+\w+\s+in\s[^;\n]*`)
	// sourceOrEvalWord finds source, a lone dot or eval as a command word.
	sourceOrEvalWord = regexp.MustCompile(`(^|[\s;&|(])(\.|source|eval)\s`)
	// shellCommentText finds a comment to the end of its line.
	shellCommentText = regexp.MustCompile(`(^|\s)#[^\n]*`)
	// powershellWord finds pwsh or powershell as a command word.
	powershellWord = regexp.MustCompile(`(^|[\s;&|(])(pwsh|powershell)(\.exe)?\s`)
)

// shellCallPlacementUnclear reports a call the managed gateway cannot place
// without the home of the user: a shell it does not read as POSIX, a change
// of the working directory, or a pattern in a word of the call outside a
// for-loop word list. The hook client reads such a call, but nothing proves
// its targets ordinary here, so the finding keeps the rating of the pack.
func shellCallPlacementUnclear(request trustedActionRequest) bool {
	input := request.Input
	facts := actionfacts.Analyze(input)
	command, ok := trustedBashCommandInput(input)
	if !ok || !trustedPOSIXShellCall(input, facts) {
		return true
	}
	command = shellCommentText.ReplaceAllString(command, " ")
	if directoryChangeWord.MatchString(command) || powershellWord.MatchString(command) {
		return true
	}
	return strings.Contains(forWordList.ReplaceAllString(command, " "), "*")
}

// shellCallMakesOrCopiesLinks reports the link and tree-copy half of
// shellCallUnresolved.
func shellCallMakesOrCopiesLinks(request trustedActionRequest) bool {
	input := request.Input
	facts := actionfacts.Analyze(input)
	tree, otherThanCopy := false, false
	for _, command := range facts.Commands {
		switch programBaseName(command.Program) {
		case "ln", "mklink", "link":
			return true
		case "mv", "tar", "unzip", "rsync", "cpio", "pax", "ditto", "7z", "7za", "bsdtar":
			tree, otherThanCopy = true, true
		case "cp", "install":
			tree = tree || linkKeepingCopyArgs(command.Argv)
		}
		for _, word := range command.Argv {
			word = strings.ToLower(word)
			if strings.Contains(word, "mklink") || strings.Contains(word, "symboliclink") ||
				strings.Contains(word, "junction") || strings.Contains(word, "hardlink") {
				return true
			}
		}
	}
	command, ok := trustedBashCommandInput(input)
	if !ok {
		return false
	}
	cwd := facts.CWD
	if !filepath.IsAbs(cwd) {
		cwd = request.ResolvedWriteTargets[hookpaths.CWDKey]
	}
	made := hookpaths.CommandLinksWithFacts(input.Tool, command, cwd, input.ActiveHome, request.ResolvedWriteTargets)
	if made.HasAliases() || linkMakingWord.MatchString(command) {
		return true
	}
	// A copy or move with a word the shell computes (a command substitution)
	// can take a link or flag from anywhere: its link reading is unfinished.
	if !tree && (strings.Contains(command, "$(") || strings.Contains(command, "`")) {
		for _, c := range facts.Commands {
			if fileMovingProgram(c.Program) {
				tree, otherThanCopy = true, true
				break
			}
		}
	}
	// A copy of trees that hold no link takes none: the sources are read as
	// the user-side hook read them (a managed gateway cannot see the home).
	if made.HasTreeCopies() {
		return otherThanCopy || !made.CopySourcesLinkFree(request.ResolvedWriteTargets)
	}
	return tree && !made.Known()
}

// linkKeepingCopyArgs reports the options of cp and install that copy a link
// as a link, or make one (archive, recursive, no-dereference, preserve links,
// hard and symbolic link modes).
func linkKeepingCopyArgs(argv []string) bool {
	for _, word := range argv {
		if strings.HasPrefix(word, "--") {
			switch strings.SplitN(word, "=", 2)[0] {
			case "--archive", "--recursive", "--no-dereference", "--link", "--symbolic-link", "--preserve":
				return true
			}
			continue
		}
		if strings.HasPrefix(word, "-") && strings.ContainsAny(word[1:], "aRrdPls") {
			return true
		}
	}
	return false
}

// fileMovingProgram reports a program that copies, moves or links a source
// operand to a destination.
func fileMovingProgram(program string) bool {
	return slices.Contains([]string{"cp", "mv", "ln", "install", "rsync", "ditto", "dd"}, programBaseName(program))
}

func programBaseName(word string) string {
	return strings.ToLower(filepath.Base(strings.ReplaceAll(word, "\\", "/")))
}

// protectedOperandName reports an operand that names a protected file by its
// last components: an authorized-keys file, the SSH folder, an SSH control
// file or private key below it, a shell startup profile, the Git hooks
// folder, and, with state, the DefenseClaw state folder (the target of a
// link). It reads the operand only: a comment or a data word of the call is
// never passed here.
func protectedOperandName(operand string, state bool) bool {
	operand = strings.ToLower(strings.NewReplacer("\\", "/", "\x27", "", "\"", "").Replace(operand))
	parts := strings.FieldsFunc(operand, func(r rune) bool { return r == rune(0x2f) })
	if len(parts) == 0 {
		return false
	}
	base := parts[len(parts)-1]
	parent := ""
	if len(parts) > 1 {
		parent = parts[len(parts)-2]
	}
	switch {
	case strings.HasPrefix(base, "authorized_keys"), strings.Contains(base, "administrators_authorized_keys"):
		return true
	case base == ".ssh", parent == ".ssh" && (slices.Contains(hookpaths.SSHControlFiles[:], base) || strings.HasPrefix(base, "id_")):
		return true
	case parent == ".git" && base == "hooks", parent == "hooks" && len(parts) > 2 && parts[len(parts)-3] == ".git", base == "hookspath":
		return true
	case slices.Contains(shellStartupNames, base), strings.Contains(base, "powershell_profile"):
		return true
	}
	return state && slices.Contains(parts, ".defenseclaw")
}

// shellStartupNames are the shell startup profiles of the user.
var shellStartupNames = []string{
	".bashrc", ".bash_profile", ".bash_login", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".profile",
	"config.fish", "profile.ps1", "profile",
}

// placedPath is the absolute spelling of a path fact in cwd.
func placedPath(path actionfacts.PathFact, cwd string) string {
	value := path.Resolved
	if value == "" {
		value = path.Normalized
	}
	if value == "" {
		value = path.Value
	}
	return hookpaths.OperandPath(value, cwd)
}

// protectedFilePath reports a path of the files of the shell-command
// protected-file class under the active home: the authorized-keys files, the
// SSH control files, an SSH private key, a shell startup profile and an
// active Git hook.
func protectedFilePath(facts actionfacts.Facts, path actionfacts.PathFact) bool {
	if matchesAuthorizedKeys(facts, path) || matchesActiveSSHPrivateKey(facts, path) ||
		matchesActiveShellProfile(facts, path) || matchesActiveGitHook(facts, path) {
		return true
	}
	relative, ok := activeHomeRelative(facts, path)
	if !ok {
		return false
	}
	for _, name := range hookpaths.SSHControlFiles {
		if relative == ".ssh/"+name {
			return true
		}
	}
	return false
}

// shellCommandMayReachState reports a shell call that may write the
// DefenseClaw state: the state target scan places a target in the active
// state (it follows the links on disk), a word of the command is an existing
// link into it, or the hook client resolved a write target below the state
// folder of the active home. Each answer over-matches: a false answer only
// keeps the block the call had before GAP-0675. The words and comments of the
// command do not count unless they place a target (rel-1-0-6:GAP-0675 review 2).
func shellCommandMayReachState(request trustedActionRequest) bool {
	input := request.Input
	if home := strings.TrimSpace(input.ActiveHome); home != "" {
		state := strings.ToLower(filepath.ToSlash(filepath.Join(home, ".defenseclaw")))
		for _, target := range request.ResolvedWriteTargets {
			if lower := strings.ToLower(filepath.ToSlash(target)); lower == state || strings.HasPrefix(lower, state+"/") {
				return true
			}
		}
	}
	command, ok := trustedBashCommandInput(input)
	if !ok || request.SkipLocalFilesystemResolution {
		return false
	}
	return request.targetMemo.ActionStateTargetMention(command, input.CWD, input.ActiveHome) ||
		commandWordLinksIntoState(command, input.CWD, input.ActiveHome)
}

// commandWordLinksIntoState reports a word of command that names an existing
// link whose target is the DefenseClaw state folder of home or below it:
// a command can make its own link to such a link and write through it after
// a cd the readers cannot place. One readlink per word, on at most
// stateLinkWordsMax words; it over-matches (a read through the link counts).
func commandWordLinksIntoState(command, cwd, home string) bool {
	home = strings.TrimSpace(home)
	if home == "" {
		return false
	}
	state := filepath.Clean(filepath.Join(home, ".defenseclaw"))
	return commandWordLinks(command, cwd, home, func(target string) bool {
		target = filepath.Clean(target)
		return strings.EqualFold(target, state) ||
			strings.HasPrefix(strings.ToLower(target), strings.ToLower(state)+string(filepath.Separator))
	})
}

// commandWordLinks reports a word of command that names an existing link
// whose absolute target accepts allows.
func commandWordLinks(command, cwd, home string, accepts func(target string) bool) bool {
	home = strings.TrimSpace(home)
	words := strings.FieldsFunc(command, func(r rune) bool {
		return strings.ContainsRune(" \t\n;&|()\"<>=\x27", r)
	})
	for index, word := range words {
		if index == stateLinkWordsMax {
			return false
		}
		if rest, ok := strings.CutPrefix(word, "~/"); ok && home != "" {
			word = filepath.Join(home, rest)
		}
		if !filepath.IsAbs(word) {
			if cwd == "" {
				continue
			}
			word = filepath.Join(cwd, word)
		}
		target, err := os.Readlink(word)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(word), target)
		}
		if accepts(target) {
			return true
		}
	}
	return false
}

// stateLinkWordsMax bounds the words commandWordLinksIntoState reads.
const stateLinkWordsMax = 256

// selfProtectionRules are the rules that protect DefenseClaw itself: a
// write, append, delete or metadata change of its state, configuration,
// hooks, policies, receipts and registries (tamper.detector_state_write and
// the active-state owners that report it). An enforcing finding of these
// rules blocks in every profile, permissive included, per-user and managed
// (rel-1-0-6:GAP-0675 review 1 M3a).
var selfProtectionRules = map[string]bool{
	"TAMPER.DETECTOR_STATE_WRITE": true,
}

// profileClassFindings is the one place a rule-pack posture decides the
// shell-command protected-file class and DefenseClaw self-protection
// (rel-1-0-6:GAP-0675). It returns the findings to map with the thresholds
// and the least action the request gets whatever the thresholds say:
//   - a self-protection finding that could block: block, in every profile;
//   - a class finding that could block: outside the strict posture it is
//     capped at an alert, so the command runs, the agent shows the alert with
//     the rule id and the audit row records decision=alert; in every posture
//     it is at least an alert, so the permissive profile never allows it
//     silently; the strict posture keeps it as it is (it blocks).
//
// A finding that could not block (detection-only, alert-only, allowed) stays
// as it was. The Secure Client integration is unchanged: Cisco AI Defense
// decides there. posture is read only when a class finding is present.
func profileClassFindings(findings []RuleFinding, secureClient bool, posture func() string) ([]RuleFinding, string) {
	floor := guardrailActionAllow
	if secureClient {
		return findings, floor
	}
	class := false
	for _, finding := range findings {
		if !finding.contributesToEnforcement() {
			continue
		}
		if selfProtectionRules[canonicalTrustedRuleID(finding.RuleID)] {
			floor = guardrailActionBlock
		} else if finding.shellFile == shellFileProven {
			// A target the call proves (named, or reached through a value or a
			// link the call or the disk shows) is a protected file written:
			// every profile blocks it, whatever the pack rates the rule.
			floor = guardrailActionBlock
		} else if finding.shellFile != shellFileNone {
			class = class || finding.shellFile == shellFileUnproven
			floor = strongerGuardrailAction(floor, guardrailActionAlert)
		}
	}
	if !class || posture() == config.HookPolicyTierStrict {
		return findings, floor
	}
	capped := slices.Clone(findings)
	for index := range capped {
		if capped[index].shellFile == shellFileUnproven && capped[index].contributesToEnforcement() {
			capped[index].enforcement = findingEnforcementAlertOnly
		}
	}
	return capped, floor
}

// rulePackPostureForConnector is the posture of the rule pack of connector
// in cfg, as its thresholds read it (resolveThresholds).
func rulePackPostureForConnector(cfg *config.Config, connector string) func() string {
	return func() string {
		var ref config.RulePackRef
		if cfg != nil {
			ref = cfg.EffectiveRulePackRefForConnector(connector)
		}
		if cfg == nil {
			return config.HookPolicyTierDefault
		}
		return packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref))
	}
}

// guardrailRulePackPosture is rulePackPostureForConnector for a caller that
// holds only the guardrail block (resolveGuardrailThresholds).
func guardrailRulePackPosture(gc *config.GuardrailConfig, connector string) func() string {
	return func() string {
		var ref config.RulePackRef
		if gc != nil {
			ref = gc.EffectiveRulePackRef(connector)
		}
		if gc == nil {
			return config.HookPolicyTierDefault
		}
		return packPosture(ref, guardrailRulePackDir(gc, ref))
	}
}
