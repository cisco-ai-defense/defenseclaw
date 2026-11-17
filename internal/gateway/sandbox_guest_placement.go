// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"mvdan.cc/sh/v3/syntax"
)

// maxSandboxGuestCandidateDirs bounds the directories a sandbox call may
// stand in that the guest placement keeps as candidates
// (sandboxGuestPlacements): the 64 places the laptop's statement reader
// keeps (hookpaths.TopLevelStatements). Past it the oldest candidate other
// than the guest's own directory is dropped.
const maxSandboxGuestCandidateDirs = 64

// maxSandboxGuestPlacements bounds the readings of one pass of the guest
// placement: every statement the call's budget allows
// (maxSandboxGuestPlacedChildren) in every candidate directory, so a call
// within the laptop's statement budget is never cut by it. Only a call the
// laptop does not count (a here-string call parses invalid, rel-1-0-10
// statement budget) can reach it, and is then cut (fail-closed).
const maxSandboxGuestPlacements = maxSandboxGuestPlacedChildren * maxSandboxGuestCandidateDirs

// guestPlacement is one command text and the directory it is read in.
// candidate marks a directory the call may stand in only by a cd target that
// no command of the call is read in (a cd in a subshell or a function body,
// CDPATH): that reading judges only what the laptop's readers judge on a
// candidate directory, the private-key read proof and the hook-config write
// (sandboxGuestPlacedChildren, sandboxAgentHookConfigChange); every other
// owner keeps the directories the call's commands run in, so
// (cd ~/.defenseclaw || cd /tmp) && eval 'echo m > config.yaml' writes the
// starting directory's config.yaml, as on the laptop (S7's no-block rows).
type guestPlacement struct {
	text, cwd string
	candidate bool
}

// sandboxGuestPlacements lists, lexically, the commands of a sandbox call
// (input is placed in the guest's working directory, sandboxGuestPlacedInput)
// with each directory they may run in, for the guest placement
// (sandboxGuestPlacedChildren) and the sandbox hook-config guard
// (sandboxAgentHookConfigChange). A text repeated in the same directory is
// listed once. cut reports a call whose readings stop short; the caller
// gives it the evaluation-limit finding, never a clean allow
// (substrate-1 GAP-0304).
//
// A call the analysis read in full lists each simple command a static cd
// moved out of the guest's directory, in that directory, up to
// maxSandboxGuestPlacedChildren readings: its whole-call view judges the
// rest.
//
// A call the analysis did not read in full has no whole-call view that
// judges it (substrate-1 GAP-0363):
//   - A hook call that carries the command only in its arguments (Claude
//     Code) is split from its text: the split of an Args-only call the POSIX
//     reader rejects (a here-string, <(...), . /dev/stdin) placed nothing, so
//     a read after pushd, popd, cd -, { cd x; } or a function body went
//     unread (substrate-1 GAP-0378).
//   - Each simple command is read in its own directory and in every
//     directory the call stood in before it, the guest's included, and each
//     command of the script (a function body's too, guestScriptCalls) in
//     each of those directories and in each static cd or pushd target
//     (guestCDTargets) as a candidate: the CD-CANDIDATE rule of the laptop's
//     readers, which keep the earlier directories where the directory is
//     uncertain ((cd x), cd -, popd, CDPATH, a function that cds, a cd after
//     $CMD; substrate-1 GAP-0379). At most maxSandboxGuestCandidateDirs
//     directories are kept.
//   - Its top-level statements are read too, each in every directory the
//     laptop's statement reader places it (hookpaths.TopLevelStatements).
//
// Such a call is counted by statements, not readings: each pass is cut at
// maxSandboxGuestPlacedChildren statements only when the call is over the
// laptop's own statement budget (trustedCallOverStatementBudget, the call
// as the hook sent it), which gives the laptop the same limit. Charging
// every reading to that cap cut a script of 63 statements after one cd (two
// places each) where the laptop judges it in full (substrate-1 GAP-0377).
// The readings of a pass are bounded at maxSandboxGuestPlacements. The
// hook-config guard passes statementBudget false: like the laptop guard it
// reads a call past the statement budget too, so the call that carries the
// limit finding still names the write (substrate-1 GAP-0359).
func sandboxGuestPlacements(input actionfacts.Input, facts actionfacts.Facts, statementBudget bool) (placements []guestPlacement, cut bool) {
	type key struct{ text, cwd string }
	seen := map[key]int{}
	if facts.Authoritative() {
		for _, simple := range actionfacts.SimpleCommands(input, facts) {
			cwd := simple.CWD
			if guestPlacementSkips(simple) || !path.IsAbs(cwd) || cwd == input.CWD {
				continue
			}
			if _, ok := seen[key{simple.Text, cwd}]; ok {
				continue
			}
			if len(placements) == maxSandboxGuestPlacedChildren {
				return placements, true
			}
			seen[key{simple.Text, cwd}] = len(placements)
			placements = append(placements, guestPlacement{text: simple.Text, cwd: cwd})
		}
		return placements, false
	}
	overBudget := statementBudget && trustedCallOverStatementBudget(input, facts)
	if input.Command == "" {
		if command, ok := trustedBashCommandInput(input); ok {
			input.Command, input.Args, input.Argv = command, nil, nil
			facts = actionfacts.Analyze(input)
		}
	}
	// pass counts the statements and readings of one pass.
	type pass struct {
		statements map[string]bool
		read       int
	}
	place := func(p *pass, text, cwd string, candidate bool) bool {
		if at, ok := seen[key{text, cwd}]; ok {
			placements[at].candidate = placements[at].candidate && candidate
			return true
		}
		if !p.statements[text] {
			if overBudget && len(p.statements) == maxSandboxGuestPlacedChildren {
				return false
			}
			p.statements[text] = true
		}
		if p.read == maxSandboxGuestPlacements {
			return false
		}
		p.read++
		seen[key{text, cwd}] = len(placements)
		placements = append(placements, guestPlacement{text: text, cwd: cwd, candidate: candidate})
		return true
	}
	// dirs are the directories the call's commands run in, targets the cd
	// targets no command is read in yet; each keeps the guest's directory
	// or its oldest entry past the bound.
	keep := func(list []string, dir string) []string {
		if !path.IsAbs(dir) || slices.Contains(list, path.Clean(dir)) {
			return list
		}
		if len(list) == maxSandboxGuestCandidateDirs {
			list = slices.Delete(list, 1, 2)
		}
		return append(list, path.Clean(dir))
	}
	var dirs, targets []string
	dirs = keep(dirs, input.CWD)
	targets = keep(targets, input.CWD)
	simples := &pass{statements: map[string]bool{}}
	for _, simple := range actionfacts.SimpleCommands(input, facts) {
		if guestPlacementSkips(simple) {
			continue
		}
		cwd := simple.CWD
		if path.IsAbs(cwd) && !place(simples, simple.Text, cwd, false) {
			return placements, true
		}
		for _, dir := range dirs {
			if !place(simples, simple.Text, dir, false) {
				return placements, true
			}
		}
		for _, dir := range targets {
			if !place(simples, simple.Text, dir, true) {
				return placements, true
			}
		}
		bases := slices.Concat(dirs, targets)
		if path.IsAbs(cwd) {
			bases = []string{cwd}
		}
		// The split gives a cd the directory its walk reached, as if every
		// cd before it ran: (cd ~/.defenseclaw || cd /tmp) runs cd /tmp only
		// where the first cd failed. A directory change's own directory is
		// a candidate; the directory of any other command is one the call
		// runs in.
		if guestChangesDirectory(simple.Text, input.ActiveHome) {
			targets = keep(targets, cwd)
		} else {
			dirs = keep(dirs, cwd)
		}
		for _, target := range guestCDTargets(simple.Text, bases, input.ActiveHome) {
			targets = keep(targets, target)
		}
	}
	command := input.Command
	if command == "" || len(command) > agentHookConfigMaxPlacedBytes {
		return placements, false
	}
	if statements, ok := hookpaths.TopLevelStatements(command, input.CWD, input.ActiveHome); ok {
		top := &pass{statements: map[string]bool{}}
		for _, statement := range statements {
			if path.IsAbs(statement.Dir) && !place(top, statement.Command, statement.Dir, false) {
				return placements, true
			}
		}
	}
	// Every call of the script, a function body's included: the split stops
	// at a construct it cannot read (f() { cd .cache; }; f; $CMD gives one
	// parse failure), while a static cd anywhere in the text is still a
	// directory the laptop's readers keep.
	calls := &pass{statements: map[string]bool{}}
	for _, call := range guestScriptCalls(command) {
		for _, dir := range dirs {
			if !place(calls, call.text, dir, false) {
				return placements, true
			}
		}
		for _, dir := range targets {
			if !place(calls, call.text, dir, true) {
				return placements, true
			}
		}
		for _, target := range guestCDTargets(call.text, slices.Concat(dirs, targets), input.ActiveHome) {
			targets = keep(targets, target)
		}
	}
	return placements, false
}

// guestPlacementSkips reports a simple command the guest placement does not
// read: one with no complete view, an opaque assignment, literal output, or
// a guessed login.
func guestPlacementSkips(simple actionfacts.SimpleCommand) bool {
	return simple.EvaluationFailure != "" || simple.OpaqueValueAssignment || simple.LiteralOutputOnly || simple.LoginGuess
}

// guestChangesDirectory reports, lexically, a cd, pushd or popd command
// text.
func guestChangesDirectory(text, home string) bool {
	call, ok := guestCall(text)
	if !ok {
		return false
	}
	program, static := hookpaths.StaticWord(call.Args[0], home)
	return static && (program == "cd" || program == "pushd" || program == "popd")
}

// guestCall parses a command text that is one simple command.
func guestCall(text string) (*syntax.CallExpr, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil || len(file.Stmts) != 1 {
		return nil, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	return call, ok && len(call.Args) != 0
}

// guestCDTargets returns, lexically, the directories a cd or pushd command
// text moves to from each of bases: a static operand joined to each base,
// an absolute or ~ operand as it is, the home for a bare cd. A dynamic
// operand, cd - and popd add none (they return to a directory already a
// candidate, or to one no static word names).
func guestCDTargets(text string, bases []string, home string) []string {
	call, ok := guestCall(text)
	if !ok {
		return nil
	}
	program, static := hookpaths.StaticWord(call.Args[0], home)
	if !static || program != "cd" && program != "pushd" {
		return nil
	}
	operand := ""
	for _, word := range call.Args[1:] {
		value, static := hookpaths.StaticWord(word, home)
		if !static {
			return nil
		}
		if value == "--" || operand == "" && strings.HasPrefix(value, "-") && value != "-" {
			continue
		}
		operand = value
		break
	}
	switch {
	case operand == "-":
		return nil
	case operand == "" || operand == "~":
		if path.IsAbs(home) {
			return []string{path.Clean(home)}
		}
		return nil
	case strings.HasPrefix(operand, "~/") && path.IsAbs(home):
		return []string{path.Join(home, operand[2:])}
	case path.IsAbs(operand):
		return []string{path.Clean(operand)}
	}
	var targets []string
	for _, base := range bases {
		if path.IsAbs(base) {
			targets = append(targets, path.Join(base, operand))
		}
	}
	return targets
}

// guestScriptCall is the source text of one call of a script.
type guestScriptCall struct{ text string }

// guestScriptCalls returns, in source order, the source text of every
// simple-command statement of a Bash script, with its redirections, nested
// ones included (a function body, a group, a subshell, a process
// substitution), lexically; nil when the script does not parse.
func guestScriptCalls(command string) []guestScriptCall {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	var calls []guestScriptCall
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		if call, isCall := stmt.Cmd.(*syntax.CallExpr); !isCall || len(call.Args) == 0 {
			return true
		}
		// The statement's span keeps its redirections (> ../.claude/settings.json).
		start, end := int(stmt.Pos().Offset()), int(stmt.End().Offset())
		if start >= 0 && end <= len(command) && start < end {
			calls = append(calls, guestScriptCall{text: command[start:end]})
		}
		return true
	})
	return calls
}
