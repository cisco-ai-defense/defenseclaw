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
// keeps (hookpaths.TopLevelStatements). Past it the directories already kept
// stay and a later one is not added, as the laptop's private-key reader
// keeps its first candidate directories (actionPosixPrivateKeyRead): an
// earlier cd target a later relative read depends on is never dropped.
// Dropping the oldest one let cd .cache, a here-string, 63 cd /tmp/x && ls
// and cat ../.ssh/id_ed25519 read the guest's key where the laptop blocks
// (substrate-1 GAP-0499).
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
// moved out of the guest's directory, in each directory the walk places it,
// up to maxSandboxGuestPlacedChildren statements (and
// maxSandboxGuestPlacements readings): its whole-call view judges the rest.
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
		// Counted by statements, as the laptop counts them: the walk reads a
		// command after a cd that may not run in every directory it may run
		// in, so after three such cds each later command has seven readings
		// outside the guest's directory, and a cap on readings cut a 24-line
		// script the laptop allows (a here-string call, judged by its
		// authoritative twin, substrate-1 GAP-0377).
		statements := map[string]bool{}
		for _, simple := range actionfacts.SimpleCommands(input, facts) {
			cwd := simple.CWD
			if guestPlacementSkips(simple) || !path.IsAbs(cwd) || cwd == input.CWD {
				continue
			}
			if _, ok := seen[key{simple.Text, cwd}]; ok {
				continue
			}
			if !statements[simple.Text] {
				if len(statements) == maxSandboxGuestPlacedChildren {
					return placements, true
				}
				statements[simple.Text] = true
			}
			if len(placements) == maxSandboxGuestPlacements {
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
	// targets no command is read in yet; each keeps its first
	// maxSandboxGuestCandidateDirs entries, the guest's directory first
	// (substrate-1 GAP-0499).
	keep := func(list []string, dir string) []string {
		if !path.IsAbs(dir) || len(list) == maxSandboxGuestCandidateDirs || slices.Contains(list, path.Clean(dir)) {
			return list
		}
		return append(list, path.Clean(dir))
	}
	var dirs, targets []string
	dirs = keep(dirs, input.CWD)
	targets = keep(targets, input.CWD)
	// A pass first lists its readings in source order, as the folders evolve,
	// then places those whose text may name a path in another folder
	// before the rest (guestReadingFirst): when the readings bound cuts a
	// pass, it cuts touch f1 ... touch f150, not the cat ../.ssh/id_ed25519
	// after them, which read keeps the laptop's block next to the limit
	// (substrate-1 GAP-0501).
	type pending struct {
		text, cwd string
		candidate bool
	}
	// collect keeps the distinct readings of a pass, at most
	// maxSandboxGuestPlacements. Past the bound the pass is cut (dropped): a
	// plain reading is not kept, and a first reading (guestReadingFirst)
	// takes the place of the last plain one kept, so the list stays at the
	// bound (substrate-1 GAP-0624: a here-string call listed ~200k readings)
	// and a protected tail is still read next to the limit (GAP-0501).
	// plain holds the indexes of the plain readings kept; listed maps each
	// reading kept to its index.
	//
	// A reading listed as a candidate that comes again in a directory the
	// call runs in is no longer a candidate: every owner reads it, as place
	// does for a reading placed twice. The split reads a body after a cd that
	// may fail in each folder the chain may leave (rel-1-0-10:GAP-1144), so
	// cd ~/.defenseclaw || cd /tmp && sh -c 'x=config.yaml; echo m > $x'
	// gives echo m > 'config.yaml' in ~/.defenseclaw after the earlier cd
	// listed that folder as a target. Kept as a candidate, judged only for a
	// private-key read and a hook-config write, it let the actor allow the
	// write the laptop blocks with tamper.detector_state_write
	// (substrate-1 GAP-0645).
	collect := func(list []pending, listed map[key]int, plain *[]int, dropped *bool, reading pending) []pending {
		at := key{reading.text, reading.cwd}
		if index, ok := listed[at]; ok {
			list[index].candidate = list[index].candidate && reading.candidate
			return list
		}
		first := guestReadingFirst(reading.text)
		if len(list) >= maxSandboxGuestPlacements {
			*dropped = true
			if !first || len(*plain) == 0 {
				return list
			}
			last := (*plain)[len(*plain)-1]
			*plain = (*plain)[:len(*plain)-1]
			delete(listed, key{list[last].text, list[last].cwd})
			listed[at] = last
			list[last] = reading
			return list
		}
		if !first {
			*plain = append(*plain, len(list))
		}
		listed[at] = len(list)
		return append(list, reading)
	}
	placeAll := func(p *pass, list []pending) bool {
		for _, first := range []bool{true, false} {
			for _, reading := range list {
				if guestReadingFirst(reading.text) == first && !place(p, reading.text, reading.cwd, reading.candidate) {
					return false
				}
			}
		}
		return true
	}
	simples := &pass{statements: map[string]bool{}}
	var simpleReadings []pending
	simplesDropped, simplesListed := false, map[key]int{}
	var simplesPlain []int
	// stoodIn is the folder of the last command that is not a directory
	// change, held until the next command of the split shows whether the
	// call still stands there. When the split places the next command in
	// another folder with no directory change between them, a ( ... )
	// group, a pipeline stage before the last or a command substitution
	// ended: its folder is a candidate for the later commands (the
	// laptop's CD-CANDIDATE rule), not a folder they run in. Kept as a
	// folder the call runs in,
	// it gave (cd ~/.defenseclaw && ls); echo m > config.yaml the reading
	// echo m > config.yaml in ~/.defenseclaw, and the actor blocked with
	// tamper.detector_state_write where the laptop allows
	// (substrate-1 GAP-0648). A next reading in another folder the same
	// statement may run in (OtherFolder), or in a folder the split cannot
	// tell, settles nothing: the folder stays one the call runs in.
	// The folder of a command in the last stage of a pipeline or in an &
	// list (LastStageOrBackground) is one the call runs in at once, as
	// before GAP-0648: zsh and Bash with lastpipe run the last stage in the
	// shell itself, and the laptop keeps both folders, so
	// true | { cd ~/.claude && ls; }; echo x > settings.json keeps the
	// laptop's tamper.agent_hook_config_write alert (GAP-0648 review P2-1).
	stoodIn, standing := "", false
	settle := func(simple actionfacts.SimpleCommand) {
		if !standing || simple.OtherFolder {
			return
		}
		standing = false
		if !simple.UnresolvedFolder && path.IsAbs(simple.CWD) && path.Clean(simple.CWD) != stoodIn {
			targets = keep(targets, stoodIn)
			return
		}
		dirs = keep(dirs, stoodIn)
	}
	for _, simple := range actionfacts.SimpleCommands(input, facts) {
		settle(simple)
		if guestPlacementSkips(simple) {
			continue
		}
		cwd := simple.CWD
		if path.IsAbs(cwd) {
			simpleReadings = collect(simpleReadings, simplesListed, &simplesPlain, &simplesDropped, pending{simple.Text, cwd, false})
		}
		for _, dir := range dirs {
			simpleReadings = collect(simpleReadings, simplesListed, &simplesPlain, &simplesDropped, pending{simple.Text, dir, false})
		}
		for _, dir := range targets {
			simpleReadings = collect(simpleReadings, simplesListed, &simplesPlain, &simplesDropped, pending{simple.Text, dir, true})
		}
		bases := slices.Concat(dirs, targets)
		if path.IsAbs(cwd) {
			bases = []string{cwd}
		}
		// The split gives a cd the directory its walk reached, as if every
		// cd before it ran: (cd ~/.defenseclaw || cd /tmp) runs cd /tmp only
		// where the first cd failed. A directory change's own directory is
		// a candidate; the directory of any other command is one the call
		// runs in, once the next command shows the call still stands there
		// (stoodIn).
		switch {
		case guestChangesDirectory(simple.Text, input.ActiveHome):
			targets = keep(targets, cwd)
		case simple.OtherFolder || simple.UnresolvedFolder || simple.LastStageOrBackground || !path.IsAbs(cwd):
			dirs = keep(dirs, cwd)
		default:
			stoodIn, standing = path.Clean(cwd), true
		}
		for _, target := range guestCDTargets(simple.Text, bases, input.ActiveHome) {
			targets = keep(targets, target)
		}
	}
	if standing {
		dirs = keep(dirs, stoodIn)
	}
	// A cut pass does not end the others: each has its own bound, and the
	// call is reported cut.
	simplesCut := !placeAll(simples, simpleReadings) || simplesDropped
	command := input.Command
	if command == "" || len(command) > agentHookConfigMaxPlacedBytes {
		return placements, simplesCut
	}
	topCut := false
	if statements, ok := hookpaths.TopLevelStatements(command, input.CWD, input.ActiveHome); ok {
		top := &pass{statements: map[string]bool{}}
		for _, statement := range statements {
			if path.IsAbs(statement.Dir) && !place(top, statement.Command, statement.Dir, false) {
				topCut = true
				break
			}
		}
	}
	// Every call of the script, a function body's included: the split stops
	// at a construct it cannot read (f() { cd .cache; }; f; $CMD gives one
	// parse failure), while a static cd anywhere in the text is still a
	// directory the laptop's readers keep.
	calls := &pass{statements: map[string]bool{}}
	var callReadings []pending
	callsDropped, callsListed := false, map[key]int{}
	var callsPlain []int
	for _, call := range guestScriptCalls(command) {
		for _, dir := range dirs {
			callReadings = collect(callReadings, callsListed, &callsPlain, &callsDropped, pending{call, dir, false})
		}
		for _, dir := range targets {
			callReadings = collect(callReadings, callsListed, &callsPlain, &callsDropped, pending{call, dir, true})
		}
		for _, target := range guestCDTargets(call, slices.Concat(dirs, targets), input.ActiveHome) {
			targets = keep(targets, target)
		}
	}
	callsCut := !placeAll(calls, callReadings) || callsDropped
	return placements, simplesCut || topCut || callsCut
}

// guestReadingFirst reports a command text whose reading in another folder
// may reach a different protected path: a word with a dot or a slash
// (../.ssh/id_ed25519, .bashrc, a/b), a ~, an expansion or a pattern. A text
// of plain words (touch f1, ls, cd sub) is read after them.
func guestReadingFirst(text string) bool {
	return strings.ContainsAny(text, "./~$`*?[{\\")
}

// withSandboxGuestFolderTier gives a sandbox call the unknown tier the
// laptop gives the same call in its own folder (withUnresolvedFolderTier,
// rel-1-0-10:GAP-0871): an operand that may name a protected file in a
// folder the call does not give, after a function that cds or a $CMD. A
// copy-mode call names no folder, so the tier is read on the call placed in
// the guest's working directory (sandboxGuestPlacedInput), as the laptop
// reads it in its own. It is decided on that whole-call reading alone: the
// commands the guest placement reads one by one (sandboxGuestPlacements) are
// the laptop's piece readings, whose proof comes after the laptop's tier, so
// their proof does not take the tier away here either. f() { cd .cache; };
// f; $CMD; rm .defenseclaw/audit.db blocked in both, and only the laptop
// named ACTION-COMPOUND-LIMIT (substrate-1 GAP-0377 at FU8). The reading is
// lexical and only adds a finding.
func withSandboxGuestFolderTier(findings []RuleFinding, request trustedActionRequest, facts actionfacts.Facts) []RuleFinding {
	if request.simpleCommandPass || request.hostTwinDepth != 0 || request.stateProofOnly {
		return findings
	}
	guest, ok := sandboxGuestPlacedInput(request, facts)
	if !ok {
		return findings
	}
	guestFacts := actionfacts.Analyze(guest)
	if !guestFacts.MayRunInUnresolvedFolder() {
		return findings
	}
	placed := request
	placed.Input, placed.SandboxGuestCWD = guest, ""
	return withSimpleCommandFindings(findings, withUnresolvedFolderTier(nil, placed, guestFacts, false))
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

// guestCallRunsUnreadCommand reports, lexically, a script with a command the
// statement split cannot read and that may change the folder: a program word
// that is not static ($CMD), or one of cmdRedefiningCommands (eval, source,
// ., trap, alias, ...) or mapfile and readarray (-C runs a string), also
// behind builtin, command or exec (the sandbox hook-config guard,
// substrate-1 GAP-0500). A script that does not parse counts, and so does a
// wrapper with options.
func guestCallRunsUnreadCommand(command, home string) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return true
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if found || !ok || len(call.Args) == 0 {
			return !found
		}
		for index, word := range call.Args {
			program, static := hookpaths.StaticWord(word, home)
			if !static || cmdRedefiningCommands[program] || program == "mapfile" || program == "readarray" {
				found = true
				break
			}
			// builtin, command and exec run the word after their options.
			if (program != "builtin" && program != "command" && program != "exec") || index == len(call.Args)-1 {
				break
			}
			if next, known := hookpaths.StaticWord(call.Args[index+1], home); known && strings.HasPrefix(next, "-") {
				found = true // an option word: read it as unread rather than parse every wrapper option
				break
			}
		}
		return !found
	})
	return found
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

// guestScriptCalls returns, in source order, the source text of every
// simple-command statement of a Bash script, with its redirections, nested
// ones included (a function body, a group, a subshell, a process
// substitution), lexically; nil when the script does not parse.
func guestScriptCalls(command string) []string {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	var calls []string
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
			calls = append(calls, command[start:end])
		}
		return true
	})
	return calls
}
