// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// SimpleCommand is one command of a shell action, with the directory in
// which it runs. Its text is independently suitable for Analyze.
type SimpleCommand struct {
	Text string
	CWD  string
	// OpaqueValueAssignment has no command word outside a balanced value.
	// Its contents can run code that the PowerShell reader cannot analyze.
	// The child pass is skipped because it cannot read inside that value.
	OpaqueValueAssignment bool
	// LiteralOutputOnly is a Write-Output with inert literal arguments. The
	// whole action has already been analyzed; a child pass adds no evidence.
	LiteralOutputOnly bool
	// ZshHistoryBuiltin marks a history command in an explicitly invoked zsh
	// body. Zsh history is fc -l, so Bash's history -c clear grammar does not
	// apply to this child.
	ZshHistoryBuiltin bool
	// ResolvedVariable means the walk replaced a parameter of the statement by
	// the value it followed (d=ordinary; cp a build/$d.txt reads
	// build/ordinary.txt). A gateway judges the resolved path, which the
	// command text of a hook client does not spell.
	ResolvedVariable bool
	// UnresolvedBoundVariable means a parameter in Text is bound elsewhere
	// in the action but this walk could not carry its value into Text. The
	// original action decides the protected-write class for that value.
	UnresolvedBoundVariable bool
	// LoginGuess means this reading holds a value USER or LOGNAME has only as
	// the guess that the login is the last element of the home, or the value
	// one word of a for or while-read list gives its variable in one iteration
	// (simpleForkLoopBind). A rule over the words of the command must not read
	// it (the shell may hold another login or run another iteration); it only
	// proves a write to protected state.
	LoginGuess bool
	// LoopReading marks a LoginGuess reading that is one iteration of a loop
	// variable. Its path is spelled in the reading, so a managed hook client
	// has no evidence keyed for it: the text decides whether it can name state.
	LoopReading bool
	// UnboundUser means Text names USER or LOGNAME after a binding the walk
	// cannot follow (read, a loop, eval): the value is unknown, not the
	// login the home spells. A reader may keep the guess that the name is
	// that login for the spelling of the path, but a file it reaches only
	// through a link on disk is not a file the command names
	// (rel-1-0-6:GAP-0601 review 5).
	UnboundUser bool
	// OtherFolder marks the reading of a statement in another folder it may
	// run in, after a cd that may fail (rel-1-0-10:GAP-0869): a reading,
	// not a further statement of the call.
	OtherFolder bool
	// bodyReading marks a reading of a nested body statement in another
	// folder its call may run in (rel-1-0-10:GAP-1144): it does not count
	// against the evaluation budget of the statements of the call, which
	// it would otherwise push into the limit (GAP-1228).
	bodyReading bool
	// UnresolvedFolder means the directory of the command is unknown and an
	// operand of Text depends on it: the gateway reads it in each folder
	// that holds a protected file (rel-1-0-10:GAP-0871).
	UnresolvedFolder bool
	// cappedFolders are, for the UnresolvedFolder reading of a Windows
	// statement past maxSimpleWindowsOtherReadings, the folders it was not
	// read in (CappedFolders). A pointer keeps the type comparable.
	cappedFolders *[]string
	// AbsoluteOnly means the directory of the command is unknown (an eval,
	// an unreadable cd) and no operand of Text depends on it: CWD is empty,
	// and the directory the action starts in judges the command as well as
	// any other (rel-1-0-6:GAP-0630 review 5).
	AbsoluteOnly bool
	// UnprovenHome means Text reads a file through ~ or $HOME after HOME got
	// a value the walk could not read (HOME=$(pwd); cp ~/../f d): Text spells
	// the previous home, and the file the shell reads is known only when it
	// runs. A reader judges Text and adds the unknown tier
	// (rel-1-0-10:GAP-0996). A write there is judged against the previous
	// home only (GAP-2476): a scratch HOME=$(mktemp -d) keeps its writes.
	UnprovenHome bool
	// LastStageOrBackground marks a command in the last stage of a pipeline
	// or in a statement run in the background (&), or in a body such a
	// command runs. Bash runs it in a subshell, so the walk drops a folder
	// it moves to there, but zsh and Bash with lastpipe run the last stage
	// in the shell itself, and the laptop's readers keep that folder for the
	// later commands; the copy-mode guest placement keeps it as a folder the
	// call runs in (substrate-1 GAP-0648 review P2-1). It is no other
	// reading: a piece of the call is the same piece without it.
	LastStageOrBackground bool
	// EvaluationFailure is "limit" or "parse" when no complete per-command
	// view can be produced, EvaluationFailureInternal when the reader
	// itself failed, and EvaluationFailureSyntax when a text with a syntax
	// error was read only in part. A parse gap is not an action refusal.
	EvaluationFailure string
}

// EvaluationFailureSyntax is the EvaluationFailure that closes the readings
// of a text the shell parser rejects with a syntax error, at the top level or
// in a static eval or shell -c body (shellparse.ReadSyntaxTail): its
// readable statements come before it, each judged as any other command, and
// what was not read is recorded by the gateway as an unread part, which
// does not raise the verdict (rel-1-0-10:GAP-0526).
const EvaluationFailureSyntax = "syntax"

// EvaluationFailureUnresolvedBody is the EvaluationFailure of a call that
// starts a nested shell body the walk cannot resolve statically (a shell
// option word that may be -c, a dynamic -c body, trap handler or su
// command): what runs is not known; the gateway records it as an unread part
// (rel-1-0-10:GAP-0535).
const EvaluationFailureUnresolvedBody = "unresolved-body"

// EvaluationFailureUnknownStdinConsumer is the EvaluationFailure of a
// here-document with a body that may write DefenseClaw state, fed to a
// program whose use of its standard input is not known (newgrp, a shell
// behind an untrusted wrapper, a data program after its PATH changed;
// simpleTopLevelHereDocBodies): the gateway judges it as the unknown tier of
// the pack, alert by default and block in strict (rel-1-0-10:GAP-1183,
// GAP-1240).
const EvaluationFailureUnknownStdinConsumer = "unknown-stdin-consumer"

// EvaluationFailureUnknownStdinConsumerStrict is the EvaluationFailure of
// the same here-document fed to a program that is no shell and no newgrp,
// only after PATH changed (PATH=dir:$PATH cat <<E, export PATH=...; cat >
// script <<E): the program is most likely the data program it names, so the
// gateway judges it in the strict tiers only (the unknown tier there, a
// block) and allows it in the others, as release did (rel-1-0-10:GAP-1481).
const EvaluationFailureUnknownStdinConsumerStrict = "unknown-stdin-consumer-strict"

func isSyntaxTailUnread(simple SimpleCommand) bool {
	return simple.EvaluationFailure == EvaluationFailureSyntax
}

// syntaxTailCommands is the per-command reading of a text with a syntax
// error (tail): each readable statement, as a command of its own and with
// its own commands, in the directory the text starts in, then the
// EvaluationFailureSyntax marker for the part that was not read. A statement
// keeps the readings it has alone, a limit included. The runs of a quoted
// here-document body are statements only when its command runs its standard
// input as shell code; another command's body is its data and stays unread
// text, and a command that is not known is the unknown tier
// (EvaluationFailureUnresolvedBody, rel-1-0-10:GAP-0876). The consumer
// reading takes the readable statements for the bindings that may rename a
// data program (hereDocCallBindings, GAP-0902, GAP-0913).
func syntaxTailCommands(input Input, tail shellparse.SyntaxTail, depth int, interpreter string, inherited map[string]string, guess bool, operands *RelativeOperandMemo) []SimpleCommand {
	result := make([]SimpleCommand, 0, len(tail.Statements)+2)
	emitted := make(map[SimpleCommand]bool, len(tail.Statements))
	capped := tail.Truncated.Any()
	add := func(command SimpleCommand) bool {
		if len(result) >= maxSimpleEvaluations {
			capped = true
			return false
		}
		if !emitted[command] {
			emitted[command] = true
			result = append(result, command)
		}
		return true
	}
	read := func(statement string) bool {
		piece := input
		piece.Command, piece.Args, piece.Argv = statement, nil, nil
		// The statement as written is judged whatever its own reading
		// finds: its raw-text and whole-call readers run on it.
		if !add(SimpleCommand{Text: statement, CWD: input.CWD}) {
			return false
		}
		for _, command := range simpleCommands(piece, Analyze(piece), depth+1, interpreter, inherited, guess, nil, operands) {
			if command.EvaluationFailure == "limit" {
				// A statement whose own reading is past the statement
				// budget is a capped reading of the text, not a refusal of
				// the call: what was read is judged and the cap adds the
				// evaluation-limit finding (the bound rule,
				// rel-1-0-10:GAP-0744).
				capped = true
				continue
			}
			if !add(command) {
				return false
			}
		}
		return true
	}
	statements := slices.Clone(tail.Statements)
	unknownBody := false
	for _, doc := range tail.HereDocs {
		switch syntaxTailHereDocConsumerIn(doc, tail.Statements) {
		case hereDocRunsCode:
			statements = append(statements, doc.Statements...)
		case hereDocUnknown:
			unknownBody = true
		}
	}
	for _, statement := range statements {
		if !read(statement) {
			break
		}
	}
	if unknownBody {
		add(SimpleCommand{EvaluationFailure: EvaluationFailureUnresolvedBody})
	}
	result = append(result, SimpleCommand{EvaluationFailure: EvaluationFailureSyntax})
	if capped {
		// The reading stopped at a cap: the call is at least the unknown
		// tier of the pack, and the statements read before the cap are
		// still judged (the bound rule).
		result = append(result, SimpleCommand{EvaluationFailure: EvaluationFailureSyntaxCap})
	}
	return result
}

// EvaluationFailureSyntaxCap follows EvaluationFailureSyntax when the reading
// of a text with a syntax error stopped at a cap of shellparse.ReadSyntaxTail:
// the gateway adds the evaluation-limit finding (the unknown tier of the
// pack) and still judges every statement read before the cap. It is not the
// statement-budget refusal ("limit"), which judges none of them.
const EvaluationFailureSyntaxCap = "syntax-cap"

// EvaluationFailureInternal is the EvaluationFailure of a call whose
// per-command reading stopped on an internal reader error (a recovered
// panic): nothing of the call was read, so it is unknown, never ordinary
// (gas-ux-r2:GAP-0082).
const EvaluationFailureInternal = "internal"

// simpleCommandsFault is a test-only seam: when non-nil SimpleCommands calls
// it first, so a test can make the reader fail. Production never sets it.
var simpleCommandsFault func()

type simpleShellState struct {
	cwd        string
	cwdUnknown bool
	dirStack   []string
	vars       map[string]string
	// locals holds, innermost last, the caller value of each name a
	// function body made local; the body end restores it.
	locals []simpleLocal
	// forked holds the forked loop variables that hold the value of one list
	// word (simpleForkLoopBind) in this state, until their loop ends.
	forked []string
	// folderVars are the variables assigned from a current-folder head while
	// the folder was unknown (X=$PWD/f after cd "$D"): their value is the
	// relative spelling in that folder, which the next cd moves away from, so
	// the next cd forgets them (rel-1-0-10:GAP-1042).
	folderVars []string
	// homeUnproven means HOME holds a value the walk could not read
	// (HOME=$(pwd), HOME=$X, a declaration option that changes what the
	// value means). HOME is then the active home the action started in
	// (startHome), so a later ~ or $HOME write is still judged against a
	// home the call can reach (GAP-2476), and a reading through it is marked
	// UnprovenHome (rel-1-0-10:GAP-0996).
	homeUnproven bool
	// startHome is the active home of the action, the HOME the walk starts
	// with. An unreadable HOME value falls back to it, never only to a
	// literal home an earlier statement moved HOME to: after export
	// HOME=/tmp/x; export HOME=$(...) a later ~ write may reach the active
	// home, and the earlier literal alone judged it a clean allow
	// (rel-1-0-10:GAP-1087).
	startHome string
	// movedHome is that earlier literal home while the statement that made
	// HOME unreadable is read: the walk then reads the statements after it
	// in both homes (simpleHomeReadings), so a ~ write that blocks in
	// either still blocks.
	movedHome string
	// homeGuess is the folder the walk reads an unproven HOME as, when the
	// run-time value is one it can place (simpleRunTimeHomeGuess): HOME
	// stays unproven, and a reading through it of a file that this folder
	// makes an account's file is marked UnprovenHome (rel-1-0-10:GAP-1022).
	homeGuess string
}

// simpleLocal is the caller value of name saved by a local declaration in
// the function body of scope.
type simpleLocal struct {
	scope, name, value string
	known              bool
}

const (
	maxSimpleStates      = 32
	maxSimpleEvaluations = 512
	maxCompactionCases   = 8
	// maxSimpleWindowsOtherReadings bounds the readings of a PowerShell or
	// CMD call in other folders that name the folder: each is a policy
	// pass of its own, and a padded call past it took the native gateway
	// past its hook persistence deadline (rel-1-0-10:GAP-1228). It is the
	// statement budget, so such a call costs at most about three times a
	// call of the same statements on rel.
	maxSimpleWindowsOtherReadings = maxStatementsAlone
)

// CappedFolders are the folders a Windows statement after moves that may
// fail was not read in because the call reached
// maxSimpleWindowsOtherReadings (nil for every other reading). Only its
// UnresolvedFolder reading carries them (rel-1-0-10:GAP-1281).
func (s SimpleCommand) CappedFolders() []string {
	if s.cappedFolders == nil {
		return nil
	}
	return *s.cappedFolders
}

func (s simpleShellState) clone() simpleShellState {
	copy := simpleShellState{cwd: s.cwd, cwdUnknown: s.cwdUnknown,
		dirStack: slices.Clone(s.dirStack), vars: make(map[string]string, len(s.vars)),
		locals: slices.Clone(s.locals), forked: slices.Clone(s.forked), folderVars: slices.Clone(s.folderVars),
		homeUnproven: s.homeUnproven, startHome: s.startHome, movedHome: s.movedHome, homeGuess: s.homeGuess}
	for name, value := range s.vars {
		copy.vars[name] = value
	}
	return copy
}

// noteHome records what assignments did to HOME (updateSimpleVariables): a
// value the walk read proves the home, a value it could not read leaves the
// home unproven (unproveHome).
func (s *simpleShellState) noteHome(set, known bool) {
	switch {
	case set && !known:
		s.unproveHome()
	case set:
		s.homeUnproven, s.homeGuess = false, ""
	}
}

// noteHomeGuess records guess (simpleRunTimeHomeGuessOf) for a HOME that
// the assignments left unproven.
func (s *simpleShellState) noteHomeGuess(guess string, set bool) {
	if set && s.homeUnproven {
		s.homeGuess = guess
	}
}

// unproveHome records that HOME got a value the walk cannot read: HOME is
// the active home the action started in again; a literal home an earlier
// statement moved it to stays a second reading (movedHome,
// rel-1-0-10:GAP-1087). A guess of the earlier value is dropped
// (rel-1-0-10:GAP-1022).
func (s *simpleShellState) unproveHome() {
	s.homeUnproven, s.homeGuess = true, ""
	if home := s.vars["HOME"]; s.startHome != "" && home != s.startHome {
		if s.movedHome == "" {
			s.movedHome = home
		}
		s.vars["HOME"] = s.startHome
	}
}

// simpleHomeReadings is the state after a statement: one state, or, when the
// statement made HOME unreadable after HOME had been moved to another
// literal home (unproveHome), the state in the active home and the state in
// that literal home, since either may be the home the shell has
// (rel-1-0-10:GAP-1087).
func simpleHomeReadings(state simpleShellState) []simpleShellState {
	if state.movedHome == "" {
		return []simpleShellState{state}
	}
	moved := state.clone()
	moved.vars["HOME"], moved.movedHome, state.movedHome = state.movedHome, "", ""
	return []simpleShellState{state, moved}
}

// simpleReadsThroughUnprovenHome reports whether the reading text of a
// statement spelled with ~ or HOME (source) reads, under the home of state
// while that home is unproven (SimpleCommand.UnprovenHome), a path that
// another home makes an account's file: one that climbs out of the home
// (~/../f) or one of the credentials-file table (~/.git-credentials).
// A test script that sets HOME to its own folder and reads its own files
// there (export HOME=$T; tail "$HOME/init.log") reads no such path.
func simpleReadsThroughUnprovenHome(input Input, state simpleShellState, source, text string, resolved bool) bool {
	home := state.vars["HOME"]
	if !state.homeUnproven || !resolved || home == "" ||
		!strings.Contains(source, "~") && !strings.Contains(source, "HOME") {
		return false
	}
	reading := input
	reading.Command, reading.Args, reading.Argv, reading.CWD = text, nil, nil, state.cwd
	prefix := strings.TrimSuffix(home, "/") + "/"
	for _, fact := range Analyze(reading).Paths {
		if fact.Access != PathAccessRead || !strings.HasPrefix(fact.Value, prefix) {
			continue
		}
		relative := strings.TrimPrefix(fact.Value, prefix)
		if slices.Contains(strings.Split(relative, "/"), "..") {
			return true
		}
		if _, credential := MatchCredentialFileShape(relative); credential {
			return true
		}
		// HOME=$(cd ~/.aws; pwd); cp ~/credentials reads ~/.aws/credentials
		// (rel-1-0-10:GAP-1022).
		if state.homeGuess != "" {
			if guessed := simplePathClean(state.homeGuess + "/" + relative); strings.HasPrefix(guessed, prefix) {
				if _, credential := MatchCredentialFileShape(strings.TrimPrefix(guessed, prefix)); credential {
					return true
				}
			}
		}
	}
	return false
}

// simpleRunTimeHomeGuessOf is simpleRunTimeHomeGuess of the last HOME of
// assigns, read in state before they run; set reports a HOME among them.
func simpleRunTimeHomeGuessOf(assigns []*syntax.Assign, state simpleShellState) (guess string, set bool) {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil || assign.Name.Value != "HOME" || assign.Index != nil || assign.Array != nil {
			continue
		}
		guess, set = simpleRunTimeHomeGuess(assign.Value, state), true
	}
	return guess, set
}

// simpleRunTimeHomeGuess is the folder a run-time HOME value names when the
// walk can place it: $(pwd) is the working folder, $(cd D; pwd) and
// $(cd D && pwd) are D, $(echo W) is W, and a static tail after one of them
// ($(pwd)/../D) is joined to it. It is "" for any other value, an unknown
// working folder, or a place that is not absolute. The guess only widens
// which readings through the unproven home read an account's file
// (simpleReadsThroughUnprovenHome); HOME itself stays unproven, so a
// scratch HOME the shell may give another value is never made definite
// (rel-1-0-10:GAP-1022).
func simpleRunTimeHomeGuess(word *syntax.Word, state simpleShellState) string {
	if word == nil || len(word.Parts) == 0 || state.cwdUnknown || !simplePOSIXAbs(state.cwd) {
		return ""
	}
	var subst *syntax.CmdSubst
	switch first := word.Parts[0].(type) {
	case *syntax.CmdSubst:
		subst = first
	case *syntax.DblQuoted:
		if !first.Dollar && len(first.Parts) == 1 {
			subst, _ = first.Parts[0].(*syntax.CmdSubst)
		}
	}
	if subst == nil || subst.TempFile || subst.ReplyVar {
		return ""
	}
	folder, ok := simpleSubstitutionFolder(subst, state)
	if !ok {
		return ""
	}
	if len(word.Parts) > 1 {
		tail, static := simpleStaticWord(&syntax.Word{Parts: word.Parts[1:]}, state.vars)
		if !static || !strings.HasPrefix(tail, "/") {
			return ""
		}
		folder += tail
	}
	return simplePathClean(folder)
}

// simpleSubstitutionFolder is the folder a substitution of
// simpleRunTimeHomeGuess prints, read in state.
func simpleSubstitutionFolder(subst *syntax.CmdSubst, state simpleShellState) (string, bool) {
	words := func(stmt *syntax.Stmt) ([]string, bool) {
		if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown || len(stmt.Redirs) != 0 {
			return nil, false
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
			return nil, false
		}
		values := make([]string, 0, len(call.Args))
		for _, arg := range call.Args {
			value, static := simpleStaticWord(arg, state.vars)
			if !static {
				return nil, false
			}
			values = append(values, value)
		}
		return values, true
	}
	place := func(folder string) (string, bool) {
		switch {
		case folder == "":
			return "", false
		case simplePOSIXAbs(folder):
			return folder, true
		default:
			return state.cwd + "/" + folder, true
		}
	}
	cdThenPwd := func(cd, pwd *syntax.Stmt) (string, bool) {
		cdWords, ok := words(cd)
		if !ok || cdWords[0] != "cd" || len(cdWords) > 2 {
			return "", false
		}
		if pwdWords, ok := words(pwd); !ok || len(pwdWords) != 1 || pwdWords[0] != "pwd" {
			return "", false
		}
		if len(cdWords) == 1 {
			return place(state.vars["HOME"])
		}
		return place(cdWords[1])
	}
	switch len(subst.Stmts) {
	case 1:
		stmt := subst.Stmts[0]
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && binary.Op == syntax.AndStmt &&
			!stmt.Negated && !stmt.Background && len(stmt.Redirs) == 0 {
			return cdThenPwd(binary.X, binary.Y)
		}
		values, ok := words(stmt)
		if !ok {
			return "", false
		}
		switch {
		case len(values) == 1 && values[0] == "pwd":
			return state.cwd, true
		case len(values) == 2 && values[0] == "echo" && !strings.HasPrefix(values[1], "-"):
			return place(values[1])
		}
	case 2:
		return cdThenPwd(subst.Stmts[0], subst.Stmts[1])
	}
	return "", false
}

// simpleHomeChanged reports whether state holds another HOME than prior.
func simpleHomeChanged(prior, state simpleShellState) bool {
	return prior.vars["HOME"] != state.vars["HOME"] || prior.homeUnproven != state.homeUnproven ||
		prior.homeGuess != state.homeGuess
}

// simplePieces holds the commands a walk reads from the text of the call as it
// is written: no variable of them resolved, no word of them changed. A nil
// pointer records nothing.
type simplePieces []SimpleCommand

func (pieces *simplePieces) add(command SimpleCommand) {
	if pieces != nil {
		*pieces = append(*pieces, command)
	}
}

// has reports a command that is one of the pieces. A reading marked
// LoginGuess or LastStageOrBackground is judged as the piece it repeats.
func (pieces *simplePieces) has(command SimpleCommand) bool {
	command.LoginGuess, command.LastStageOrBackground = false, false
	return slices.ContainsFunc(*pieces, func(piece SimpleCommand) bool {
		piece.LoginGuess, piece.LastStageOrBackground = false, false
		return piece == command
	})
}

// SimpleCommands flattens an action with the full parser used by the hook
// command class rule. Every returned command is judged on its own, in
// addition to the original action. A plain single command needs no second
// pass. Ordinary assignments and known home or local variable expansions
// are resolved; a subshell or pipeline stage has its own shell state.
func SimpleCommands(input Input, facts Facts) []SimpleCommand {
	return SimpleCommandsWith(input, facts, nil)
}

// SimpleCommandsWith is SimpleCommands with the relative-operand answers of
// relative (nil: none kept), for callers that split several readings of one
// call (GAP-0923).
func SimpleCommandsWith(input Input, facts Facts, operands *RelativeOperandMemo) (commands []SimpleCommand) {
	defer func() {
		if recover() != nil {
			commands = []SimpleCommand{{EvaluationFailure: EvaluationFailureInternal}}
		}
	}()
	if simpleCommandsFault != nil {
		simpleCommandsFault()
	}
	argsOnly := input.Command == "" && facts.Parse.Status == StatusInvalid && containsIssue(facts.Parse.Issues, IssueInvalidSyntax)
	var pieces *simplePieces
	if argsOnly && argsExecutionTool(input.Tool) {
		pieces = new(simplePieces)
	}
	result := simpleCommandsOfCall(input, facts, pieces, operands)
	if facts.Parse.Dialect == DialectPOSIX && facts.Parse.Status != StatusInvalid {
		source := input.Command
		if source == "" && (bytes.Contains(input.Args, []byte("<<")) || facts.Parse.Status == StatusPartial) {
			_, capture := analyzeWithRedirectTargets(input, "")
			source = capture.source
		}
		if strings.Contains(source, "<<") && len(source) <= maxCommandBytes {
			result = append(result, simpleTopLevelHereDocBodies(source, input)...)
		}
		if facts.Parse.Status == StatusPartial && len(source) <= maxCommandBytes {
			if reading, _, ok := simpleNeutralWrapperFreeReading(input, source); ok &&
				!slices.ContainsFunc(result, func(simple SimpleCommand) bool { return simple.Text == reading.Text }) {
				result = append(result, reading)
			}
		}
	}
	if argsOnly && slices.ContainsFunc(result, isSyntaxTailUnread) {
		// A text with a syntax error (syntaxTailCommands): its readings are
		// all of the call that was read, a cap they stopped at included.
		return result
	}
	if argsOnly {
		// The POSIX reader rejected the call (a construct only Bash has) and
		// the shell parse reads it only to add readings (simpleCommands): a
		// call it cannot read in full keeps the judgment it had without them.
		if slices.ContainsFunc(result, func(simple SimpleCommand) bool { return simple.EvaluationFailure != "" }) {
			return nil
		}
		// A command that is a piece of the call as written adds nothing: the
		// call is judged as written, with the rules and the enforcement it had
		// before this reading. Only a reading with a variable resolved is new.
		// The walk records the pieces as it reads them, so a text that merely
		// occurs elsewhere in the call (a comment, a quoted word) is no piece.
		if pieces != nil {
			result = slices.DeleteFunc(result, pieces.has)
		}
	}
	return result
}

// simpleTopLevelHereDocBodies gives a parsed here-document to the same
// consumer reader used after a syntax error, for the openers whose stdin no
// other reader judges (rel-1-0-10:GAP-1183): a shell outside the ordinary
// shell set (yash), a shell behind a launcher the stdin-code reader does not
// unwrap, and the launchers of unknown stdin semantics with a possible state
// write (topLevelHereDocUnknownStateConsumer). Each statement of the text is
// read, also one in a group, a subshell or a control body, and so is every
// call in it that owns a document, wherever it sits in a list or a pipeline,
// behind a static prefix wrapper, or after a statement that rebinds PATH
// (rel-1-0-10:GAP-1240). An opener the ordinary readers already judge
// (topLevelHereDocReadElsewhere) adds nothing, so their reading stays the
// only one: the cap-floor here-document reader (GAP-0691: bash script.sh
// <<X is data for the script), the stdin-code reader of privilege wrappers
// and schedulers (sudo sh <<X, crontab - <<X) and the shell twin of a piped
// document with its unquoted body (heredocScriptText, rel-1-0-10:GAP-1137,
// GAP-1193).
func simpleTopLevelHereDocBodies(source string, input Input) []SimpleCommand {
	file, ok := shellparse.Parse(source)
	if !ok || file == nil {
		return nil
	}
	var result []SimpleCommand
	syntax.Walk(file, func(node syntax.Node) bool {
		if len(result) >= maxSimpleEvaluations {
			return false
		}
		// A function declaration does not run its body in this call.
		if _, definition := node.(*syntax.FuncDecl); definition {
			return false
		}
		stmt, isStmt := node.(*syntax.Stmt)
		if !isStmt {
			return true
		}
		switch stmt.Cmd.(type) {
		case *syntax.CallExpr, *syntax.BinaryCmd:
		default:
			// A definition or control construct is not itself a consumer:
			// the statements of its body are read on their own.
			return true
		}
		result = append(result, hereDocStatementBodies(file, stmt, input)...)
		return false
	})
	if len(result) >= maxSimpleEvaluations {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	return result
}

// hereDocStatementBodies is the reading of the documents of one statement
// (a call or a list or pipeline of calls) for simpleTopLevelHereDocBodies.
func hereDocStatementBodies(file *syntax.File, stmt *syntax.Stmt, input Input) []SimpleCommand {
	reading := hereDocData
	var consumer strings.Builder
	if syntax.NewPrinter().Print(&consumer, stmt.Cmd) == nil {
		reading = syntaxTailHereDocConsumer(consumer.String())
	}
	runsCode := reading == hereDocRunsCode && !topLevelHereDocReadElsewhere(stmt.Cmd)
	var result []SimpleCommand
	syntax.Walk(stmt, func(node syntax.Node) bool {
		if len(result) >= maxSimpleEvaluations {
			return false
		}
		if _, definition := node.(*syntax.FuncDecl); definition {
			return false
		}
		owner, isStmt := node.(*syntax.Stmt)
		if !isStmt || len(owner.Redirs) == 0 {
			return true
		}
		for _, redirection := range owner.Redirs {
			if redirection.Op != syntax.Hdoc && redirection.Op != syntax.DashHdoc {
				continue
			}
			if redirection.Hdoc == nil {
				// An empty here-document: the consumer gets no input.
				continue
			}
			// The body as the shell that runs it reads it: the literal body,
			// or an unquoted body that expands only parameters, as written
			// (heredocScriptText, the reading of the shell twin). A body the
			// twin cannot read (a command substitution) shows no state write
			// here.
			body, known := heredocScriptText(redirection)
			if tier := hereDocOwnerUnknownStateConsumer(file, owner); tier != hereDocConsumerKnown && hereDocBodyMayWriteState(body, input) {
				// A valid here-document fed to an ordinary program is data
				// even when the closed syntax-tail reader cannot prove the
				// stdin semantics of that program. Only the GAP-1183 launcher
				// forms with a possible state write are the unknown tier; a
				// data program after a PATH change is the strict tiers only
				// (GAP-1481).
				failure := EvaluationFailureUnknownStdinConsumer
				if tier == hereDocConsumerStrictOnly {
					failure = EvaluationFailureUnknownStdinConsumerStrict
				}
				result = append(result, SimpleCommand{EvaluationFailure: failure})
			}
			if !runsCode {
				continue
			}
			if !known || len(body) > maxScalarBytes || strings.ContainsRune(body, 0) {
				result = append(result, SimpleCommand{EvaluationFailure: EvaluationFailureUnresolvedBody})
				continue
			}
			result = append(result, SimpleCommand{Text: body, CWD: input.CWD})
		}
		return true
	})
	return result
}

// hereDocOwnerUnknownStateConsumer reports a call that owns a document and
// whose program, as the statements before it may bind it, has unknown stdin
// semantics and is one of the GAP-1183 opener forms
// (topLevelHereDocUnknownStateConsumer).
func hereDocOwnerUnknownStateConsumer(file *syntax.File, owner *syntax.Stmt) hereDocConsumerTier {
	call, isCall := owner.Cmd.(*syntax.CallExpr)
	if !isCall {
		return hereDocConsumerKnown
	}
	var consumer strings.Builder
	if syntax.NewPrinter().Print(&consumer, call) != nil {
		return hereDocConsumerKnown
	}
	bindings := hereDocBindingsBefore(file, owner)
	if hereDocTextConsumer(consumer.String(), bindings, 0) != hereDocUnknown {
		return hereDocConsumerKnown
	}
	return topLevelHereDocUnknownStateConsumer(call, bindings)
}

// topLevelHereDocReadElsewhere reports an opener whose every command that
// runs its standard input as code (hereDocArgvConsumer) is one the
// stdin-code reader names on its own: static words, a command word that is
// a trusted program, no assignment that changes which program runs, and
// posixStdinCodeTarget (a POSIX shell without -c, also behind env or
// command, a privilege wrapper or a scheduler). The ordinary readers judge
// that body already, and a second reading here differs from theirs only
// where it is wrong: posixStdinCodeTarget names bash script.sh, whose
// script file gets the document as data (GAP-0691), crontab - installs a
// table, not a script, and an unquoted body they read became an unread one
// (the FU9 reds of TestCapFloorHeredocConsumer, TestStdinCodeWrapper* and
// TestHeredocPipedToAShellIsJudgedAsTheScriptItCarries).
func topLevelHereDocReadElsewhere(cmd syntax.Command) bool {
	elsewhere := true
	syntax.Walk(cmd, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !elsewhere || !isCall || len(call.Args) == 0 {
			return elsewhere
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for index, arg := range call.Args {
			words[index], static[index] = simpleStaticWord(arg, nil)
		}
		if hereDocArgvConsumer(words, static, nil, 0) != hereDocRunsCode {
			return true
		}
		elsewhere = allStatic(static) && commandProgram(words[0]) != "" && posixStdinCodeTarget(words)
		for _, assign := range call.Assigns {
			if assign.Name != nil && resolutionVariable(assign.Name.Value) {
				elsewhere = false
			}
		}
		return elsewhere
	})
	return elsewhere
}

// hereDocBindingsBefore uses the syntax-tail binding reader on statements
// that can run before owner. A later PATH assignment cannot rename an
// earlier data consumer.
func hereDocBindingsBefore(file *syntax.File, owner *syntax.Stmt) *hereDocBindings {
	bindings := &hereDocBindings{names: map[string]bool{}}
	start := owner.Pos().Offset()
	var walk func(node syntax.Node) bool
	walk = func(node syntax.Node) bool {
		if fn, definition := node.(*syntax.FuncDecl); definition {
			if fn.End().Offset() <= start && fn.Name != nil {
				bindings.names[fn.Name.Value] = true
			}
			return false
		}
		stmt, isStmt := node.(*syntax.Stmt)
		if !isStmt || stmt.End().Offset() > start {
			return true
		}
		if fn, definition := stmt.Cmd.(*syntax.FuncDecl); definition {
			if fn.Name != nil {
				bindings.names[fn.Name.Value] = true
			}
			return false
		}
		if clause, isIf := stmt.Cmd.(*syntax.IfClause); isIf && hereDocDeadThen(stmt, clause, bindings) {
			// if false; then ...; fi: the then branch never runs, so only an
			// else or elif branch can bind.
			if clause.Else != nil {
				syntax.Walk(clause.Else, walk)
			}
			return false
		}
		bindings.read(stmt, 0)
		return false
	}
	syntax.Walk(file, walk)
	return bindings
}

// hereDocDeadThen reports an if statement whose condition is the plain
// builtin false, which bindings do not rename: its then branch never runs.
func hereDocDeadThen(stmt *syntax.Stmt, clause *syntax.IfClause, bindings *hereDocBindings) bool {
	if stmt.Negated || stmt.Background || stmt.Coprocess || len(stmt.Redirs) != 0 || len(clause.Cond) != 1 {
		return false
	}
	cond := clause.Cond[0]
	call, isCall := cond.Cmd.(*syntax.CallExpr)
	if !isCall || cond.Negated || cond.Background || cond.Coprocess || len(cond.Redirs) != 0 ||
		len(call.Assigns) != 0 || len(call.Args) != 1 {
		return false
	}
	word, static := simpleStaticWord(call.Args[0], nil)
	return static && word == "false" && !bindings.renames(word)
}

// hereDocConsumerTier is how the gateway judges a here-document that may
// write DefenseClaw state, by the program it is fed to
// (topLevelHereDocUnknownStateConsumer).
type hereDocConsumerTier uint8

const (
	// hereDocConsumerKnown: the document is data, or the ordinary readers
	// judge it.
	hereDocConsumerKnown hereDocConsumerTier = iota
	// hereDocConsumerUnknown: newgrp, or a shell behind a wrapper the
	// reading does not know: the unknown tier of every pack.
	hereDocConsumerUnknown
	// hereDocConsumerStrictOnly: a program that is no shell and no newgrp,
	// after a PATH change before it or on it: the strict tiers only
	// (rel-1-0-10:GAP-1481).
	hereDocConsumerStrictOnly
)

// topLevelHereDocUnknownStateConsumer is the small set of valid opener
// shapes in GAP-1183. Other unknown stdin consumers retain their release
// behavior; the syntax-error tail has its separate conservative contract.
// newgrp and a shell behind a wrapper are the unknown tier; a changed PATH
// alone, before a program that names no shell (export PATH=~/bin:$PATH;
// cat > script <<E), is the strict tiers only: the PATH most often adds a
// tool folder and the program stays the data program it names
// (rel-1-0-10:GAP-1481).
func topLevelHereDocUnknownStateConsumer(call *syntax.CallExpr, bindings *hereDocBindings) hereDocConsumerTier {
	if len(call.Args) == 0 {
		return hereDocConsumerKnown
	}
	pathChanged := bindings != nil && bindings.resolution
	for _, assign := range call.Assigns {
		if assign.Name != nil && assign.Name.Value == "PATH" {
			pathChanged = true
		}
	}
	changed := hereDocConsumerKnown
	if pathChanged {
		changed = hereDocConsumerStrictOnly
	}
	words := make([]string, len(call.Args))
	static := make([]bool, len(words))
	for i, arg := range call.Args {
		words[i], static[i] = simpleStaticWord(arg, nil)
	}
	if run, ok := StaticPrefixWrapperChild(words, static); ok {
		if run.ChangesResolution {
			changed = hereDocConsumerStrictOnly
		}
		words, static = words[run.Index:], static[run.Index:]
	}
	if len(words) == 0 || !static[0] {
		return changed
	}
	program := commandProgram(words[0])
	if program == "newgrp" {
		return hereDocConsumerUnknown
	}
	if changed != hereDocConsumerKnown && (posixShellProgram(program) || hereDocExtraShells[program]) {
		// A shell the changed PATH may rename: what runs the text is not
		// known.
		return hereDocConsumerUnknown
	}
	if program != "" || len(words) < 2 {
		return changed
	}
	for i, word := range words[1:] {
		if static[i+1] && (posixShellProgram(commandProgram(word)) || hereDocExtraShells[commandProgram(word)]) {
			return hereDocConsumerUnknown
		}
	}
	return changed
}

func hereDocBodyMayWriteState(body string, input Input) bool {
	lower := strings.ToLower(strings.NewReplacer("'", "", "\"", "", "\\", "", "`", "").Replace(body))
	if !strings.Contains(lower, "defense") && !strings.Contains(lower, "claw") {
		return false
	}
	piece := input
	piece.Command, piece.Args, piece.Argv = body, nil, nil
	for _, target := range Analyze(piece).Paths {
		if target.Access != PathAccessWrite && target.Access != PathAccessAppend && target.Access != PathAccessDelete {
			continue
		}
		name := strings.ToLower(target.Value)
		if strings.Contains(name, "defense") || strings.Contains(name, "claw") {
			return true
		}
	}
	return false
}

func simpleCommandsOfCall(input Input, facts Facts, pieces *simplePieces, operands *RelativeOperandMemo) []SimpleCommand {
	result := simpleCommands(input, facts, 0, "", nil, false, pieces, operands)
	// USER and LOGNAME carry a value from the home only as the guess that the
	// login is the home's last element, and the shell may hold another. A
	// second walk reads the action with that guess, to prove a write to state
	// spelled through the names. Only a reading the first walk did not make is
	// added, marked LoginGuess: a rule over the words of the command reads the
	// first walk (an unproven $USER is a runtime-expanded word), and the
	// guess reading only proves a protected write (rel-1-0-6:GAP-0630
	// integration: a word expanded at run time keeps its detection-only
	// outcome). An action that names neither has no second reading.
	if input.Command != "" && !strings.Contains(input.Command, "USER") && !strings.Contains(input.Command, "LOGNAME") {
		return result
	}
	for _, guessed := range simpleCommands(input, facts, 0, "", nil, true, pieces, operands) {
		if !slices.Contains(result, guessed) {
			guessed.LoginGuess = true
			result = append(result, guessed)
		}
	}
	return result
}

// simpleCommands reads the commands of input. guess gives USER and LOGNAME
// the value the home spells where the action has not assigned one; without
// it a name has a value only where the action assigns one, or a caller
// hands one to a shell body. inherited holds the values USER and LOGNAME
// have where a shell body starts (simpleChildUserVars); nil is the start of
// the action, where guess gives both the home base name.
func simpleCommands(input Input, facts Facts, depth int, interpreter string, inherited map[string]string, guess bool, pieces *simplePieces, operands *RelativeOperandMemo) []SimpleCommand {
	if facts.Parse.Dialect == DialectPowerShell || facts.Parse.Dialect == DialectCMD {
		return windowsSimpleCommands(input, facts)
	}
	if facts.Parse.Dialect != DialectPOSIX {
		return nil
	}
	if depth >= 8 {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	source := input.Command
	if source == "" {
		_, capture := analyzeWithRedirectTargets(input, "")
		source = capture.source
		if source == "" && facts.Parse.Status == StatusInvalid && containsIssue(facts.Parse.Issues, IssueInvalidSyntax) &&
			argsExecutionTool(input.Tool) {
			// The POSIX reader rejects a construct only Bash has (select, a
			// here-string), so it kept no source; the shell parse below reads
			// it, and each command of it is judged as any other is.
			if command := extractArgsForTool(input.Args, input.Tool).command; utf8.ValidString(command) && !strings.ContainsRune(command, 0) {
				source = command
			}
		}
	}
	if len(source) > maxCommandBytes {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	if source == "" {
		return nil
	}
	// Only a text the analysis already rejected with a syntax error is read
	// for its tail, so a call that parses pays no second parse.
	if facts.Parse.Status == StatusInvalid && containsIssue(facts.Parse.Issues, IssueInvalidSyntax) {
		if tail, ok := shellparse.ReadSyntaxTail(source); ok {
			return syntaxTailCommands(input, tail, depth, interpreter, inherited, guess, operands)
		}
	}
	// A ~+ head is the working folder, which only the walk writes
	// (rel-1-0-10:GAP-1204).
	if !input.folderUnknown && !strings.ContainsAny(source, ";&|(){}<>\n`$=!") &&
		!strings.Contains(source, "eval") && !strings.Contains(source, "trap") &&
		!strings.Contains(source, " -") && !strings.Contains(source, "~+") {
		return nil
	}
	parts, reduced, ok := sequenceStatementDetails(source, true, true, input.LoopBindsStraightLine, !input.StraightLineFunctions)
	if !ok {
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	var bound map[string]bool
	if strings.ContainsRune(source, '$') {
		file, _ := shellparse.Parse(source)
		bound = simpleBoundVariables(file)
	}
	if len(parts) == 0 {
		return nil
	}
	if len(parts) > maxStatementsAlone {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	// The folders each statement may run in, by the working-folder tracking
	// of the analysis (working_folder.go): the walk below moves its folder
	// at every cd as if the cd ran and worked, so a statement after a cd that
	// may fail or not run is also read where the shell was before it
	// (rel-1-0-10:GAP-0869).
	mayRunIn := simplePartWorkFolders(source, parts, input.CWD, input.ActiveHome)
	var futureSafe []bool
	var checkedCases, tooManyCases bool
	compact := func(states []simpleShellState, index int) []simpleShellState {
		if !simpleOverStateBound(states) {
			return states
		}
		if !checkedCases {
			checkedCases = true
			tooManyCases = simpleTooManyCompactionCases(source)
		}
		if tooManyCases {
			return states
		}
		if futureSafe == nil {
			futureSafe = make([]bool, len(parts)+1)
			futureSafe[len(parts)] = true
			for at := len(parts) - 1; at >= 0; at-- {
				futureSafe[at] = simplePartCompactionSafe(parts[at]) && futureSafe[at+1]
			}
		}
		return compactSimpleStatesForFuture(states, parts[index:], futureSafe[index])
	}
	// A body that starts in an unknown folder (Input.folderUnknown) is read
	// whole: a single statement of it is a reading in that folder.
	if !reduced && len(parts) == 1 && !input.folderUnknown {
		file, parsed := shellparse.Parse(parts[0].text)
		if !parsed || len(file.Stmts) != 1 {
			return nil
		}
		stmt := file.Stmts[0]
		call, _ := stmt.Cmd.(*syntax.CallExpr)
		prefix := call != nil && len(call.Assigns) != 0 && len(call.Args) != 0
		duplication := slices.ContainsFunc(stmt.Redirs, func(redirect *syntax.Redirect) bool {
			return redirect.Op == syntax.DplIn || redirect.Op == syntax.DplOut
		})
		_, _, nested, _ := simpleNestedScript(call, nil, nil, nil)
		// A body that names USER or LOGNAME is read with the values its
		// caller hands over (inherited).
		inheritsUser := inherited != nil && (strings.Contains(parts[0].text, "USER") || strings.Contains(parts[0].text, "LOGNAME"))
		// A current-folder head ($PWD/, ${PWD}/, "$PWD"/, "$PWD/...", ~+/) is
		// the folder the call runs in: the walk writes it as that folder, as
		// it does for $(pwd)/ (a statement of its own there), so cat "$PWD"/.env
		// and cat ~+/.env in a known folder read the file cat .env reads
		// (rel-1-0-10:GAP-0878, rel-1-0-10:GAP-1204).
		folderHead := input.CWD != "" && (strings.Contains(parts[0].text, "PWD") || strings.Contains(parts[0].text, "~+"))
		if !prefix && !duplication && !nested && !inheritsUser && !folderHead && !simpleRedirectDefaultExpansion(stmt) {
			return nil
		}
	}
	home, _ := normalizeActiveHome(input.ActiveHome)
	initialVars := map[string]string{"HOME": home}
	// USER and LOGNAME are two names, each with the value it has where the
	// shell is: the last element of a POSIX home at the start of the action
	// (the trusted home rewrite reads <parent>/$USER, userHomeRewriteWord,
	// and the hook target scans read both names), changed in order by the
	// assignments below and handed to a shell body by the call that starts
	// it. A child command spelled with them is judged as its literal
	// spelling (rel-1-0-6:GAP-0601, GAP-0681, GAP-0630 review 3). A loop,
	// read or eval that binds a name takes its value away from the point
	// where it runs (the statements before it still read the value the
	// name has there, review 4).
	login := map[string]string{}
	if guess {
		login = simpleInitialUserVars(home, nil)
	}
	if guess || inherited != nil {
		for name, value := range simpleInitialUserVars(home, inherited) {
			initialVars[name] = value
		}
	}
	if simplePathAbs(input.CWD) {
		initialVars["PWD"] = simplePathClean(input.CWD)
	}
	states := map[string][]simpleShellState{
		"0": {{cwd: input.CWD, cwdUnknown: input.folderUnknown && input.CWD == "", vars: initialVars, startHome: home}},
	}
	result := make([]SimpleCommand, 0, len(parts))
	// extra counts the readings of result that are body readings in another
	// folder (bodyReading): the budget of the statements of the call is
	// len(result)-extra, as on rel, where those readings did not exist.
	extra := 0
	changed := reduced || len(parts) != 1 || input.folderUnknown
	unproven := false
	// syntaxUnread: a nested body with a syntax error was read only in part
	// (syntaxTailCommands).
	syntaxUnread := false
	// unknownFolderBody: a body the caller expands in an unknown folder was
	// read with that folder as its head (simpleUnknownFolderNestedCall); the
	// reading of the body as unread stays too.
	unknownFolderBody := ""
	// unresolvedBody: a nested shell body made at run time was not read
	// (EvaluationFailureUnresolvedBody); the rest of the call was.
	unresolvedBody := false
	// parseGap is the reading of a call the walk gives up on (a parse gap,
	// judged as the whole action): the call is not split, but a nested shell
	// body made at run time that an earlier statement already left unread
	// stays recorded, as the walk gave it up at that statement on rel
	// (rel-1-0-10:GAP-0535, GAP-1083: a later parse gap must not turn the
	// unknown body into an allow).
	parseGap := func() []SimpleCommand {
		if unresolvedBody || unknownFolderBody == EvaluationFailureUnresolvedBody {
			return []SimpleCommand{{EvaluationFailure: "parse"}, {EvaluationFailure: EvaluationFailureUnresolvedBody}}
		}
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	previousScope := "0"
	unreadLoops := make(map[string]bool)
	var plainWords simplePlainWords
	for partIndex, part := range parts {
		// A conditional or loop body runs in its parent's shell when selected.
		// Keep both its resulting state and the path that skipped the body.
		for previousScope != part.scope && !strings.HasPrefix(part.scope, previousScope+"/") {
			index := strings.LastIndexByte(previousScope, '/')
			if index < 0 {
				return parseGap()
			}
			parent := previousScope[:index]
			body, ran := states[previousScope]
			switch previousScope[index+1] {
			case 'c', 'u', 'o', forkedLoopScopeKind:
				if ran {
					merged := append(simpleScopeStates(states, parent), body...)
					merged = simpleJoinForgottenUserVars(merged, body)
					if previousScope[index+1] == forkedLoopScopeKind {
						// Like USER and LOGNAME, the name of such a loop has the
						// value of its last iteration, which the walk does not
						// read. Only this loop's name goes: any other variable,
						// also one that a later loop binds, keeps its value here.
						name := simpleForkedScopeName(previousScope)
						reading := func(state simpleShellState) bool { return slices.Contains(state.forked, name) }
						unread := slices.DeleteFunc(slices.Clone(merged), reading)
						for i := range merged {
							merged[i] = merged[i].clone()
							merged[i].forked = slices.DeleteFunc(merged[i].forked, func(forked string) bool { return forked == name })
							simpleForgetUserVars(merged[i].vars, []string{name})
						}
						if simpleOverStateBound(uniqueSimpleStates(merged)) {
							// Values the readings gave other variables of the
							// body would not fit: keep the states of the walk
							// that left the name unread.
							merged = unread
						}
					}
					for name, kind := range loopScopeKinds {
						if previousScope[index+1] == kind {
							// A loop leaves its name the value of its last
							// iteration, which the walk does not follow.
							for i := range merged {
								merged[i] = merged[i].clone()
								simpleForgetUserVars(merged[i].vars, []string{name})
							}
						}
					}
					states[parent] = uniqueSimpleStates(merged)
				}
			case 'f':
				// A called function body always runs; its local HOME ends
				// with it (GAP-2476, RV-pod2-2).
				if ran {
					states[parent] = uniqueSimpleStates(simpleEndFunctionBody(body, previousScope))
				}
			}
			// A pipeline sibling may inherit from an ancestor when this
			// scope has no state of its own. Do not install an empty entry:
			// it would hide that inherited state from the next child.
			if parentStates, present := states[parent]; present {
				states[parent] = compact(parentStates, partIndex)
			}
			if simpleOverStateBound(states[parent]) {
				return []SimpleCommand{{EvaluationFailure: "limit"}}
			}
			previousScope = parent
		}
		previousScope = part.scope
		var reads []string
		if slices.ContainsFunc(part.binds, func(bind simpleLoopBind) bool { return bind.fork }) {
			reads = simpleParamNames(part.text)
		}
		if !simpleEnterForkedLoops(states, part, unreadLoops, &plainWords) {
			return parseGap()
		}
		variants := simpleScopeStates(states, part.scope)
		if variants == nil {
			return parseGap()
		}
		file, parsed := shellparse.Parse(part.text)
		if !parsed || len(file.Stmts) != 1 {
			return parseGap()
		}
		stmt := file.Stmts[0]
		nextVariants := make([]simpleShellState, 0, len(variants))
		emitted := make(map[SimpleCommand]bool)
		var own []SimpleCommand
		for _, prior := range variants {
			if simpleReboundReading(prior, part) {
				continue
			}
			state := prior.clone()
			simpleApplyLoopBinds(state.vars, part.binds, login)
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) == 0 && len(call.Assigns) != 0 && len(stmt.Redirs) == 0 {
				assigns, folderNames := call.Assigns, []string(nil)
				if folder, names, ok := simpleUnknownFolderAssignment(part.text, &state); ok {
					if folderCall, ok := folder.Cmd.(*syntax.CallExpr); ok && len(folderCall.Args) == 0 &&
						len(folderCall.Assigns) == len(assigns) {
						assigns, folderNames = folderCall.Assigns, names
					}
				}
				guess, guessed := simpleRunTimeHomeGuessOf(assigns, state)
				state.noteHome(updateSimpleVariables(state.vars, assigns))
				state.noteHomeGuess(guess, guessed)
				state.setFolderVars(simpleAssignNames(assigns), folderNames)
				changed = true
				nextVariants = append(nextVariants, simpleHomeReadings(state)...)
				if part.maySkip && (len(prior.forked) != 0 || simpleHomeChanged(prior, state)) {
					// The assignment may not run: the word of the loop, and the
					// HOME it would change (false && HOME=/x, true || HOME=/x),
					// stay as they were (rel-1-0-10:GAP-0996).
					nextVariants = append(nextVariants, prior)
				}
				continue
			}
			text := part.text
			effective := state.vars
			loopRead := slices.ContainsFunc(state.forked, func(name string) bool { return slices.Contains(reads, name) })
			// unprefixed is the call without prefix assignments that can
			// change which program runs (PATH=/x aws ...). The policy facts
			// are the command's argv, so the call is also judged without
			// them (GAP-1200, #1189): such a prefix can only pick another
			// program of the same name, and a rule that matches the argv
			// then over-blocks at worst, never hides a match. The call with
			// its prefixes is still judged too: dropping PATH alone from
			// `PATH=/missing $'rm' -rf /` would invent a runnable rm for
			// rules that read the prefix.
			unprefixed := ""
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Assigns) != 0 && len(call.Args) != 0 {
				effective = state.clone().vars
				updateSimpleVariables(effective, call.Assigns)
				start := int(call.Args[0].Pos().Offset())
				end := int(call.Pos().Offset())
				if start <= end || start > len(text) {
					return parseGap()
				}
				if simplePrefixChangesResolution(call.Assigns) {
					unprefixed = text[start:]
				} else if simplePrefixBindsUser(call, effective) {
					// The shell body inherits USER and LOGNAME from the
					// prefix: the call without it names other files.
				} else {
					text = text[start:]
					changed = true
				}
			}
			// The shell expands the words of the command, ~ included, before
			// it applies the prefix assignments, so HOME=/tmp cp a ~/f
			// writes the previous ~/f (GAP-2476). The prefixes set only the
			// environment of the program (effective, used for nested scripts).
			resolvedVariable := false
			resolve := func(text string) string {
				if resolved, ok := simpleResolvedVariables(text, state.vars); ok {
					text = resolved
					changed, resolvedVariable = true, true
				}
				if resolved, ok := simpleResolvedDirectoryStackTildes(text, &state, home); ok {
					text = resolved
					changed = true
				}
				if resolved, ok, held := simpleResolvedCurrentFolderHeads(text, &state); ok {
					text = resolved
					changed, resolvedVariable = true, resolvedVariable || held
				}
				if stripped, ok := withoutDescriptorDuplications(text); ok {
					text = stripped
					changed = true
				}
				return text
			}
			text = resolve(text)
			if strings.TrimSpace(text) == "" {
				return parseGap()
			}
			relative := state.cwdUnknown && operands.of(text)
			if relative {
				unproven = true
			}
			call, _ := stmt.Cmd.(*syntax.CallExpr)
			command := SimpleCommand{Text: text, CWD: state.cwd,
				ZshHistoryBuiltin:       simpleZshHistoryCall(call, effective, interpreter),
				LoginGuess:              loopRead,
				LoopReading:             loopRead,
				ResolvedVariable:        resolvedVariable,
				UnresolvedBoundVariable: simpleUnresolvedBoundVariable(text, effective, bound),
				UnboundUser:             simpleUnboundUser(text, effective, bound),
				AbsoluteOnly:            state.cwdUnknown && !relative,
				UnresolvedFolder:        relative,
				LastStageOrBackground:   lastStageOrBackgroundScope(part.scope),
				UnprovenHome:            simpleReadsThroughUnprovenHome(input, state, part.text, text, resolvedVariable)}
			if text == part.text {
				pieces.add(command)
			}
			if !emitted[command] {
				result = append(result, command)
				emitted[command] = true
				own = append(own, command)
				if len(result)-extra > maxSimpleEvaluations {
					return []SimpleCommand{{EvaluationFailure: "limit"}}
				}
			}
			if unprefixed != "" {
				if reading := resolve(unprefixed); strings.TrimSpace(reading) != "" {
					alone := SimpleCommand{Text: reading, CWD: state.cwd,
						ZshHistoryBuiltin:       command.ZshHistoryBuiltin,
						LoginGuess:              command.LoginGuess,
						LoopReading:             command.LoopReading,
						ResolvedVariable:        resolvedVariable,
						UnresolvedBoundVariable: simpleUnresolvedBoundVariable(reading, effective, bound),
						UnboundUser:             simpleUnboundUser(reading, effective, bound),
						AbsoluteOnly:            command.AbsoluteOnly,
						LastStageOrBackground:   command.LastStageOrBackground,
						UnprovenHome:            command.UnprovenHome}
					if reading == unprefixed {
						pieces.add(alone)
					}
					if !emitted[alone] {
						result = append(result, alone)
						emitted[alone] = true
						changed = true
						if len(result)-extra > maxSimpleEvaluations {
							return []SimpleCommand{{EvaluationFailure: "limit"}}
						}
					}
				}
			}
			if call != nil {
				var innerCWDUnknown bool
				var innerInterpreter string
				nestedCall, nestedVars := call, effective
				if state.cwdUnknown || state.cwd == "" && input.CWD == "" {
					// Only a body the caller's expansion left unread is read
					// so; the call keeps the unread body's reading as well
					// (EvaluationFailureUnresolvedBody below), so its verdict
					// is never below the one it had.
					if _, _, nested, static := simpleNestedScript(call, effective, nil, nil); nested && !static {
						folderCall, folderVars := simpleUnknownFolderNestedCall(part.text, call, effective)
						if _, _, nested, static := simpleNestedScript(folderCall, folderVars, nil, nil); nested && static {
							nestedCall, nestedVars = folderCall, folderVars
							// The failure the unread body gives (below).
							unknownFolderBody = EvaluationFailureUnresolvedBody
							if !simplePotentialShellScript(call.Args, effective) || !simpleRuntimeWords(call.Args) {
								unknownFolderBody = "parse"
							}
						}
					}
				}
				script, shared, nested, static := simpleNestedScript(nestedCall, nestedVars, &innerCWDUnknown, &innerInterpreter)
				if nested && !static && simplePotentialShellScript(call.Args, effective) && simpleRuntimeWords(call.Args) {
					// A shell -c body, or a word that may be the -c option,
					// whose text is made at run time: what runs is not known
					// (rel-1-0-10:GAP-0535). The statements around it are
					// still read, each in its folder (a body that runs in the
					// caller may move it): the unknown body is one more
					// finding, never the only reading of the call
					// (rel-1-0-10:GAP-1083).
					unresolvedBody, nested, changed = true, false, true
					if shared {
						state.cwd, state.cwdUnknown = "", true
						delete(state.vars, "PWD")
					}
				}
				if nested {
					if !static {
						// Static text the walk does not model (a quoted
						// pattern, an option it does not read), a trap
						// handler: a parse gap, judged as the whole action.
						return parseGap()
					}
					if len(script) > maxCommandBytes {
						return parseGap()
					}
					innerInput := input
					innerInput.Command, innerInput.Args, innerInput.Argv = script, nil, nil
					innerInput.CWD = state.cwd
					var wrapperFolderUnknown bool
					if folder, changed, unknown := simpleNestedChildFolder(nestedCall.Args, nestedVars, state.cwd); changed {
						innerInput.CWD = folder
						wrapperFolderUnknown = unknown
						innerCWDUnknown = innerCWDUnknown || unknown
					}
					if innerCWDUnknown {
						innerInput.CWD = ""
					}
					// A body that starts after a cd the walk could not follow,
					// or in a call with no folder at all, starts in a folder
					// the walk does not know: its walk knows that, so a
					// current-folder head or a relative operand of the body is
					// read as on the top level (rel-1-0-10:GAP-1042).
					innerInput.folderUnknown = innerInput.CWD == "" && (wrapperFolderUnknown || state.cwdUnknown || input.CWD == "")
					if shared {
						if resolved, ok := simpleResolvedVariables(script, effective); ok {
							innerInput.Command = resolved
						}
					}
					// A body with a syntax error is read as far as it parses
					// (syntaxTailCommands, rel-1-0-10:GAP-0526); a body the
					// parser cannot read at all stays a parse gap.
					_, bodyParsed := shellparse.Parse(innerInput.Command)
					innerFacts := Analyze(innerInput)
					if innerInterpreter == "" {
						innerInterpreter = interpreter
					}
					// The commands of a script the call spells as it is are pieces of
					// the call; those of a script with a variable resolved are not.
					innerPieces := pieces
					if innerInput.Command != script {
						innerPieces = nil
					}
					inner := simpleCommands(innerInput, innerFacts, depth+1, innerInterpreter,
						simpleChildUserVars(call, effective, shared, innerInterpreter, login), guess, innerPieces, operands)
					if !bodyParsed && !slices.ContainsFunc(inner, isSyntaxTailUnread) {
						return parseGap()
					}
					if len(inner) == 0 && strings.TrimSpace(innerInput.Command) != "" {
						zshHistory := innerInterpreter == "zsh" && len(innerFacts.Commands) == 1 &&
							innerFacts.Commands[0].Executable == "history"
						inner = []SimpleCommand{{Text: innerInput.Command, CWD: innerInput.CWD,
							ZshHistoryBuiltin: zshHistory}}
						if innerInput.Command == script {
							pieces.add(inner[0])
						}
					}
					changed = changed || len(inner) != 0
					for _, child := range inner {
						if isSyntaxTailUnread(child) {
							syntaxUnread = true
							continue
						}
						if child.EvaluationFailure != "" {
							unproven = true
							continue
						}
						child.UnresolvedBoundVariable = child.UnresolvedBoundVariable ||
							simpleUnresolvedBoundVariable(child.Text, effective, bound)
						child.UnboundUser = child.UnboundUser || simpleUnboundUser(child.Text, effective, bound)
						child.LastStageOrBackground = child.LastStageOrBackground || command.LastStageOrBackground
						result = append(result, child)
						if child.bodyReading {
							extra++
						}
						if len(result)-extra > maxSimpleEvaluations {
							return []SimpleCommand{{EvaluationFailure: "limit"}}
						}
					}
					// The body starts where its caller is. After a cd that
					// may fail or not run, that is each folder the tracking
					// gives the call (mayRunIn), not only the one the walk
					// moved to: `cd X || cd Y && eval "$body"` runs the body
					// in X or Y, so it is read in each of them as well
					// (rel-1-0-10:GAP-1144, GAP-0183). A body that starts in
					// a folder of its own (innerCWDUnknown) has none.
					//
					// These readings come on top of the statements of the
					// call: they never make the call over its budget. Past
					// maxSimpleEvaluations readings in all, the body is not
					// read again folder by folder; each statement of it with a
					// relative operand is kept as a reading in a folder the
					// walk does not give (UnresolvedFolder), which the gateway
					// judges by the protected files it may name there, beside
					// every reading made before (the one bound rule,
					// rel-1-0-10:GAP-1228).
					if !innerCWDUnknown && innerInput.CWD != "" {
						capped := false
						for _, dir := range mayRunIn[partIndex] {
							if dir == innerInput.CWD {
								continue
							}
							if len(result) >= maxSimpleEvaluations {
								capped = true
								break
							}
							otherInput := innerInput
							otherInput.CWD, otherInput.folderUnknown = dir, false
							others := simpleCommands(otherInput, Analyze(otherInput), depth+1, innerInterpreter,
								simpleChildUserVars(call, effective, shared, innerInterpreter, login), guess, nil, operands)
							if len(others) == 0 && strings.TrimSpace(otherInput.Command) != "" {
								others = []SimpleCommand{{Text: otherInput.Command, CWD: dir}}
							}
							for _, child := range others {
								if isSyntaxTailUnread(child) {
									syntaxUnread = true
									continue
								}
								if child.EvaluationFailure != "" {
									unproven = true
									continue
								}
								if !operands.of(child.Text) {
									continue // read in its own folder above
								}
								child.UnresolvedBoundVariable = child.UnresolvedBoundVariable ||
									simpleUnresolvedBoundVariable(child.Text, effective, bound)
								child.UnboundUser = child.UnboundUser || simpleUnboundUser(child.Text, effective, bound)
								child.OtherFolder, child.bodyReading = true, true
								if emitted[child] {
									continue
								}
								if len(result) >= maxSimpleEvaluations {
									capped = true
									break
								}
								emitted[child] = true
								result = append(result, child)
								extra++
							}
						}
						if capped {
							for _, child := range inner {
								if child.EvaluationFailure != "" || child.OtherFolder || !operands.of(child.Text) {
									continue
								}
								child.UnresolvedBoundVariable = child.UnresolvedBoundVariable ||
									simpleUnresolvedBoundVariable(child.Text, effective, bound)
								child.UnboundUser = child.UnboundUser || simpleUnboundUser(child.Text, effective, bound)
								child.CWD, child.AbsoluteOnly = "", false
								child.OtherFolder, child.UnresolvedFolder, child.bodyReading = true, true, true
								if emitted[child] {
									continue
								}
								emitted[child] = true
								result = append(result, child)
								extra++
							}
						}
					}
					if shared && !bodyParsed {
						// The directory a shared body leaves is not known
						// past its unread part.
						state.cwd, state.cwdUnknown = "", true
						delete(state.vars, "PWD")
					}
					if shared {
						for _, innerCommand := range innerFacts.Commands {
							if ChangesShellDirectory(innerCommand) {
								state.cwd, state.cwdUnknown = "", true
								delete(state.vars, "PWD")
								break
							}
						}
					}
				}
			}
			if decl, ok := stmt.Cmd.(*syntax.DeclClause); ok {
				// export HOME=v sets HOME for the commands after it, as
				// HOME=v; export HOME does (GAP-2476).
				var folderNames []string
				if folder, names, ok := simpleUnknownFolderAssignment(part.text, &state); ok {
					if folderDecl, ok := folder.Cmd.(*syntax.DeclClause); ok && len(folderDecl.Args) == len(decl.Args) {
						decl, folderNames = folderDecl, names
					}
				}
				updateSimpleDeclVariables(&state, decl, part.scope)
				state.setFolderVars(simpleAssignNames(decl.Args), folderNames)
			}
			if call != nil {
				simpleForgetUserVars(state.vars, CallBindsUserNames(call))
				if simpleCallReadsHome(call) {
					// read HOME: the value is known only when it runs, and
					// HOME is the active home again (rel-1-0-10:GAP-0996,
					// GAP-1087).
					state.unproveHome()
				}
			}
			nextCWD, changedDirectory := simpleCommandNextCWD(text, &state, effective)
			if !changedDirectory {
				// An unmodeled shell builtin or dynamic program may move the
				// caller's directory. Later relative operands cannot use the
				// original hook directory as an authoritative base.
				if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) != 0 {
					program, known := simpleStaticProgramWord(call.Args[0], effective)
					if !known || program != "trap" &&
						ChangesShellDirectory(CommandFact{Dialect: DialectPOSIX, Program: program}) {
						nextCWD, changedDirectory = "", true
					}
				}
			}
			if changedDirectory {
				// A value spelled relative to the folder the walk did not know
				// names another file in the next one.
				simpleForgetUserVars(state.vars, state.folderVars)
				state.folderVars = nil
				if state.cwd != "" {
					state.vars["OLDPWD"] = state.cwd
				} else {
					delete(state.vars, "OLDPWD")
				}
				if nextCWD != "" {
					state.vars["PWD"] = nextCWD
				} else {
					delete(state.vars, "PWD")
				}
			}
			state.cwd = nextCWD
			if changedDirectory {
				state.cwdUnknown = nextCWD == ""
			}
			if part.read != nil {
				state.vars[part.read.name] = part.read.word
			}
			nextVariants = append(nextVariants, simpleHomeReadings(state)...)
			if part.maySkip && (len(prior.forked) != 0 || simpleHomeChanged(prior, state)) {
				// The statement may not run: the word of the loop, and the
				// HOME it would change (false && export HOME=/x), stay as
				// they were (rel-1-0-10:GAP-0996).
				nextVariants = append(nextVariants, prior)
			}
		}
		for _, command := range own {
			// A statement the walk placed nowhere (after a dynamic command
			// word, an eval or an unmodeled builtin that may move the shell)
			// is read in every folder the working-folder tracking gives it,
			// the one the shell was in before that command included, and it
			// keeps UnresolvedFolder, so the unknown tier applies as well:
			// the folder it may still be in judges it, never the unplaced
			// reading alone (rel-1-0-10:GAP-1083, substrate-1:GAP-0367).
			// A reading of the guess walk (LoginGuess) stays where the walk
			// read it: it only proves a state write by the login it spells,
			// which the walk could not bind there (u=$USER; command echo
			// IFS=x; read u <<< w), and placed in a folder it proved one the
			// shell never makes.
			dirs := mayRunIn[partIndex]
			if len(dirs) == 0 || guess || command.LoginGuess || !operands.of(command.Text) {
				continue
			}
			for _, dir := range mayRunIn[partIndex] {
				again := command
				again.CWD, again.AbsoluteOnly = dir, false
				if emitted[again] {
					continue // the walk itself read it there
				}
				emitted[again] = true
				again.OtherFolder = true
				result = append(result, again)
				if len(result)-extra > maxSimpleEvaluations {
					return []SimpleCommand{{EvaluationFailure: "limit"}}
				}
			}
		}
		states[part.scope] = compact(uniqueSimpleStates(nextVariants), partIndex+1)
		if simpleOverStateBound(states[part.scope]) {
			return []SimpleCommand{{EvaluationFailure: "limit"}}
		}
	}
	if !changed {
		return nil
	}
	result, fits := simpleExpandPlainWords(result, &plainWords)
	if !fits {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	if syntaxUnread {
		result = append(result, SimpleCommand{EvaluationFailure: EvaluationFailureSyntax})
	}
	if unknownFolderBody != "" {
		result = append(result, SimpleCommand{EvaluationFailure: unknownFolderBody})
	}
	if unresolvedBody && unknownFolderBody != EvaluationFailureUnresolvedBody {
		result = append(result, SimpleCommand{EvaluationFailure: EvaluationFailureUnresolvedBody})
	}
	if unproven {
		return append(result, SimpleCommand{EvaluationFailure: "parse"})
	}
	return result
}

// windowsSimpleCommands uses the same lexer as Analyze to find statement and
// pipeline boundaries. The source slices preserve quotes, escaping and path
// spelling for each standalone policy evaluation.
func windowsSimpleCommands(input Input, facts Facts) []SimpleCommand {
	source := input.Command
	if source == "" && argsExecutionTool(input.Tool) {
		source = extractArgsForTool(input.Args, input.Tool).command
	}
	if source == "" {
		return nil
	}
	if len(source) > maxCommandBytes {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	dialect := windowsPowerShell
	if facts.Parse.Dialect == DialectCMD {
		dialect = windowsCMD
	}
	if !strings.ContainsAny(source, ";&|\n\r") && !windowsSimplePotentialGroup(source, dialect) {
		return nil
	}
	var groupEvents []windowsSimpleGroupEvent
	source, groupEvents, ok := windowsSimpleGroupSource(source, dialect)
	if !ok {
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	out := newParseOutput(facts.Parse.Dialect, 1)
	lexemes, ok := windowsLex(source, dialect, &out)
	if !ok || out.status == StatusInvalid {
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	if out.status == StatusLimitExceeded {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	lexemes = windowsSimpleContinuedLexemes(lexemes)
	if _, _, ok = windowsBuildCommands(lexemes, &out); !ok {
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	if len(groupEvents) != 0 && strings.TrimSpace(source) == "" {
		return nil
	}
	runes := []rune(source)
	begin := 0
	result := make([]SimpleCommand, 0, 2)
	variables := make(map[string]string)
	state := simpleWindowsState{cwd: input.CWD, trackOthers: windowsSimpleCallFolder(input.CWD)}
	failed := false
	// readings counts the readings of a statement in another folder it may
	// run in (OtherFolder): readings, not statements of the call; placed
	// counts those that name the folder.
	readings, placed := 0, 0
	groupIndex := 0
	var groups []simpleWindowsGroupSnapshot
	processGroupEvents := func(before int) {
		for groupIndex < len(groupEvents) && groupEvents[groupIndex].offset < before {
			if groupEvents[groupIndex].open {
				groups = append(groups, state.groupSnapshot(variables))
			} else if len(groups) == 0 {
				failed = true
			} else {
				state.mergeGroup(groups[len(groups)-1], variables)
				groups = groups[:len(groups)-1]
			}
			groupIndex++
		}
	}
	appendPart := func(part string, start, end int, operator string) {
		childStart := start
		for childStart < end && unicode.IsSpace(runes[childStart]) {
			childStart++
		}
		processGroupEvents(childStart)
		childInput := input
		childInput.CWD = state.cwd
		if dialect == windowsPowerShell {
			if windowsSimpleLiteralOutput(part) {
				result = append(result, SimpleCommand{Text: part, CWD: state.cwd, LiteralOutputOnly: true})
				// It moves nothing; the folders an && skipped come back.
				state.advance(part, dialect, childInput, variables, operator)
				processGroupEvents(end)
				return
			}
			if name, only := windowsSimpleOpaqueValueAssignment(part); only {
				delete(variables, name)
				state.forgetKnownVariables(variables)
				if state.referencesUncertainVariable(part) {
					failed = true
				}
				result = append(result, SimpleCommand{Text: part, CWD: state.cwd, OpaqueValueAssignment: true})
				// It moves nothing; the folders an && skipped come back.
				state.advance(part, dialect, childInput, variables, operator)
				processGroupEvents(end)
				return
			}
		}
		text := part
		if dialect == windowsPowerShell {
			if !windowsSimpleAssignment(part, childInput, variables) {
				text = windowsSimpleResolvedVariables(part, variables)
			}
		}
		state.forgetKnownVariables(variables)
		if state.referencesUncertainVariable(part) {
			failed = true
		}
		if state.cwdUnknown && windowsSimpleRelativePathOperand(text, facts.Parse.Dialect) {
			failed = true
		}
		result = append(result, SimpleCommand{Text: text, CWD: state.cwd})
		if (len(state.others) != 0 || state.othersUnresolved) && windowsSimpleRelativePathOperand(text, facts.Parse.Dialect) {
			// A relative operand names a file in each folder the
			// statement may run in (rel-1-0-10:GAP-1150). Those readings
			// come on top of the statements of the call, which keep the
			// budget they have on rel. Past maxSimpleWindowsOtherReadings
			// of them, the statement is read once more as in a folder the
			// walk does not give (UnresolvedFolder), as past
			// maxSimpleWindowsFolders, beside every reading made before:
			// never the whole-call limit (the one bound rule,
			// rel-1-0-10:GAP-1228).
			//
			// The folders past the cap stay on that reading
			// (CappedFolders): the gateway reads the statement in those
			// of them where its operand may name a protected file, as
			// below the cap, so the cap drops only benign readings
			// (rel-1-0-10:GAP-1281).
			unresolved := state.othersUnresolved
			var capped []string
			if placed+len(state.others) <= maxSimpleWindowsOtherReadings {
				for _, other := range state.others {
					result = append(result, SimpleCommand{Text: text, CWD: other.cwd, OtherFolder: true})
					readings++
					placed++
				}
			} else {
				unresolved = true
				for _, other := range state.others {
					capped = append(capped, other.cwd)
				}
			}
			if unresolved {
				reading := SimpleCommand{Text: text, OtherFolder: true, UnresolvedFolder: true}
				if len(capped) != 0 {
					reading.cappedFolders = &capped
				}
				result = append(result, reading)
				readings++
			}
		}
		state.advance(part, dialect, childInput, variables, operator)
		processGroupEvents(end)
	}
	for _, lexeme := range lexemes {
		if lexeme.kind != windowsSeparatorLexeme && lexeme.kind != windowsPipeLexeme {
			continue
		}
		if lexeme.start < begin || lexeme.end > len(runes) {
			return []SimpleCommand{{EvaluationFailure: "parse"}}
		}
		part := strings.TrimSpace(string(runes[begin:lexeme.start]))
		if part == "" {
			return []SimpleCommand{{EvaluationFailure: "parse"}}
		}
		operator := lexeme.operator
		if lexeme.kind == windowsPipeLexeme {
			operator = "|"
		}
		appendPart(part, begin, lexeme.start, operator)
		begin = lexeme.end
		if lexeme.kind == windowsPipeLexeme || lexeme.operator == "&&" || lexeme.operator == "||" {
			// A pipeline stage has a separate scope; conditional assignments
			// may not have run. Do not carry either into a later command.
			clear(variables)
		}
		if len(result)-readings >= maxStatementsAlone {
			return []SimpleCommand{{EvaluationFailure: "limit"}}
		}
	}
	if len(result) == 0 && len(groupEvents) == 0 {
		return nil
	}
	last := strings.TrimSpace(string(runes[begin:]))
	if last == "" {
		if dialect == windowsPowerShell && len(lexemes) != 0 &&
			lexemes[len(lexemes)-1].kind == windowsSeparatorLexeme &&
			lexemes[len(lexemes)-1].operator == ";" {
			if failed {
				return append(result, SimpleCommand{EvaluationFailure: "parse"})
			}
			return result
		}
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	appendPart(last, begin, len(runes), "")
	if failed {
		return append(result, SimpleCommand{EvaluationFailure: "parse"})
	}
	return result
}

// Recognize only bounded PowerShell path assignments. An unresolved value is
// left dynamic, so its later use keeps the ordinary fail-closed path proof.
func windowsSimpleAssignment(part string, input Input, variables map[string]string) bool {
	out := newParseOutput(DialectPowerShell, 1)
	lexemes, ok := windowsLex(part, windowsPowerShell, &out)
	if !ok || len(lexemes) < 3 {
		return false
	}
	words := make([]windowsWord, 0, len(lexemes))
	for _, lexeme := range lexemes {
		if lexeme.kind != windowsWordLexeme {
			return false
		}
		words = append(words, lexeme.word)
	}
	name := strings.ToLower(words[0].value)
	if words[0].quote != QuoteNone || !windowsSimpleVariableName(name) || words[1].value != "=" {
		return false
	}
	delete(variables, name)
	var value string
	switch {
	case len(words) == 3:
		value, ok = windowsSimplePathValue(words[2], input, variables)
	case len(words) == 5 && strings.EqualFold(words[2].value, "Join-Path"):
		var base string
		base, ok = windowsSimplePathValue(words[3], input, variables)
		child := words[4]
		if !ok || child.expands || child.wildcard || child.value == "" ||
			strings.ContainsAny(child.value, "$%`*?[]\r\n") ||
			strings.HasPrefix(child.value, "/") || strings.HasPrefix(child.value, `\`) ||
			strings.Contains(child.value, ":") {
			ok = false
			break
		}
		for _, component := range strings.Split(strings.ReplaceAll(child.value, `\`, "/"), "/") {
			if component == ".." || strings.Contains(component, "~") {
				ok = false
				break
			}
		}
		if ok {
			_, _, value = deriveWindowsPathWithPolicy(joinWindowsPath(base, child.value),
				input.CWD, input.ActiveHome, pathExpansionPolicy{expandTilde: true})
			ok = value != ""
		}
	default:
		ok = false
	}
	if ok {
		variables[name] = value
	}
	return true
}

func windowsSimplePathValue(word windowsWord, input Input, variables map[string]string) (string, bool) {
	if word.quote != QuoteSingle && windowsSimpleVariableName(strings.ToLower(word.value)) {
		if value, ok := variables[strings.ToLower(word.value)]; ok {
			return value, true
		}
		if strings.EqualFold(word.value, "$HOME") {
			_, _, value := deriveWindowsPathWithPolicy(input.ActiveHome, input.CWD,
				input.ActiveHome, pathExpansionPolicy{expandTilde: true})
			return value, value != ""
		}
	}
	if word.expands || word.wildcard || strings.ContainsAny(word.value, "$%`*?[]\r\n") {
		return "", false
	}
	_, _, value := deriveWindowsPathWithPolicy(word.value, input.CWD, input.ActiveHome,
		pathExpansionPolicy{expandTilde: true})
	return value, value != ""
}

func windowsSimpleVariableName(value string) bool {
	if len(value) < 2 || value[0] != '$' ||
		!windowsSimpleVariableLetter(rune(value[1])) {
		return false
	}
	for _, char := range value[2:] {
		if !windowsSimpleVariableLetter(char) && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func windowsSimpleVariableLetter(char rune) bool {
	return char >= 'a' && char <= 'z' || char == '_'
}

func windowsSimpleResolvedVariables(source string, variables map[string]string) string {
	if len(variables) == 0 {
		return source
	}
	runes := []rune(source)
	var result strings.Builder
	var quote rune
	writePath := func(value string) {
		result.WriteByte('\'')
		result.WriteString(strings.ReplaceAll(value, "'", "''"))
		result.WriteByte('\'')
	}
	for index := 0; index < len(runes); index++ {
		char := runes[index]
		if char == '`' && quote != '\'' && index+1 < len(runes) {
			result.WriteRune(char)
			index++
			result.WriteRune(runes[index])
			continue
		}
		if char == '"' && quote == 0 {
			end := index + 1
			for end < len(runes) && runes[end] != '"' && runes[end] != '`' {
				end++
			}
			if end < len(runes) && runes[end] == '"' {
				name := strings.ToLower(string(runes[index+1 : end]))
				if windowsSimpleVariableName(name) {
					if value, ok := variables[name]; ok {
						writePath(value)
						index = end
						continue
					}
				}
			}
		}
		if char == '\'' || char == '"' {
			switch quote {
			case 0:
				quote = char
			case char:
				quote = 0
			}
			result.WriteRune(char)
			continue
		}
		if char == '$' && quote == 0 && index+1 < len(runes) &&
			(unicode.IsLetter(runes[index+1]) || runes[index+1] == '_') {
			end := index + 2
			for end < len(runes) && (unicode.IsLetter(runes[end]) || unicode.IsDigit(runes[end]) || runes[end] == '_') {
				end++
			}
			if end == len(runes) || runes[end] != ':' {
				if value, ok := variables[strings.ToLower(string(runes[index:end]))]; ok {
					writePath(value)
					index = end - 1
					continue
				}
			}
		}
		result.WriteRune(char)
	}
	return result.String()
}

func simplePrefixChangesResolution(assigns []*syntax.Assign) bool {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil {
			continue
		}
		switch assign.Name.Value {
		case "PATH", "IFS", "CDPATH", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS":
			return true
		}
		if strings.HasPrefix(assign.Name.Value, "LD_") ||
			strings.HasPrefix(assign.Name.Value, "DYLD_") {
			return true
		}
	}
	return false
}

func uniqueSimpleStates(states []simpleShellState) []simpleShellState {
	result := make([]simpleShellState, 0, len(states))
	for _, state := range states {
		if !slices.ContainsFunc(result, func(previous simpleShellState) bool {
			return previous.cwd == state.cwd && previous.cwdUnknown == state.cwdUnknown &&
				slices.Equal(previous.dirStack, state.dirStack) && maps.Equal(previous.vars, state.vars) &&
				slices.Equal(previous.locals, state.locals) && previous.homeUnproven == state.homeUnproven &&
				previous.homeGuess == state.homeGuess && slices.Equal(previous.folderVars, state.folderVars)
		}) {
			result = append(result, state)
		}
	}
	return result
}

// A branch may produce many distinct assignments that no later command
// reads. Once the state cap is reached, merge states that differ only in
// those dead values. Keep shell control variables, and leave indirect name
// lookup and code evaluation to the existing fail-closed state bound.
func compactSimpleStatesForFuture(states []simpleShellState, remaining []sequenceStatement, safe bool) []simpleShellState {
	if !safe {
		return states
	}
	var future strings.Builder
	for _, part := range remaining {
		future.WriteString(part.text)
		future.WriteByte('\n')
	}
	text := future.String()
	for i, state := range states {
		state = state.clone()
		for name := range state.vars {
			switch name {
			case "HOME", "PWD", "OLDPWD", "IFS", "PATH", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE":
				continue
			}
			if !strings.Contains(text, name) {
				delete(state.vars, name)
			}
		}
		states[i] = state
	}
	return uniqueSimpleStates(states)
}

func simplePartCompactionSafe(part sequenceStatement) bool {
	file, ok := shellparse.Parse(part.text)
	if !ok {
		return false
	}
	indirect := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if indirect {
			return false
		}
		switch node := node.(type) {
		case *syntax.ParamExp:
			indirect = node.Excl || node.NestedParam != nil || node.Flags != nil
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ArithmCmd, *syntax.LetClause, *syntax.FuncDecl:
			indirect = true
		case *syntax.CallExpr:
			if len(node.Args) > 0 {
				program, fixed := simpleStaticProgramWord(node.Args[0], nil)
				if !fixed {
					indirect = true
				} else {
					switch program {
					case ":", "[", "test", "true", "false", "echo", "cp", "gcp":
					default:
						indirect = true
					}
				}
			}
		}
		return !indirect
	})
	return !indirect
}

// Longer case chains retain the original state bound. Repeatedly merging
// their candidate sets costs more than the bounded analysis is allowed to
// spend, while the ordinary six-option script stays within this limit.
func simpleTooManyCompactionCases(source string) bool {
	if !strings.Contains(source, "case") {
		return false
	}
	file, ok := shellparse.Parse(source)
	if !ok {
		return true
	}
	cases := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.CaseClause); ok {
			cases++
		}
		return cases <= maxCompactionCases
	})
	return cases > maxCompactionCases
}

// updateSimpleDeclVariables applies each NAME=value word of an export,
// readonly, declare, typeset or local statement to vars, as
// updateSimpleVariables applies a bare NAME=value: a later $NAME, and for
// HOME every later ~, then names value. A name with no value keeps its
// value. An option other than -x, -r and -g (export -n also assigns) can
// change what the value means (a reference, an integer, a case or an array
// attribute): HOME then keeps its previous value, so a later ~ or $HOME
// write is still judged against a home the call can reach (GAP-2476,
// RV-pc11-1), and any other name is unknown. export F=<file> names the
// file for a later "$F" as F=<file> does; it was left unbound, so a write
// through it named no file for any path rule (gas-ux-r1 GAP-0076).
//
// local NAME=v counts only in a function body, until the body ends: bash
// refuses local outside a function (the name is unchanged), and the
// caller value is back once the function returns (RV-pod2-2). declare and
// typeset without -g in a function body are local too; export, readonly
// and declare -g there set the caller value (checker p3i3 D01-D21).
func updateSimpleDeclVariables(state *simpleShellState, decl *syntax.DeclClause, scope string) {
	if decl == nil || decl.Variant == nil {
		return
	}
	vars := state.vars
	local := false
	switch decl.Variant.Value {
	case "export", "readonly":
	case "declare", "typeset":
		// In a function body declare and typeset make the name local
		// unless -g is given (bash, ksh); at the top level they set it.
		local = simpleFunctionBodyScope(scope) != "" && !simpleDeclGlobal(decl)
	case "local":
		if simpleFunctionBodyScope(scope) == "" {
			return
		}
		local = true
	default:
		return
	}
	if local {
		body := simpleFunctionBodyScope(scope)
		for _, assign := range decl.Args {
			if assign == nil || assign.Name == nil {
				continue
			}
			name := assign.Name.Value
			if slices.ContainsFunc(state.locals, func(saved simpleLocal) bool {
				return saved.scope == body && saved.name == name
			}) {
				continue
			}
			value, known := vars[name]
			state.locals = append(state.locals, simpleLocal{scope: body, name: name, value: value, known: known})
		}
	}
	known := true
	options, strays := simpleDeclOptions(decl)
	for _, option := range options {
		if decl.Variant.Value == "export" && !option.Expands && option.Value == "-n" {
			continue
		}
		if !homeDeclOption(option) {
			known = false
		}
	}
	// A word after the first name that is no option (declare IFS=x -p) is a
	// name too: it sets nothing unless it expands or spells an assignment.
	for _, stray := range strays {
		if stray.Expands || strings.Contains(stray.Value, "=") {
			known = false
		}
	}
	for _, assign := range decl.Args {
		if assign == nil || assign.Name == nil || assign.Naked {
			continue
		}
		if !known || assign.Index != nil || assign.Array != nil {
			if assign.Name.Value != "HOME" {
				delete(vars, assign.Name.Value)
			} else {
				state.unproveHome()
			}
			continue
		}
		guess, guessed := simpleRunTimeHomeGuessOf([]*syntax.Assign{assign}, *state)
		state.noteHome(updateSimpleVariables(vars, []*syntax.Assign{assign}))
		state.noteHomeGuess(guess, guessed)
	}
}

// simpleDeclOptions splits the words of a declaration (export, readonly,
// declare, typeset, local) that are no assignment, as bash reads them: the
// options are the words in front of the first name, up to and with --, and
// every later word is a stray, a name bash rejects (declare d=x -g sets d
// and reports -g; it is no option). This one scan serves every reader of a
// declaration option, so no two of them can order the options differently.
func simpleDeclOptions(decl *syntax.DeclClause) (options, strays []ArgumentFact) {
	leading := true
	for _, assign := range decl.Args {
		switch {
		case assign == nil || assign.Value == nil && assign.Name == nil:
		case assign.Name != nil:
			leading = false
		case !leading:
			strays = append(strays, projectPOSIXWord(assign.Value))
		default:
			word := projectPOSIXWord(assign.Value)
			if !word.Expands && !strings.HasPrefix(word.Value, "-") && !strings.HasPrefix(word.Value, "+") {
				// Not an option: the first name, and the options end.
				leading = false
				strays = append(strays, word)
				continue
			}
			options = append(options, word)
			if !word.Expands && word.Value == "--" {
				leading = false
			}
		}
	}
	return options, strays
}

// simpleDeclGlobal reports a static -g option of a declaration.
func simpleDeclGlobal(decl *syntax.DeclClause) bool {
	options, _ := simpleDeclOptions(decl)
	return slices.ContainsFunc(options, func(option ArgumentFact) bool {
		return !option.Expands && strings.HasPrefix(option.Value, "-") && strings.ContainsRune(option.Value[1:], 103)
	})
}

// simpleScopeStates returns the states of scope: its own, or copies of
// those of the nearest scope around it that has states. nil means none.
func simpleScopeStates(states map[string][]simpleShellState, scope string) []simpleShellState {
	if own, present := states[scope]; present {
		return own
	}
	for {
		index := strings.LastIndexByte(scope, '/')
		if index < 0 {
			return nil
		}
		scope = scope[:index]
		if inherited, ok := states[scope]; ok {
			copies := make([]simpleShellState, 0, len(inherited))
			for _, state := range inherited {
				copies = append(copies, state.clone())
			}
			return copies
		}
	}
}

// simpleFunctionBodyScope returns the innermost function body scope (kind
// f or e) that holds scope, or "" at the top level of the action.
func simpleFunctionBodyScope(scope string) string {
	for {
		index := strings.LastIndexByte(scope, '/')
		if index < 0 {
			return ""
		}
		if kind := scope[index+1]; kind == 'f' || kind == 'e' {
			return scope
		}
		scope = scope[:index]
	}
}

// simpleEndFunctionBody restores the caller values that the local
// declarations of the function body of scope saved.
func simpleEndFunctionBody(states []simpleShellState, scope string) []simpleShellState {
	ended := make([]simpleShellState, 0, len(states))
	for _, state := range states {
		state = state.clone()
		for last := len(state.locals) - 1; last >= 0 && state.locals[last].scope == scope; last-- {
			saved := state.locals[last]
			state.locals = state.locals[:last]
			if saved.known {
				state.vars[saved.name] = saved.value
			} else {
				delete(state.vars, saved.name)
			}
		}
		ended = append(ended, state)
	}
	return ended
}

// updateSimpleVariables applies assigns to vars. It reports whether one of
// them set HOME and whether the walk read the value HOME has after them.
func updateSimpleVariables(vars map[string]string, assigns []*syntax.Assign) (homeSet, homeKnown bool) {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil || assign.Index != nil || assign.Array != nil {
			continue
		}
		name := assign.Name.Value
		known := true
		if assign.Value == nil {
			vars[name] = ""
		} else if value, static := simpleStaticWord(assign.Value, vars); static {
			vars[name] = value
		} else {
			known = false
			if name != "HOME" {
				delete(vars, name)
			}
		}
		// A HOME value the walk cannot read (HOME=$(echo $HOME), HOME=$X)
		// leaves vars as they are; the state then makes HOME the active home
		// (noteHome): an unknown HOME dropped every later ~ write
		// (GAP-2476). The home a run-time value moves to is not known, so the
		// state records it as unproven (rel-1-0-10:GAP-0996, GAP-1087).
		if name == "HOME" {
			homeSet, homeKnown = true, known
		}
	}
	return homeSet, homeKnown
}

// The full action may bind a value that the simple-command walk cannot
// resolve. Record only shell bindings, using the shared shell parser.
func simpleBoundVariables(file *syntax.File) (bound map[string]bool) {
	bound = make(map[string]bool)
	if file == nil {
		return bound
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch part := node.(type) {
		case *syntax.Assign:
			if part.Name != nil {
				bound[part.Name.Value] = true
			}
		case *syntax.WordIter:
			if part.Name != nil {
				bound[part.Name.Value] = true
			}
		case *syntax.FuncDecl:
			for i := '1'; i <= '9'; i++ {
				bound[string(i)] = true
			}
		case *syntax.CallExpr:
			if len(part.Args) == 0 {
				break
			}
			program, known := simpleStaticWord(part.Args[0], nil)
			if !known {
				break
			}
			switch program {
			case "printf":
				if len(part.Args) >= 3 && part.Args[1].Lit() == "-v" {
					if name, known := simpleStaticWord(part.Args[2], nil); known && simpleVariableName(name) {
						bound[name] = true
					}
				}
			case "read", "mapfile", "readarray":
				for _, arg := range part.Args[1:] {
					name, known := simpleStaticWord(arg, nil)
					if !known {
						break
					}
					if strings.HasPrefix(name, "-") {
						continue
					}
					if simpleVariableName(name) {
						bound[name] = true
					}
					break
				}
			}
		}
		return true
	})
	return bound
}

// CallBindsUserNames returns the names of USER and LOGNAME that the call
// binds where a walk cannot follow the value: read and mapfile (readarray)
// name them as variables, not as the value of an option such as read -p, a
// printf -v names one, and the text of an eval, trap or source may bind any
// it spells (any when it is not static). The statements after the call read
// no value for them; the statements before it do.
func CallBindsUserNames(call *syntax.CallExpr) []string {
	return callBindsNames(call, func(name string) bool { return slices.Contains(simpleUserNames, name) }, simpleUserNames)
}

// callBindsNames is CallBindsUserNames for the names match accepts: read,
// mapfile and printf -v name one; eval and trap code binds the names it binds
// itself (evalCodeBindsNames); a sourced file, or code that is not static,
// may bind any, which is every. The here-document consumer reading uses it
// for PATH and the other names that change what a word runs
// (hereDocCallBindings, rel-1-0-10:GAP-0913).
func callBindsNames(call *syntax.CallExpr, match func(string) bool, every []string) []string {
	if call == nil || len(call.Args) == 0 {
		return nil
	}
	program, known := simpleStaticWord(call.Args[0], nil)
	if !known {
		return nil
	}
	var names []string
	add := func(name string) {
		if match(name) && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	switch program {
	case "printf":
		if len(call.Args) >= 3 && call.Args[1].Lit() == "-v" {
			if name, known := simpleStaticWord(call.Args[2], nil); known {
				add(name)
			} else {
				// A name the walk cannot read may be any name
				// (rel-1-0-10:GAP-1044).
				for _, user := range every {
					add(user)
				}
			}
		}
	case "read", "mapfile", "readarray":
		// An option that takes a value takes the next word: read -p USER
		// OTHER binds OTHER (and the array of read -a), not USER. A word the
		// walk cannot read may be any name.
		valued := "dinNptu"
		if program != "read" {
			valued = "dnOsuC"
		}
		options := true
		for index := 1; index < len(call.Args); index++ {
			name, known := simpleStaticWord(call.Args[index], nil)
			switch {
			case !known:
				for _, user := range every {
					add(user)
				}
			case options && name == "--":
				options = false
			case options && len(name) > 1 && name[0] == '-':
				for at := 1; at < len(name); at++ {
					if strings.ContainsRune(valued, rune(name[at])) {
						if at == len(name)-1 {
							index++
						}
						break
					}
					if program == "read" && name[at] == 'a' && at == len(name)-1 && index+1 < len(call.Args) {
						// read -a names the array it fills.
						array, _ := simpleStaticWord(call.Args[index+1], nil)
						add(array)
						index++
					}
				}
			default:
				options = false
				add(name)
			}
		}
	case ".", "source":
		// The sourced file is code the walk does not read.
		for _, name := range every {
			add(name)
		}
	case "eval", "trap":
		// The code an eval or trap runs binds the names it binds itself: a
		// no-op, or code that only mentions USER, binds nothing.
		code := call.Args[1:]
		if program == "trap" {
			code = code[:min(len(code), 1)]
			if len(code) != 0 && simpleStaticWordOrEmpty(code[0], '-') {
				code = nil
			}
		}
		var words []string
		for _, arg := range code {
			text, known := simpleStaticWord(arg, nil)
			if !known {
				for _, name := range every {
					add(name)
				}
				return names
			}
			words = append(words, text)
		}
		for _, name := range evalCodeBindsNames(strings.Join(words, " "), match, every) {
			add(name)
		}
	}
	return names
}

// simpleCallReadsHome reports a read, mapfile, readarray or printf -v call
// that binds HOME to a value it reads when it runs (rel-1-0-10:GAP-0996).
func simpleCallReadsHome(call *syntax.CallExpr) bool {
	if call == nil || len(call.Args) == 0 {
		return false
	}
	switch program, _ := simpleStaticWord(call.Args[0], nil); program {
	case "read", "mapfile", "readarray", "printf":
		return slices.Contains(callBindsNames(call, func(name string) bool { return name == "HOME" }, []string{"HOME"}), "HOME")
	}
	return false
}

// simpleStaticWordOrEmpty reports a static word that starts with prefix.
func simpleStaticWordOrEmpty(word *syntax.Word, prefix byte) bool {
	text, known := simpleStaticWord(word, nil)
	return known && text != "" && text[0] == prefix
}

// evalCodeBindsNames returns the names match accepts that the shell code
// text binds: an assignment, a loop name, or a call that binds one
// (callBindsNames, so a nested eval is read the same way; its code is part
// of text, so the walk ends). Code that does not parse may bind any: every.
func evalCodeBindsNames(text string, match func(string) bool, every []string) []string {
	file, ok := shellparse.Parse(text)
	if !ok {
		return every
	}
	var names []string
	add := func(name string) {
		if match(name) && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Assign:
			if node.Name != nil {
				add(node.Name.Value)
			}
		case *syntax.WordIter:
			if node.Name != nil {
				add(node.Name.Value)
			}
		case *syntax.CallExpr:
			for _, name := range callBindsNames(node, match, every) {
				add(name)
			}
		}
		return true
	})
	return names
}

// simpleApplyLoopBinds gives each name a for or select loop binds the value
// it has in the iteration that matters. A list that can hold the login the
// home spells (an empty list, the login or a name that holds it, a word the
// walk cannot read or that has a pattern) gives the name that login in the
// iteration that has it: the statement in the body is read with it, as the
// shell runs it. A list of other logins only leaves the name without a
// value the walk can follow (rel-1-0-6:GAP-0630, GAP-0681 review 7).
func simpleApplyLoopBinds(vars map[string]string, binds []simpleLoopBind, login map[string]string) {
	for _, bind := range binds {
		if bind.fork {
			continue
		}
		active, hasLogin := login[bind.name]
		reads := hasLogin && len(bind.items) == 0
		for _, word := range bind.items {
			value, known := simpleStaticWord(word, vars)
			reads = reads || hasLogin && (!known || value == active || strings.ContainsAny(value, "*?["))
		}
		if reads {
			vars[bind.name] = active
		} else {
			delete(vars, bind.name)
		}
	}
}

// simpleForgetUserVars drops the value of each name from vars.
func simpleForgetUserVars(vars map[string]string, names []string) {
	for _, name := range names {
		delete(vars, name)
	}
}

// simpleJoinForgottenUserVars is merged less the USER and LOGNAME values
// that a conditional or loop body forgot: a name that a read or a loop
// binds in the body has no value the walk can follow after it.
func simpleJoinForgottenUserVars(merged, body []simpleShellState) []simpleShellState {
	var forgotten []string
	for _, name := range simpleUserNames {
		if slices.ContainsFunc(body, func(state simpleShellState) bool {
			_, has := state.vars[name]
			return !has
		}) {
			forgotten = append(forgotten, name)
		}
	}
	if len(forgotten) == 0 {
		return merged
	}
	for index := range merged {
		merged[index] = merged[index].clone()
		simpleForgetUserVars(merged[index].vars, forgotten)
	}
	return merged
}

// simpleRedirectDefaultExpansion reports a ${NAME:-word} or ${NAME-word} word
// in a redirect target of stmt. A lone statement is read on its own only when
// a word of it changes with the values the walk holds; a default is read from
// the static word when the walk holds no value for NAME
// (simpleStaticWordWithNewline).
func simpleRedirectDefaultExpansion(stmt *syntax.Stmt) bool {
	for _, redirect := range stmt.Redirs {
		if redirect.Word != nil && simpleDefaultExpansion(redirect.Word) {
			return true
		}
	}
	return false
}

// simpleDefaultExpansion reports a ${NAME:-word} or ${NAME-word} in node.
func simpleDefaultExpansion(node syntax.Node) bool {
	found := false
	syntax.Walk(node, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok && param.Param != nil && param.Exp != nil &&
			(param.Exp.Op == syntax.DefaultUnset || param.Exp.Op == syntax.DefaultUnsetOrNull) &&
			simpleVariableName(param.Param.Value) {
			found = true
		}
		return !found
	})
	return found
}

func simpleVariableName(name string) bool {
	if name == "" {
		return false
	}
	for index, char := range name {
		if char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
			index > 0 && char >= '0' && char <= '9' {
			continue
		}
		return false
	}
	return true
}

func simpleUnresolvedBoundVariable(source string, vars map[string]string, bound map[string]bool) bool {
	if len(bound) == 0 || !strings.ContainsRune(source, '$') {
		return false
	}
	file, ok := shellparse.Parse(source)
	if !ok {
		return false
	}
	unresolved := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok && param.Param != nil &&
			bound[param.Param.Value] {
			if _, known := vars[param.Param.Value]; !known {
				unresolved = true
				return false
			}
		}
		return !unresolved
	})
	return unresolved
}

// simpleUnboundUser reports a USER or LOGNAME parameter of source that the
// action binds and vars carries no value for.
func simpleUnboundUser(source string, vars map[string]string, bound map[string]bool) bool {
	if !strings.ContainsRune(source, '$') || !bound["USER"] && !bound["LOGNAME"] {
		return false
	}
	file, ok := shellparse.Parse(source)
	if !ok {
		return false
	}
	unbound := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok && param.Param != nil &&
			slices.Contains(simpleUserNames, param.Param.Value) && bound[param.Param.Value] {
			if _, known := vars[param.Param.Value]; !known {
				unbound = true
			}
		}
		return !unbound
	})
	return unbound
}

func simpleStaticWord(word *syntax.Word, vars map[string]string) (string, bool) {
	return simpleStaticWordWithNewline(word, vars, false)
}

// '[' is a literal test builtin. The ordinary word resolver rejects its
// unmatched glob opener, but it cannot change the shell's directory.
func simpleStaticProgramWord(word *syntax.Word, vars map[string]string) (string, bool) {
	if word != nil && word.Lit() == "[" {
		return "[", true
	}
	return simpleStaticWord(word, vars)
}

func simpleZshHistoryCall(call *syntax.CallExpr, vars map[string]string, interpreter string) bool {
	if interpreter != "zsh" || call == nil || len(call.Args) == 0 {
		return false
	}
	program, known := simpleStaticProgramWord(call.Args[0], vars)
	return known && program == "history"
}

// A quoted -c or trap action can contain physical lines. Other shell words
// still require one line so they cannot silently become a different command.
func simpleStaticScriptWord(word *syntax.Word, vars map[string]string) (string, bool) {
	return simpleStaticWordWithNewline(word, vars, true)
}

func simpleStaticWordWithNewline(word *syntax.Word, vars map[string]string, allowNewline bool) (string, bool) {
	if word == nil {
		return "", false
	}
	if len(word.Parts) == 1 {
		// A word of one literal made of plain characters is its own value; the
		// expansion below would only return it.
		if lit, ok := word.Parts[0].(*syntax.Lit); ok && simplePlainLiteral(lit.Value) {
			return lit.Value, true
		}
	}
	safe := true
	syntax.Walk(word, func(node syntax.Node) bool {
		switch part := node.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				safe = false
			}
		case *syntax.ParamExp:
			if part.Param == nil {
				safe = false
				return false
			}
			_, known := vars[part.Param.Value]
			// ${NAME:-word} and ${NAME-word} read NAME, or the static word
			// when the walk holds no value for NAME (unset in the walk): the
			// default of an unset name is what the shell expands.
			defaulted := part.Exp != nil && simpleVariableName(part.Param.Value) &&
				(part.Exp.Op == syntax.DefaultUnset || part.Exp.Op == syntax.DefaultUnsetOrNull)
			if !known && !defaulted || part.Excl || part.Length || part.Width || part.IsSet || part.Index != nil ||
				part.Slice != nil || part.Repl != nil || part.Names != 0 || part.Exp != nil && !defaulted ||
				part.Flags != nil || part.NestedParam != nil || len(part.Modifiers) != 0 {
				safe = false
			}
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ExtGlob, *syntax.BraceExp:
			safe = false
		}
		return safe
	})
	if !safe {
		return "", false
	}
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	slices.Sort(names)
	env := make([]string, 0, len(names))
	for _, name := range names {
		env = append(env, name+"="+vars[name])
	}
	if shellparse.MinBraceFields(word) > 1 {
		return "", false
	}
	fields, err := shellparse.Fields(&expand.Config{Env: expand.ListEnviron(env...)}, word)
	if err != nil || len(fields) != 1 || strings.ContainsRune(fields[0], 0) ||
		!allowNewline && strings.ContainsAny(fields[0], "\r\n") {
		return "", false
	}
	return fields[0], true
}

// simplePlainLiteral reports text of letters, digits and . / _ : @ % + , = -
// only: no quote, escape, expansion, glob, brace or tilde, so the shell
// reads it as it is.
func simplePlainLiteral(text string) bool {
	if text == "" {
		return false
	}
	for index := 0; index < len(text); index++ {
		char := text[index]
		letter := char >= 0x41 && char <= 0x5a || char >= 0x61 && char <= 0x7a
		digit := char >= 0x30 && char <= 0x39
		if !letter && !digit && strings.IndexByte("._/:@%+,=-", char) < 0 {
			return false
		}
	}
	return true
}

func simpleResolvedVariables(source string, vars map[string]string) (string, bool) {
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return "", false
	}
	type replacement struct {
		start, end int
		text       string
	}
	var replacements []replacement
	redirectTargets := map[*syntax.Word]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok {
			if redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc {
				return false
			}
			redirectTargets[redirect.Word] = true
			return true
		}
		word, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		// A default in an operand word stays a runtime-expanded word, as it
		// was: only the target of a redirect is read through the default,
		// which is where the hook client lists the file it names. A name the
		// walk holds a value for through an earlier binding is read as that.
		if !redirectTargets[word] && simpleDefaultExpansion(word) {
			return false
		}
		hasParam := false
		hasTilde := false
		if len(word.Parts) != 0 {
			if lit, ok := word.Parts[0].(*syntax.Lit); ok {
				hasTilde = lit.Value == "~" || strings.HasPrefix(lit.Value, "~/")
			}
		}
		syntax.Walk(word, func(part syntax.Node) bool {
			if _, ok := part.(*syntax.ParamExp); ok {
				hasParam = true
			}
			return true
		})
		if !hasParam && !hasTilde {
			return false
		}
		value, known := simpleStaticWord(word, vars)
		if !known {
			return false
		}
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start >= 0 && end > start && end <= len(source) {
			replacements = append(replacements, replacement{start, end,
				"'" + strings.ReplaceAll(value, "'", "'\\''") + "'"})
		}
		return false
	})
	if len(replacements) == 0 {
		return "", false
	}
	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		source = source[:r.start] + r.text + source[r.end:]
	}
	return source, true
}

// simpleResolvedDirectoryStackTildes writes the bash directory-stack
// tildes of source (~+, ~-, ~N, ~+N and ~-N at a word start, alone or
// before a slash) as the directories they name in state: ~+ is PWD, ~- is
// OLDPWD and ~N / ~+N / ~-N index the dirs list (the current directory,
// then the pushed directories, last pushed first). After pushd ~/.ssh;
// pushd /tmp the word ~1 is ~/.ssh, and grep -r . ~1 read the keys while
// the reading saw a literal ~1 (GAP-2480). A tilde whose directory is not
// known, or whose index is outside the list (bash keeps it literal), is
// left as written. The tilde-prefix of another account (~bob, ~root) is
// written as that account's home when the home of the active account tells
// where homes sit (simpleOtherAccountHome); one it cannot place stays as
// written, an operand the call does not resolve (rel-1-0-10:GAP-0837).
func simpleResolvedDirectoryStackTildes(source string, state *simpleShellState, activeHome string) (string, bool) {
	if !strings.Contains(source, "~") {
		return "", false
	}
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return "", false
	}
	directory := func(prefix string) (string, bool) {
		switch prefix {
		case "~+":
			dir, known := state.vars["PWD"]
			return dir, known && dir != ""
		case "~-":
			dir, known := state.vars["OLDPWD"]
			return dir, known && dir != ""
		}
		if other, ok := simpleOtherAccountHome(prefix[1:], activeHome); ok {
			return other, true
		}
		digits := strings.TrimLeft(prefix[1:], "+-")
		if digits == "" || len(digits) > 3 || strings.Trim(digits, "0123456789") != "" ||
			len(prefix)-1-len(digits) > 1 || state.cwd == "" || state.cwdUnknown {
			return "", false
		}
		index, err := strconv.Atoi(digits)
		if err != nil {
			return "", false
		}
		list := []string{state.cwd}
		for at := len(state.dirStack) - 1; at >= 0; at-- {
			list = append(list, state.dirStack[at])
		}
		if strings.HasPrefix(prefix, "~-") {
			index = len(list) - 1 - index
		}
		if index < 0 || index >= len(list) || list[index] == "" {
			return "", false
		}
		return list[index], true
	}
	type replacement struct {
		start, end int
		text       string
	}
	var replacements []replacement
	syntax.Walk(file, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok &&
			(redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc) {
			return false
		}
		word, ok := node.(*syntax.Word)
		if !ok || len(word.Parts) == 0 {
			return true
		}
		lit, ok := word.Parts[0].(*syntax.Lit)
		if !ok || !strings.HasPrefix(lit.Value, "~") || len(lit.Value) < 2 {
			return false
		}
		prefix, _, slash := strings.Cut(lit.Value, "/")
		if !slash && len(word.Parts) > 1 {
			// A quoted part inside the tilde-prefix stops the expansion.
			return false
		}
		dir, known := directory(prefix)
		if !known {
			return false
		}
		start := int(word.Pos().Offset())
		end := start + len(prefix)
		if start >= 0 && end <= len(source) && source[start:end] == prefix {
			replacements = append(replacements, replacement{start, end,
				"'" + strings.ReplaceAll(dir, "'", "'\\''") + "'"})
		}
		return false
	})
	if len(replacements) == 0 {
		return "", false
	}
	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		source = source[:r.start] + r.text + source[r.end:]
	}
	return source, true
}

// simpleResolvedCurrentFolderHeads writes the current-folder head of a word
// ($PWD, ${PWD}, "$PWD", $(pwd), `pwd` and ~+ before a slash, alone or in
// double quotes) as the folder the walk is in. After a cd the walk cannot
// follow (cd "$X", cd "$(mktemp -d)": cwdUnknown, PWD dropped) the head is
// the current folder itself, so the word is the relative operand it spells
// there and takes the path of its plain spelling: $PWD/.ssh/id_rsa is
// .ssh/id_rsa, where the head kept its $ or ~ and the operand named nothing
// (rel-1-0-10:GAP-1023). The head and its slash go; it stays as "." where
// the rest alone would be another word: the program word (a bare name is
// looked up in PATH), or a rest that starts with -, ~, / or a quote. In a folder the walk knows, $(pwd) and
// `pwd` are that folder, as $PWD and ~+ already are there
// (simpleResolvedVariables, simpleResolvedDirectoryStackTildes,
// rel-1-0-10:GAP-1024); held reports such a written folder. The value of an
// assignment is left as written: the variable keeps the folder the shell
// gave it, which a later cd does not move. Only an assignment made while the
// folder is unknown is read with its heads written
// (simpleUnknownFolderAssignment), and the next cd forgets it.
func simpleResolvedCurrentFolderHeads(source string, state *simpleShellState) (resolved string, ok, held bool) {
	return simpleResolvedCurrentFolderHeadsIn(source, state, false)
}

// simpleResolvedCurrentFolderHeadsIn is simpleResolvedCurrentFolderHeads;
// assignments also writes the heads in the value of an assignment.
func simpleResolvedCurrentFolderHeadsIn(source string, state *simpleShellState, assignments bool) (resolved string, ok, held bool) {
	if !strings.Contains(source, "PWD") && !strings.Contains(source, "pwd") && !strings.Contains(source, "~+") {
		return "", false, false
	}
	unresolved := state.cwdUnknown
	folder := ""
	if !unresolved && strings.HasPrefix(state.cwd, "/") {
		folder = simplePathClean(state.cwd)
	}
	if !unresolved && folder == "" {
		return "", false, false
	}
	// A PWD the walk holds was written by simpleResolvedVariables already.
	_, pwdHeld := state.vars["PWD"]
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return "", false, false
	}
	type replacement struct {
		start, end int
		text       string
	}
	var replacements []replacement
	// programs are the program words: a head there stays "./".
	programs := map[*syntax.Word]bool{}
	add := func(word *syntax.Word, start, end int, text string) {
		if start < 0 || end <= start || end > len(source) {
			return
		}
		if text == "." && !programs[word] && end+1 < len(source) && source[end] == '/' &&
			simpleBareOperandStart(source[end+1]) {
			// The plain spelling: the head and its slash go.
			text, end = "", end+1
		}
		replacements = append(replacements, replacement{start, end, text})
	}
	addNode := func(word *syntax.Word, node syntax.Node, text string) {
		add(word, int(node.Pos().Offset()), int(node.End().Offset()), text)
	}
	// head is the text of a current-folder part: "." where the folder is
	// not known, else the folder, quoted for where the part sits.
	head := func(part syntax.WordPart, quoted bool) (string, bool) {
		switch node := part.(type) {
		case *syntax.ParamExp:
			if !unresolved || pwdHeld || !simplePlainParameter(node, "PWD") {
				return "", false
			}
		case *syntax.CmdSubst:
			if !simplePwdSubstitution(node) {
				return "", false
			}
		default:
			return "", false
		}
		switch {
		case unresolved:
			return ".", true
		case quoted:
			return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`").Replace(folder), true
		default:
			return "'" + strings.ReplaceAll(folder, "'", "'\\''") + "'", true
		}
	}
	slashAt := func(parts []syntax.WordPart, index int) bool {
		if index >= len(parts) {
			return false
		}
		lit, ok := parts[index].(*syntax.Lit)
		return ok && strings.HasPrefix(lit.Value, "/")
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Redirect:
			return node.Op != syntax.Hdoc && node.Op != syntax.DashHdoc
		case *syntax.Assign:
			return assignments
		case *syntax.CallExpr:
			if len(node.Args) != 0 {
				programs[node.Args[0]] = true
			}
		case *syntax.Word:
			if len(node.Parts) == 0 {
				return true
			}
			switch first := node.Parts[0].(type) {
			case *syntax.Lit:
				if unresolved && !pwdHeld && strings.HasPrefix(first.Value, "~+/") {
					start := int(first.Pos().Offset())
					if start >= 0 && start+2 <= len(source) && source[start:start+2] == "~+" {
						add(node, start, start+2, ".")
					}
					return false
				}
			case *syntax.DblQuoted:
				if first.Dollar || len(first.Parts) == 0 {
					break
				}
				if len(first.Parts) == 1 && slashAt(node.Parts, 1) {
					// "$PWD"/x: the quoted head is the whole quote.
					if text, ok := head(first.Parts[0], false); ok {
						addNode(node, first, text)
						return false
					}
				} else if slashAt(first.Parts, 1) {
					// "$PWD/x": the head sits inside the quotes.
					if text, ok := head(first.Parts[0], true); ok {
						addNode(node, first.Parts[0], text)
						return false
					}
				}
			default:
				if slashAt(node.Parts, 1) {
					if text, ok := head(first, false); ok {
						addNode(node, first, text)
						return false
					}
				}
			}
		}
		return true
	})
	if len(replacements) == 0 {
		return "", false, false
	}
	slices.SortFunc(replacements, func(a, b replacement) int { return a.start - b.start })
	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		source = source[:r.start] + r.text + source[r.end:]
	}
	return source, true, !unresolved
}

// CurrentFolderHeadsAsRelative is command with each current-folder head
// ($PWD/, ${PWD}/, "$PWD"/, $(pwd)/, `pwd`/, ~+/) written as the current
// folder itself, as the walk writes it after a cd it cannot follow
// (simpleResolvedCurrentFolderHeads): the operand alone. A gateway reads it
// for a call with no folder from the agent at all, whose current folder is
// as unknown (rel-1-0-10:GAP-1023). ok is false when command has no head.
func CurrentFolderHeadsAsRelative(command string) (string, bool) {
	state := simpleShellState{cwdUnknown: true, vars: map[string]string{}}
	resolved, ok, _ := simpleResolvedCurrentFolderHeads(command, &state)
	return resolved, ok
}

// simpleUnknownFolderAssignment re-reads an assignment statement (X=v,
// export X=v, declare X=v) made while the folder is unknown, with each
// current-folder head of an assigned value written as that folder itself:
// X=$PWD/.ssh/id_rsa after cd "$D" gives X the value .ssh/id_rsa in the
// unknown folder, as X=.ssh/id_rsa does, where the head left X unread and
// cat "$X" named nothing (rel-1-0-10:GAP-1042). names are the variables
// whose value had such a head. ok is false when no value has one.
func simpleUnknownFolderAssignment(text string, state *simpleShellState) (stmt *syntax.Stmt, names []string, ok bool) {
	if !state.cwdUnknown {
		return nil, nil, false
	}
	resolved, changed, _ := simpleResolvedCurrentFolderHeadsIn(text, state, true)
	if !changed || resolved == text {
		return nil, nil, false
	}
	before, parsedBefore := shellparse.Parse(text)
	after, parsedAfter := shellparse.Parse(resolved)
	if !parsedBefore || !parsedAfter || len(before.Stmts) != 1 || len(after.Stmts) != 1 {
		return nil, nil, false
	}
	var assigns []*syntax.Assign
	switch command := before.Stmts[0].Cmd.(type) {
	case *syntax.CallExpr:
		assigns = command.Assigns
	case *syntax.DeclClause:
		assigns = command.Args
	}
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil || assign.Value == nil {
			continue
		}
		start, end := int(assign.Value.Pos().Offset()), int(assign.Value.End().Offset())
		if start < 0 || end > len(text) || start >= end {
			continue
		}
		if value := text[start:end]; strings.Contains(value, "PWD") || strings.Contains(value, "pwd") || strings.Contains(value, "~+") {
			names = append(names, assign.Name.Value)
		}
	}
	return after.Stmts[0], names, len(names) != 0
}

// simpleUnknownFolderNestedCall is the call that starts a nested shell
// (source) as the walk reads its body while the folder is unknown: the
// caller expands a current-folder head in a double-quoted body (bash -c
// "cat $PWD/f") to that unknown folder, so the head is the folder itself (.)
// and the body is static: cat ./f, a relative operand the body's walk reads
// in the unknown folder (Input.folderUnknown), where the head left the body
// unread (rel-1-0-10:GAP-1042). $(pwd) and `pwd` print PWD. A body with a cd
// of its own is left as it was: there the expanded folder is no longer the
// current one. The walk reads a body so only where it would be unread, and
// keeps that unread reading beside it: a rule that judges the whole call
// (a fetched file run as ./p) reads $PWD/p as no file it fetched.
func simpleUnknownFolderNestedCall(source string, call *syntax.CallExpr, vars map[string]string) (*syntax.CallExpr, map[string]string) {
	if _, held := vars["PWD"]; held || !strings.Contains(source, "PWD") && !strings.Contains(source, "pwd") ||
		strings.Contains(source, "cd ") || strings.Contains(source, "pushd") || strings.Contains(source, "popd") {
		return call, vars
	}
	if strings.Contains(source, "$(pwd)") || strings.Contains(source, "`pwd`") {
		file, parsed := shellparse.Parse(strings.NewReplacer("$(pwd)", "$PWD", "`pwd`", "$PWD").Replace(source))
		if !parsed || len(file.Stmts) != 1 {
			return call, vars
		}
		rewritten, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
		if !ok {
			return call, vars
		}
		call = rewritten
	}
	folder := make(map[string]string, len(vars)+1)
	for name, value := range vars {
		folder[name] = value
	}
	folder["PWD"] = "."
	return call, folder
}

// simpleAssignNames are the names assigns give a value.
func simpleAssignNames(assigns []*syntax.Assign) []string {
	var names []string
	for _, assign := range assigns {
		if assign != nil && assign.Name != nil {
			names = append(names, assign.Name.Value)
		}
	}
	return names
}

// setFolderVars records an assignment of assigned: a name it gave a value
// relative to the unknown folder (folder) is a folder variable, any other
// name it assigned is no longer one.
func (s *simpleShellState) setFolderVars(assigned, folder []string) {
	s.folderVars = slices.DeleteFunc(s.folderVars, func(name string) bool { return slices.Contains(assigned, name) })
	for _, name := range folder {
		if !slices.Contains(s.folderVars, name) {
			s.folderVars = append(s.folderVars, name)
		}
	}
	if len(s.folderVars) == 0 {
		s.folderVars = nil
	}
}

// simpleBareOperandStart reports a first character after which a word reads
// the same with or without a leading ./: a letter, a digit, . _ or a
// pattern character. A -, ~, / or quote there would make another word.
func simpleBareOperandStart(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' ||
		strings.IndexByte("._*?[", char) >= 0
}

// simplePlainParameter reports $name or ${name} with no operator, index or
// flag: the value of name as it is.
func simplePlainParameter(param *syntax.ParamExp, name string) bool {
	return param.Param != nil && param.Param.Value == name && !param.Excl && !param.Length && !param.Width &&
		!param.IsSet && param.Index == nil && param.Slice == nil && param.Repl == nil && param.Names == 0 &&
		param.Exp == nil && param.Flags == nil && param.NestedParam == nil && len(param.Modifiers) == 0
}

// simplePwdSubstitution reports $(pwd) or `pwd`: a substitution of the pwd
// program alone, which prints the current folder.
func simplePwdSubstitution(subst *syntax.CmdSubst) bool {
	if subst.TempFile || subst.ReplyVar || len(subst.Stmts) != 1 {
		return false
	}
	stmt := subst.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	return ok && !stmt.Negated && !stmt.Background && !stmt.Coprocess && !stmt.Disown && len(stmt.Redirs) == 0 &&
		len(call.Assigns) == 0 && len(call.Args) == 1 && call.Args[0].Lit() == "pwd"
}

// simpleOtherAccountHome is the home that the tilde-prefix ~name names, for an
// account other than the active one, found by the position of the active home:
// homes sit side by side below /home, /Users or <drive>:/Users, so another
// account's home is the folder of that name beside the active home. ~root is
// /root where homes sit below /home (and the other accounts of a root agent are
// the folders of /home). The name of the active account is
// left to ActiveUserTildeTwin, which also reads the logins of the OS identity.
// A home that does not sit in such a folder tells nothing, and the prefix stays
// unresolved. The directory-stack forms (~N, ~+N, ~-N, ~+, ~-) are never an
// account name: bash takes them from the dirs list, PWD and OLDPWD
// (directoryStackTildeName, rel-1-0-10:GAP-0887). macOS keeps root's home in
// /var/root, not beside the others in /Users.
func simpleOtherAccountHome(name, activeHome string) (string, bool) {
	home := strings.TrimRight(activeHome, "/")
	if home == "" || directoryStackTildeName(name) || !activeUserTildeName.MatchString(name) ||
		strings.EqualFold(name, path.Base(home)) {
		return "", false
	}
	parent := path.Dir(home)
	if strings.EqualFold(home, "/root") {
		// root's home sits outside the folder that holds the others.
		parent = "/home"
	}
	switch lower := strings.ToLower(parent); {
	case lower == "/home":
		if name == "root" {
			return "/root", true
		}
	case lower == "/users":
		if name == "root" {
			return "/var/root", true
		}
	case len(parent) >= 3 && parent[1] == ':' && lower[2:] == "/users":
	default:
		return "", false
	}
	return parent + "/" + name, true
}

// directoryStackTildeName reports whether name, the text after the ~ of a
// tilde-prefix, is a bash directory-stack form: empty, + or - (HOME, PWD,
// OLDPWD), or N, +N or -N with N all digits (an entry of the dirs list).
// bash expands these before it consults the password database, so after
// pushd ~/.ssh the word ~1 is a folder of the active home, never the home of
// an account named 1 (rel-1-0-10:GAP-0887).
func directoryStackTildeName(name string) bool {
	switch name {
	case "", "+", "-":
		return true
	}
	if name[0] == '+' || name[0] == '-' {
		name = name[1:]
	}
	return name != "" && strings.Trim(name, "0123456789") == ""
}

// simpleNestedChildFolder follows the same static wrapper child indexes as
// simpleNestedScript. A changed root or working directory belongs to the
// child, not to the caller's later statements.
func simpleNestedChildFolder(args []*syntax.Word, vars map[string]string, cwd string) (folder string, changed, unknown bool) {
	words := make([]string, len(args))
	static := make([]bool, len(args))
	for i, arg := range args {
		words[i], static[i] = simpleStaticScriptWord(arg, vars)
	}
	folder = cwd
	for depth := 0; depth < 8 && len(words) > 0 && static[0]; depth++ {
		var child int
		switch commandProgram(words[0]) {
		case "chroot":
			parsed := parseChrootInvocation(words)
			if !parsed.complete || parsed.childIndex <= 0 || !static[parsed.childIndex] {
				return "", true, true
			}
			child = parsed.childIndex
			if !slices.Contains(words[1:child], "--skip-chdir") {
				// A chroot root is a POSIX path: read with the rules of the
				// cd walk, not the native ones of the gateway host
				// (rel-1-0-10:GAP-1881).
				if simplePathAbs(parsed.root) {
					folder = simplePathClean(parsed.root)
				} else if folder != "" {
					folder = simplePathJoin(folder, parsed.root)
				} else {
					return "", true, true
				}
				changed = true
			}
		case "nsenter":
			parsed := parseNSEnterInvocation(words)
			if !parsed.childKnown {
				return "", true, true
			}
			child = parsed.childIndex
			if parsed.folderUnknown {
				return "", true, true
			}
			if parsed.workDir != "" {
				folder, changed = simplePathClean(parsed.workDir), true
			}
		default:
			child = WrapperChildIndex(words, static)
		}
		if child <= 0 || child >= len(words) {
			break
		}
		words, static = words[child:], static[child:]
	}
	return folder, changed, false
}

// simpleNestedScript returns a static shell -c or eval body. eval shares the
// caller's variables and directory; a -c shell starts a child shell.
func simpleNestedScript(call *syntax.CallExpr, vars map[string]string, cwdUnknown *bool, interpreter *string) (script string, shared, nested, static bool) {
	if call == nil || len(call.Args) == 0 {
		return "", false, false, false
	}
	return simpleNestedScriptArgs(call.Args, vars, 0, cwdUnknown, interpreter)
}

func simpleNestedScriptArgs(args []*syntax.Word, vars map[string]string, depth int, cwdUnknown *bool, interpreter *string) (script string, shared, nested, static bool) {
	return simpleNestedScriptRun(args, vars, depth, 0, cwdUnknown, interpreter, nil)
}

// simpleNestedScriptRun is simpleNestedScriptArgs after neutral
// context-neutral wrappers (posixContextNeutralWrappers: nice, time, timeout,
// nohup). Such a wrapper only runs the next program, so it spends no nesting
// depth, as in the action analysis (staticPOSIXWrapperDepthCost): a run of up
// to InlineChainWrappers of them is read to the program it runs, whose call
// is then judged alone as it would be without them (rel-1-0-10:GAP-1207,
// substrate-1:GAP-0478). One more is not read (nested, not static): the call
// is judged whole, where the chain is past the wrapper bound (TRUNCATED,
// PrefixWrapperRun.PastWrapperBound). A programWord that is not nil is set
// to the last word of args the chain of wrappers reached, the program they
// run when it is no wrapper itself (simpleNeutralWrapperFreeReading): the
// wrapper a word made at run time among its own words stopped the chain at,
// whatever the program's own arguments are.
func simpleNestedScriptRun(args []*syntax.Word, vars map[string]string, depth, neutral int, cwdUnknown *bool, interpreter *string, programWord **syntax.Word) (script string, shared, nested, static bool) {
	if depth >= 8 || len(args) == 0 {
		return "", false, true, false
	}
	program, ok := simpleStaticWord(args[0], vars)
	if !ok {
		return "", false, false, false
	}
	if program == "eval" {
		words := make([]string, 0, len(args)-1)
		for _, arg := range args[1:] {
			value, known := simpleStaticScriptWord(arg, vars)
			if !known {
				// The command substitution itself is exposed by the outer
				// statement walk. Runtime eval text has no static child to
				// compare with a standalone command.
				return "", true, false, false
			}
			words = append(words, value)
		}
		if len(words) == 0 {
			return "", true, false, false
		}
		return strings.Join(words, " "), true, true, true
	}
	if program == "trap" {
		// The handler executes later, after intervening commands may cd.
		if cwdUnknown != nil {
			*cwdUnknown = true
		}
		index := 1
		if index < len(args) && args[index].Lit() == "--" {
			index++
		}
		if index >= len(args) || args[index].Lit() == "-p" {
			return "", true, false, false
		}
		value, known := simpleStaticScriptWord(args[index], vars)
		return value, true, true, known
	}
	if program == "su" && simplePotentialShellScript(args, vars) {
		// The target account can change both startup files and directory.
		return "", false, true, false
	}
	wrapper := filepath.Base(program)
	if simpleNestedWrapper(wrapper) {
		// A word the walk cannot resolve in the wrapper's own words or in
		// the program word it runs leaves the call unread (a possible
		// shell -c body). One among the program's arguments does not: the
		// wrapper is read to that program, whose own reading judges the
		// word (a shell -c body, GAP-0535), as without the wrapper, so
		// time env GOOS=x go test -c -o "$d/x" is not a possible shell body.
		argv := make([]string, len(args))
		unknown := -1
		for index, arg := range args {
			value, known := simpleStaticScriptWord(arg, vars)
			if !known && unknown < 0 {
				unknown = index
			}
			argv[index] = value
		}
		unread := func() (string, bool, bool, bool) {
			if simplePotentialShellScript(args, vars) {
				return "", false, true, false
			}
			return "", false, false, false
		}
		if unknown == 0 {
			return unread()
		}
		var childIndex int
		switch wrapper {
		case "nohup":
			childIndex = 1
			if len(argv) > 1 && argv[1] == "--" {
				childIndex++
			}
		case "timeout":
			childIndex = simpleTimeoutChildIndex(argv)
		case "nice":
			childIndex = simpleNiceChildIndex(argv)
		case "env":
			if unknown < 0 {
				if split, ok := simpleEnvSplitString(argv); ok {
					return split, false, true, true
				}
			}
			childIndex = simpleEnvChildIndex(argv)
		default:
			static := make([]bool, len(argv))
			for index := range static {
				static[index] = true
			}
			if childIndex = simpleWrapperChildIndex(argv, static); childIndex > 0 {
				break
			}
			child, found, uncertain := staticPOSIXWrapperArgv(argv, wrapper)
			if uncertain {
				return unread()
			}
			if !found {
				if unknown >= 0 {
					return unread()
				}
				return "", false, false, false
			}
			childIndex = len(argv) - len(child)
		}
		if unknown >= 0 && (childIndex <= 0 || unknown <= childIndex) {
			return unread()
		}
		if childIndex <= 0 || childIndex >= len(args) {
			return "", false, true, false
		}
		if _, contextNeutral := posixContextNeutralWrappers[wrapper]; contextNeutral {
			if neutral++; neutral > InlineChainWrappers {
				return "", false, true, false
			}
		} else {
			depth++
		}
		if programWord != nil {
			// The word the chain has reached. chroot and nsenter run it in
			// another root, and a word made at run time among its arguments
			// is not read here (simpleWrappedProgram): no program word.
			// A word made at run time among the wrapper words stopped the
			// chain above (unread) at the wrapper it belongs to, so the
			// word set here is that wrapper; one among the program's own
			// arguments leaves the program static and read
			// (rel-1-0-10:GAP-1474).
			if wrapper == "chroot" || wrapper == "nsenter" {
				*programWord, programWord = nil, nil
			} else {
				*programWord = args[childIndex]
			}
		}
		if unknown < 0 {
			if program, ok := simpleWrappedProgram(wrapper, argv, childIndex, neutral > 0); ok {
				return program, false, true, true
			}
		}
		return simpleNestedScriptRun(args[childIndex:], vars, depth, neutral, cwdUnknown, interpreter, programWord)
	}
	// The other static program wrappers use the same child index as the
	// protected-target reader. Their child shell body gets the ordinary
	// nested-command checks, including a literal -c operand.
	argv := make([]string, len(args))
	fixedWords := make([]bool, len(args))
	for index, arg := range args {
		argv[index], fixedWords[index] = simpleStaticScriptWord(arg, vars)
	}
	if childIndex := WrapperChildIndex(argv, fixedWords); childIndex > 0 {
		return simpleNestedScriptArgs(args[childIndex:], vars, depth+1, cwdUnknown, interpreter)
	}
	shellProgram := filepath.Base(program)
	switch shellProgram {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash":
	default:
		return "", false, false, false
	}
	if simpleShellNoExec(args, vars, shellProgram) {
		// Syntax-check mode does not execute the -c body. Use the same
		// invocation grammar as Analyze so option order and +n are honored.
		return "", false, false, false
	}
	for index := 1; index < len(args); index++ {
		// The option is the word the shell sees, after quote removal and
		// escapes ('-c', "-c", $'-c', -'c', \-c read as -c), not its
		// spelling (rel-1-0-10:GAP-0535).
		option, known := simpleStaticWord(args[index], vars)
		if !known {
			if index+1 < len(args) {
				// A word the walk cannot resolve may be -c, with a body
				// after it: the call is not known.
				return "", false, true, false
			}
			return "", false, false, false
		}
		if option == "--" {
			continue
		}
		if option == "-o" || option == "+o" {
			index++
			if index >= len(args) {
				return "", false, true, false
			}
			name, known := simpleStaticWord(args[index], vars)
			if !known || name == "" {
				return "", false, true, false
			}
			continue
		}
		if !simpleShellSafeOption(option) {
			if simplePotentialShellScript(args, vars) {
				return "", false, true, false
			}
			return "", false, false, false
		}
		if cwdUnknown != nil && strings.ContainsAny(option[1:], "il") {
			// Login and interactive startup files may change directory
			// before the static -c body runs.
			*cwdUnknown = true
		}
		if simpleShellCOption(option) {
			if index+1 == len(args) {
				return "", false, true, false
			}
			value, known := simpleStaticScriptWord(args[index+1], vars)
			if known && interpreter != nil {
				*interpreter = shellProgram
			}
			return value, false, true, known
		}
	}
	return "", false, false, false
}

func simpleShellNoExec(args []*syntax.Word, vars map[string]string, program string) bool {
	argv := make([]string, len(args))
	for index, arg := range args {
		value, known := simpleStaticScriptWord(arg, vars)
		if !known {
			return false
		}
		argv[index] = value
	}
	return parsePOSIXShellInvocation(program, argv).noExec
}

// simpleWrapperChildIndex is the child WrapperChildIndex gives the nested
// script walk for a nested wrapper without a branch of its own (sudo, exec,
// command, chroot, nsenter), cut at the first nested wrapper of the chain
// (simpleNestedWrapper). WrapperChildIndex reads a whole chain of prefix
// wrappers at once, so for sudo nohup PROGRAM, sudo env NAME=value PROGRAM
// and nohup sudo env NAME=value PROGRAM it named PROGRAM, past the nohup or
// env whose own branch of simpleNestedScriptArgs turns PROGRAM into the
// reading the rules judge (simpleWrappedProgram). That reading was lost and
// the action was allowed (rel-1-0-10:GAP-1322). Stopping at that wrapper
// lets its branch read the rest of the chain, one wrapper at a time, as the
// walk did before; a chain of other prefix wrappers, and chroot, nsenter and
// xargs by their own grammars, keep the WrapperChildIndex child
// (rel-1-0-10:GAP-1182).
func simpleWrapperChildIndex(argv []string, static []bool) int {
	childIndex := WrapperChildIndex(argv, static)
	if childIndex <= 0 {
		return childIndex
	}
	value := func(at int) (string, bool) {
		if at < 0 || at >= len(argv) {
			return "", false
		}
		return argv[at], static[at]
	}
	var run PrefixWrapperRun
	for index := 0; index < childIndex; {
		name, ok := value(index)
		if !ok || name == "" {
			break
		}
		next, known := wrapperChildIndex(wrapperProgramName(name), value, len(argv), index, &run)
		if !known || next <= index || next >= childIndex {
			break
		}
		if wrapperChildProgram(argv, static, next) == next && simpleNestedWrapper(wrapperProgramName(argv[next])) {
			return next
		}
		index = next
	}
	return childIndex
}

// simpleNestedWrapper reports a program the walk reads as a wrapper of the
// program after it: every context-neutral wrapper (posixContextNeutralWrappers,
// the external time program included) and the wrappers that change the
// environment, the user or the root.
func simpleNestedWrapper(program string) bool {
	if _, contextNeutral := posixContextNeutralWrappers[program]; contextNeutral {
		return true
	}
	switch program {
	case "env", "sudo", "exec", "command", "nsenter", "chroot":
		return true
	default:
		return false
	}
}

// An env assignment changes the child's environment but leaves a following
// static shell -c body executable. Directory changes are accepted here only
// when they preserve the caller's directory; other forms stay whole-action
// only until the simple-command walker can carry their new CWD.
func simpleEnvChildIndex(argv []string) int {
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		switch {
		case arg == "--":
			if index+1 < len(argv) {
				return index + 1
			}
			return -1
		case arg == "-i" || arg == "--ignore-environment" ||
			arg == "-0" || arg == "--null" || arg == "-v" || arg == "--debug":
			continue
		case arg == "-u" || arg == "--unset":
			index++
			if index >= len(argv) {
				return -1
			}
		case strings.HasPrefix(arg, "--unset="):
			continue
		case arg == "--chdir=." || arg == "-C.":
			continue
		case arg == "--chdir" || arg == "-C":
			index++
			if index >= len(argv) || argv[index] != "." {
				return -1
			}
		case strings.HasPrefix(arg, "-"):
			return -1
		case isStaticEnvironmentAssignment(arg):
			continue
		default:
			return index
		}
	}
	return -1
}

// simpleEnvSplitString returns the command that env -S STRING (or
// --split-string) runs: STRING split into words, then the arguments after
// it. Analyze reads -S as uncertain, so a rule about that command never ran
// (GAP-1200). The STRING is read as shell words, which may find more
// commands than env would start (env does not split on ;), so the reading
// can only over-block.
func simpleEnvSplitString(argv []string) (string, bool) {
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		split, found := "", false
		switch {
		case arg == "-S" || arg == "--split-string":
			if index+1 >= len(argv) {
				return "", false
			}
			index++
			split, found = argv[index], true
		case strings.HasPrefix(arg, "--split-string="):
			split, found = strings.TrimPrefix(arg, "--split-string="), true
		case strings.HasPrefix(arg, "-S"):
			split, found = arg[2:], true
		case arg == "-i" || arg == "--ignore-environment" ||
			arg == "-0" || arg == "--null" || arg == "-v" || arg == "--debug" ||
			strings.HasPrefix(arg, "--unset="):
			continue
		case arg == "-u" || arg == "--unset":
			index++
			continue
		default:
			return "", false
		}
		if !found || strings.TrimSpace(split) == "" {
			return "", false
		}
		rest, ok := simpleQuotedArgv(argv[index+1:])
		if !ok {
			return "", false
		}
		if rest != "" {
			split += " " + rest
		}
		return split, true
	}
	return "", false
}

// simpleWrappedProgram returns the program call that a static wrapper runs
// when Analyze does not read it as a command of the action: env with a
// NAME=value (PATH may change which program runs) and every context-neutral
// wrapper (posixContextNeutralWrappers). A wrapper of that set only runs the
// next program, so the call keeps the verdict the program has alone: nice
// was missing, so nohup nice PROGRAM and nice PROGRAM were never judged as
// PROGRAM (rel-1-0-10:GAP-1207). A shell or another wrapper as the program
// is read as a nested script instead. The argv is static, so the call is judged as a simple command,
// where a match can only over-block (GAP-1200, #1189). env NAME=value prog
// is written as NAME=value prog, so the assignments are judged as the same
// prefix assignments are. afterNeutral is a chain with a context-neutral
// wrapper before this one: Analyze reads that call partially, so the program
// the chain ends in is judged here whatever runs it next (env, sudo, exec,
// command); nohup x64 env x4 PROGRAM was never judged as PROGRAM, a weaker
// verdict than the chain truncation of rel (rel-1-0-10:GAP-1207 review r1).
// chroot and nsenter run the program in another root, so it is not judged
// alone after them.
func simpleWrappedProgram(wrapper string, argv []string, childIndex int, afterNeutral bool) (string, bool) {
	if childIndex <= 0 || childIndex >= len(argv) {
		return "", false
	}
	var assignments []string
	if wrapper == "env" {
		for _, arg := range argv[1:childIndex] {
			name, value, found := strings.Cut(arg, "=")
			if !found || !simpleVariableName(name) {
				continue
			}
			quoted, err := syntax.Quote(value, syntax.LangBash)
			if err != nil {
				return "", false
			}
			assignments = append(assignments, name+"="+quoted)
		}
	}
	_, contextNeutral := posixContextNeutralWrappers[wrapper]
	switch {
	case contextNeutral, len(assignments) > 0:
	case afterNeutral && wrapper != "chroot" && wrapper != "nsenter":
	default:
		return "", false
	}
	program := filepath.Base(argv[childIndex])
	if simpleNestedWrapper(program) {
		return "", false
	}
	switch program {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash":
		return "", false
	}
	call, ok := simpleQuotedArgv(argv[childIndex:])
	if !ok {
		return "", false
	}
	return strings.Join(append(assignments, call), " "), true
}

// simpleNeutralWrapperFreeReading is the call as written with the wrapper
// words removed from each command that starts with a context-neutral
// wrapper (posixContextNeutralWrappers) the walk reads to the program it
// runs (simpleNestedScriptRun: a run of up to InlineChainWrappers of them,
// then env, sudo, exec or command; a shell too), so each such program is
// judged where it runs, in its pipeline and list. Analyze
// reads a call behind those wrappers only partially, and the walk judges a
// program alone only when the text may hold more than one command, and a
// pipeline only stage by stage: a rule on the program (PATH-AWS-CREDS for
// cat ~/.aws/credentials) or on its pipeline (CMD-PIPE-CURL for curl URL |
// sh) was not judged behind nohup. rel judged a chain of more than
// MaxWrapperDepth of them at the truncation floor (an alert in default, a
// block in strict); reading such a chain whole up to the chain bound
// (rel-1-0-10:GAP-1207) put it below the program alone, an allow in every
// tier (rel-1-0-10:GAP-1321, and GAP-1323 for one wrapper). The reading
// keeps every other word, so the program keeps the verdict it has alone,
// alert included; like every reading of the walk it only adds findings. A
// command with a prefix assignment, a redirect before the program word (among
// the wrapper words or before the first of them: >/dev/null nohup curl URL |
// sh still runs the script curl fetches, and rel kept the floor on it), a word
// made at run time among its wrapper words, chroot or nsenter in the chain,
// and a chain past the bound (TRUNCATED) are not read so; a word made at run
// time among the program's own arguments is kept as written
// (rel-1-0-10:GAP-1474).
//
// contextRead reports that the pipeline and list rules read the context of
// every command the reading cuts: false when one is in a pipeline or && / ||
// list with a compound command (a brace group, a subshell, if, while, for,
// case) among its stages, or when the call has a coproc. Analyze projects no
// pipeline across a compound stage, so curl and sh in { curl URL; } | sh or
// coproc curl URL | sh are bare calls that CMD-PIPE-CURL does not read as one
// pipeline (rel-1-0-10:GAP-1507); a pipeline inside a compound command is
// read. Such a reading still adds its findings.
func simpleNeutralWrapperFreeReading(input Input, source string) (reading SimpleCommand, contextRead, ok bool) {
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return SimpleCommand{}, false, false
	}
	home, _ := normalizeActiveHome(input.ActiveHome)
	vars := map[string]string{"HOME": home}
	type span struct{ start, end int }
	var cuts []span
	contextRead = true
	var stack []syntax.Node
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if _, coproc := node.(*syntax.CoprocClause); coproc {
			contextRead = false
		}
		stack = append(stack, node)
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 0 || len(call.Args) < 2 {
			return true
		}
		head, known := simpleStaticWord(call.Args[0], vars)
		if _, neutral := posixContextNeutralWrappers[filepath.Base(head)]; !known || !neutral {
			return true
		}
		var program *syntax.Word
		simpleNestedScriptRun(call.Args, vars, 0, 0, nil, nil, &program)
		if program == nil {
			return true
		}
		if name, known := simpleStaticWord(program, vars); !known || simpleNestedWrapper(filepath.Base(name)) {
			// The chain stopped at a wrapper: past the bound (TRUNCATED), or
			// a wrapper the walk does not read.
			return true
		}
		cut := span{int(call.Args[0].Pos().Offset()), int(program.Pos().Offset())}
		// A redirect anywhere before the program word, the first wrapper word
		// included, is refused: the cut would move it onto the program.
		if slices.ContainsFunc(stmt.Redirs, func(redirect *syntax.Redirect) bool {
			return int(redirect.Pos().Offset()) < cut.end
		}) {
			return true
		}
		cuts = append(cuts, cut)
		if simpleSplitContext(stack[:len(stack)-1]) {
			contextRead = false
		}
		return true
	})
	var text strings.Builder
	last := 0
	for _, cut := range cuts {
		if cut.start < last || cut.end <= cut.start || cut.end > len(source) {
			return SimpleCommand{}, false, false
		}
		text.WriteString(source[last:cut.start])
		last = cut.end
	}
	if last == 0 {
		return SimpleCommand{}, false, false
	}
	text.WriteString(source[last:])
	if strings.TrimSpace(text.String()) == "" {
		return SimpleCommand{}, false, false
	}
	return SimpleCommand{Text: text.String(), CWD: input.CWD}, contextRead, true
}

// simpleSplitContext reports that the ancestors of a statement put it in a
// pipeline or && / || list with a compound command among its operands
// (simpleNeutralWrapperFreeReading).
func simpleSplitContext(ancestors []syntax.Node) bool {
	return slices.ContainsFunc(ancestors, func(node syntax.Node) bool {
		binary, ok := node.(*syntax.BinaryCmd)
		return ok && simpleBinaryHasCompound(binary)
	})
}

// simpleBinaryHasCompound reports a compound command among the operands of a
// pipeline or list, nested ones included.
func simpleBinaryHasCompound(binary *syntax.BinaryCmd) bool {
	for _, operand := range []*syntax.Stmt{binary.X, binary.Y} {
		if operand == nil || operand.Cmd == nil {
			continue
		}
		switch typed := operand.Cmd.(type) {
		case *syntax.CallExpr:
		case *syntax.BinaryCmd:
			if simpleBinaryHasCompound(typed) {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// WrapperFreeCalls is the top-level calls of the wrapper-free reading of a
// call (simpleNeutralWrapperFreeReading) as Analyze reads them.
type WrapperFreeCalls []CommandFact

// NeutralWrapperFreeCalls is the top-level calls of the wrapper-free reading
// SimpleCommands adds for input, the reading judged on its own: nil when the
// call has none, or when a top-level call of the reading still starts with a
// wrapper. Such a call is a chain the reading does not read (a prefix
// assignment, a redirect before its program word, a word made at run time
// among its wrapper words, chroot or nsenter in it, the time keyword before
// it): the program it runs is judged alone by no reader, and a rule on its
// pipeline or list (CMD-PIPE-CURL for curl URL | sh) is not judged either
// (rel-1-0-10:GAP-1474). nil too when the pipeline and list rules do not read
// the context of a call the reading cuts (a compound command among the stages
// of its pipeline or list, a coproc): the reading holds the program as a bare
// call there, but not its pipeline (rel-1-0-10:GAP-1507).
func NeutralWrapperFreeCalls(input Input, facts Facts) (calls WrapperFreeCalls) {
	defer func() {
		if recover() != nil {
			calls = nil
		}
	}()
	if facts.Parse.Dialect != DialectPOSIX || facts.Parse.Status != StatusPartial {
		return nil
	}
	source := input.Command
	if source == "" {
		_, capture := analyzeWithRedirectTargets(input, "")
		source = capture.source
	}
	if len(source) > maxCommandBytes {
		return nil
	}
	reading, contextRead, ok := simpleNeutralWrapperFreeReading(input, source)
	if !ok || !contextRead {
		return nil
	}
	readingInput := input
	readingInput.Command, readingInput.CWD = reading.Text, reading.CWD
	readingInput.Args, readingInput.Argv = nil, nil
	for _, command := range Analyze(readingInput).Commands {
		if command.ParentCommandID != 0 {
			continue
		}
		if len(command.Argv) > 0 && (len(command.Wrappers) > 0 || simpleNestedWrapper(commandProgram(command.Argv[0])) ||
			WrapperChildIndex(command.Argv, staticArgvWords(command)) >= 0) {
			return nil
		}
		calls = append(calls, command)
	}
	return calls
}

// Runs reports that calls hold program (the argv a chain of prefix wrappers
// runs, from the child word on) as a bare call, with every redirect of the
// chain: the program is judged where it runs, at the verdict it has alone.
func (calls WrapperFreeCalls) Runs(program []string, redirects []RedirectFact) bool {
	return slices.ContainsFunc(calls, func(call CommandFact) bool {
		return slices.Equal(call.Argv, program) && !slices.ContainsFunc(redirects, func(redirect RedirectFact) bool {
			return !slices.Contains(call.Redirects, redirect)
		})
	})
}

// staticArgvWords is the static mask of the argv of command: false for a word
// the shell makes at run time.
func staticArgvWords(command CommandFact) []bool {
	static := make([]bool, len(command.Argv))
	for i := range static {
		static[i] = len(command.Arguments) != len(command.Argv) || !command.Arguments[i].Expands
	}
	return static
}

// simpleQuotedArgv writes argv as one shell command line.
func simpleQuotedArgv(argv []string) (string, bool) {
	words := make([]string, 0, len(argv))
	for _, arg := range argv {
		quoted, err := syntax.Quote(arg, syntax.LangBash)
		if err != nil {
			return "", false
		}
		words = append(words, quoted)
	}
	return strings.Join(words, " "), true
}

// simpleRuntimeWords reports a word of args whose text the shell makes at run
// time: a parameter, command, arithmetic or process substitution, or a
// pattern outside quotes.
func simpleRuntimeWords(args []*syntax.Word) bool {
	runtime := false
	for _, arg := range args {
		for _, part := range arg.Parts {
			if lit, ok := part.(*syntax.Lit); ok && strings.ContainsAny(lit.Value, "*?[") {
				runtime = true
			}
		}
		syntax.Walk(arg, func(node syntax.Node) bool {
			switch node.(type) {
			case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst:
				runtime = true
			}
			return !runtime
		})
		if runtime {
			return true
		}
	}
	return false
}

// simplePotentialShellScript reports an argument that is a shell's -c
// option, alone or among combined short options, as the shell sees the word
// (quotes and escapes removed, rel-1-0-10:GAP-0535). A word the walk cannot
// resolve is judged where the shell itself reads its options
// (simpleNestedScriptArgs).
func simplePotentialShellScript(args []*syntax.Word, vars map[string]string) bool {
	shell := false
	for index, arg := range args {
		option, known := simpleStaticWord(arg, vars)
		if option == "-c" || len(option) > 2 && strings.HasPrefix(option, "-") && option[1] != '-' &&
			strings.ContainsRune(option[1:], 'c') {
			return true
		}
		if !known && shell && index+1 < len(args) {
			// A word after a shell program that the walk cannot resolve may
			// be its -c, with the body after it.
			return true
		}
		switch filepath.Base(option) {
		case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash":
			shell = shell || known
		}
	}
	return false
}

// simpleNiceChildIndex is the index of the command nice runs: after -n N,
// -N, --adjustment=N or --adjustment N, and an optional --; -1 for any other
// option.
func simpleNiceChildIndex(argv []string) int {
	index := 1
	for index < len(argv) && strings.HasPrefix(argv[index], "-") {
		arg := argv[index]
		switch {
		case arg == "--":
			return index + 1
		case arg == "-n" || arg == "--adjustment":
			index += 2
		case strings.HasPrefix(arg, "--adjustment=") ||
			strings.HasPrefix(arg, "-n") && strings.Trim(arg[2:], "0123456789") == "" ||
			len(arg) > 1 && strings.Trim(arg[1:], "0123456789") == "":
			index++
		default:
			return -1
		}
	}
	return index
}

func simpleTimeoutChildIndex(argv []string) int {
	index := 1
	for index < len(argv) && strings.HasPrefix(argv[index], "-") {
		if argv[index] == "--" {
			index++
			break
		}
		switch argv[index] {
		case "-s", "--signal", "-k", "--kill-after":
			index += 2
		case "--preserve-status", "--foreground":
			index++
		default:
			return -1
		}
	}
	if index >= len(argv) || !boundedTimeoutDuration(argv[index]) {
		return -1
	}
	return index + 1
}

func simpleShellCOption(option string) bool {
	return strings.Contains(option, "c") && simpleShellSafeOption(option)
}

func simpleShellSafeOption(option string) bool {
	if len(option) < 2 || len(option) > 5 || option[0] != '-' {
		return false
	}
	for _, flag := range option[1:] {
		// A login or interactive shell may run startup code too, but a
		// statically supplied -c body still runs and adds policy findings.
		if !strings.ContainsRune("cefiluvx", flag) {
			return false
		}
	}
	return true
}

// Once the directory is unknown, a relative path cannot be judged with the
// same facts as a standalone command in its actual directory.
func simpleRelativePathOperand(source string) bool {
	file, ok := shellparse.Parse(source)
	if !ok || len(file.Stmts) != 1 {
		return true
	}
	for _, redirect := range file.Stmts[0].Redirs {
		value, known := simpleStaticWord(redirect.Word, nil)
		if !known || !simplePathAbs(value) {
			return true
		}
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		// No program word, so no path operand: a redirect-only or assignment-only statement.
		return false
	}
	for _, arg := range call.Args[1:] {
		value, known := simpleStaticWord(arg, nil)
		if !known {
			return true
		}
		if value == "." || value == ".." || strings.HasPrefix(value, "./") ||
			strings.HasPrefix(value, "../") || strings.Contains(value, "/") &&
			!simplePathAbs(value) && !strings.Contains(value, "://") {
			return true
		}
	}
	// Reviewed command grammars also identify bare file operands such as
	// `cat id_rsa`, which have no slash to recognize lexically.
	facts := Analyze(Input{Tool: "shell", Command: source, DialectHint: DialectPOSIX})
	for _, operand := range facts.Paths {
		if operand.Flavor == PathFlavorPOSIX && !operand.Absolute {
			return true
		}
	}
	return false
}

func simpleCommandNextCWD(source string, state *simpleShellState, vars map[string]string) (string, bool) {
	file, parsed := shellparse.Parse(source)
	if !parsed || len(file.Stmts) != 1 {
		return state.cwd, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return state.cwd, false
	}
	program, known := simpleStaticProgramWord(call.Args[0], vars)
	if !known {
		return state.cwd, false
	}
	argStart := 1
	if program == "builtin" || program == "command" {
		if program == "command" && argStart < len(call.Args) && call.Args[argStart].Lit() == "-p" {
			argStart++
		}
		if argStart < len(call.Args) && call.Args[argStart].Lit() == "--" {
			argStart++
		}
		if argStart >= len(call.Args) {
			return state.cwd, false
		}
		// command [ ... ] runs the test builtin, as [ ... ] does
		// (substrate-1:GAP-0692).
		program, known = simpleStaticProgramWord(call.Args[argStart], vars)
		if !known {
			return "", true
		}
		argStart++
	}
	if program == "popd" {
		if len(call.Args) != argStart || len(state.dirStack) == 0 {
			return "", true
		}
		dir := state.dirStack[len(state.dirStack)-1]
		state.dirStack = state.dirStack[:len(state.dirStack)-1]
		return dir, true
	}
	if program != "cd" && program != "pushd" {
		return state.cwd, false
	}
	arg := argStart
	if program == "cd" {
		for arg < len(call.Args) {
			option := call.Args[arg].Lit()
			if option == "--" {
				arg++
				break
			}
			if len(option) < 2 || option[0] != '-' || option == "-" {
				break
			}
			for _, flag := range option[1:] {
				if !strings.ContainsRune("eLP", flag) {
					return "", true
				}
			}
			arg++
		}
	} else if arg < len(call.Args) && call.Args[arg].Lit() == "--" {
		arg++
	}
	if arg == len(call.Args) {
		if program == "pushd" {
			if len(state.dirStack) == 0 {
				return "", true
			}
			dir := state.dirStack[len(state.dirStack)-1]
			state.dirStack[len(state.dirStack)-1] = state.cwd
			return dir, true
		}
		return vars["HOME"], true
	}
	if arg+1 != len(call.Args) {
		return "", true
	}
	dir, known := simpleStaticWord(call.Args[arg], vars)
	if !known || dir == "" {
		return "", true
	}
	if dir == "-" {
		return vars["OLDPWD"], true
	}
	if program == "pushd" {
		state.dirStack = append(state.dirStack, state.cwd)
	}
	if simplePathAbs(dir) {
		return simplePathClean(dir), true
	}
	if program == "cd" && (vars["CDPATH"] != "" || len(cdPathCandidates(call, dir)) != 0) &&
		!strings.HasPrefix(dir, "./") && !strings.HasPrefix(dir, "../") {
		// A CDPATH may send the cd to another folder: the CDPATH the walk
		// holds, or one a prefix assignment sets (CDPATH=/srv cd app), also
		// one whose value is not known (CDPATH="$X" cd app), which the
		// assignment drops from vars. The candidates are the ones the
		// working-folder tracking reads (cdPathCandidates), so the walk and
		// the path facts agree on the folder, PWD included
		// (rel-1-0-10:GAP-1063).
		return "", true
	}
	if state.cwd == "" {
		return "", true
	}
	return simplePathJoin(state.cwd, dir), true
}

// simplePathAbs reports whether a shell directory or operand is absolute.
// The commands are POSIX shell text, so a "/" path is absolute on every
// host; filepath.IsAbs alone made `cd /home/alice` relative on a Windows
// gateway, which joined it under the current directory and hid the file a
// later relative read names. A Windows drive path keeps its native meaning.
func simplePathAbs(value string) bool {
	return strings.HasPrefix(value, "/") || filepath.IsAbs(value)
}

// simplePathClean cleans a POSIX path with POSIX rules (filepath.Clean
// rewrites "/" to "\" on Windows) and a native path with native rules.
func simplePathClean(value string) string {
	if simplePOSIXAbs(value) {
		return path.Clean(value)
	}
	return filepath.Clean(value)
}

// simplePathJoin joins a relative operand to a folder with the rules of
// the folder: POSIX rules for a "/" folder (filepath.Join would turn
// /srv/root into \srv\root on Windows), native rules for any other.
func simplePathJoin(folder, operand string) string {
	if simplePOSIXAbs(folder) {
		return path.Join(folder, operand)
	}
	return filepath.Join(folder, operand)
}

// simplePOSIXAbs reports a "/" path that is not a "//host/share" one, which
// keeps its native (UNC) meaning on Windows.
func simplePOSIXAbs(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//")
}

// simpleUserNames are the two names of the login a POSIX home spells.
var simpleUserNames = []string{"USER", "LOGNAME"}

// simpleInitialUserVars is the value of each of USER and LOGNAME where a
// walk starts: the base name of a POSIX home at the start of the action,
// the values inherited where a shell body starts.
func simpleInitialUserVars(home string, inherited map[string]string) map[string]string {
	vars := make(map[string]string, len(simpleUserNames))
	user := path.Base(home)
	for _, name := range simpleUserNames {
		if inherited != nil {
			if value, ok := inherited[name]; ok {
				vars[name] = value
			}
		} else if strings.HasPrefix(home, "/") && user != "/" && user != "." {
			vars[name] = user
		}
	}
	return vars
}

// simpleChildUserVars is USER and LOGNAME as the shell (shell, bash when
// empty) that call starts sees them: the caller values in effective (prefix
// assignments applied), changed in order by what an env wrapper puts before
// the shell. NAME=value sets a name; env -u NAME or -i unsets it, which a
// bash or sh child reads as empty and a zsh child as the login name again
// (login holds those values); the other names stay what they are. A name is
// left out when another wrapper option, sudo, or a word the walk cannot read
// may change the environment: the body then reads it as an unknown name. A
// shared body (eval, trap) runs in the caller itself.
func simpleChildUserVars(call *syntax.CallExpr, effective map[string]string, shared bool, shell string, login map[string]string) map[string]string {
	child := make(map[string]string, len(simpleUserNames))
	for _, name := range simpleUserNames {
		if value, ok := effective[name]; ok {
			child[name] = value
		}
	}
	if shared || call == nil {
		return child
	}
	unset := func(name string) {
		if !slices.Contains(simpleUserNames, name) {
			return
		}
		if value, ok := login[name]; ok && shell == "zsh" {
			child[name] = value
		} else if shell == "zsh" {
			delete(child, name)
		} else {
			child[name] = ""
		}
	}
	env := false
	for index := 0; index < len(call.Args); index++ {
		word, static := simpleStaticWord(call.Args[index], effective)
		if !static {
			clear(child)
			return child
		}
		if index == 0 {
			env = filepath.Base(word) == "env"
		} else if env {
			switch {
			case word == "-i" || word == "--ignore-environment" || word == "-":
				for _, name := range simpleUserNames {
					unset(name)
				}
				continue
			case word == "-u" || word == "--unset":
				index++
				name, known := "", false
				if index < len(call.Args) {
					name, known = simpleStaticWord(call.Args[index], effective)
				}
				if !known {
					clear(child)
					return child
				}
				unset(name)
				continue
			case strings.HasPrefix(word, "--unset="):
				unset(strings.TrimPrefix(word, "--unset="))
				continue
			case strings.HasPrefix(word, "-u") && !strings.HasPrefix(word, "--") && len(word) > 2:
				unset(word[2:])
				continue
			case word == "-0" || word == "--null" || word == "-v" || word == "--debug":
				continue
			}
		}
		if index != 0 && strings.HasPrefix(word, "-") {
			clear(child)
			return child
		}
		if name, value, cut := strings.Cut(word, "="); cut && slices.Contains(simpleUserNames, name) {
			child[name] = value
			continue
		}
		switch filepath.Base(word) {
		case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash":
			return child
		}
	}
	return child
}

// simplePrefixBindsUser reports a prefix assignment of USER or LOGNAME on a
// call that starts a shell body: the body reads the assigned value, so the
// call is read with its prefix.
func simplePrefixBindsUser(call *syntax.CallExpr, effective map[string]string) bool {
	if !slices.ContainsFunc(call.Assigns, func(assign *syntax.Assign) bool {
		return assign != nil && assign.Name != nil && slices.Contains(simpleUserNames, assign.Name.Value)
	}) {
		return false
	}
	_, _, nested, _ := simpleNestedScript(call, effective, nil, nil)
	return nested
}

// simpleReboundReading reports a state that holds a word of a forked loop for
// a statement that runs after code that can bind the variable again. The
// state that left the variable unread stays, so the statement is read as it
// was before the loop, and the statements before the binding keep the word.
func simpleReboundReading(state simpleShellState, part sequenceStatement) bool {
	for _, name := range state.forked {
		for index := len(part.binds) - 1; index >= 0; index-- {
			if bind := part.binds[index]; bind.fork && bind.name == name {
				if bind.reboundAt(part.sourceStart) {
					return true
				}
				break
			}
		}
	}
	return false
}
