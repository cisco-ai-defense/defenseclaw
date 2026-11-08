// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
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
	// AbsoluteOnly means the directory of the command is unknown (an eval,
	// an unreadable cd) and no operand of Text depends on it: CWD is empty,
	// and the directory the action starts in judges the command as well as
	// any other (rel-1-0-6:GAP-0630 review 5).
	AbsoluteOnly bool
	// EvaluationFailure is "limit" or "parse" when no complete per-command
	// view can be produced. A parse gap is not an action refusal.
	EvaluationFailure string
}

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
)

func (s simpleShellState) clone() simpleShellState {
	copy := simpleShellState{cwd: s.cwd, cwdUnknown: s.cwdUnknown,
		dirStack: slices.Clone(s.dirStack), vars: make(map[string]string, len(s.vars)),
		locals: slices.Clone(s.locals), forked: slices.Clone(s.forked)}
	for name, value := range s.vars {
		copy.vars[name] = value
	}
	return copy
}

// SimpleCommands flattens an action with the full parser used by the hook
// command class rule. Every returned command is judged on its own, in
// addition to the original action. A plain single command needs no second
// pass. Ordinary assignments and known home or local variable expansions
// are resolved; a subshell or pipeline stage has its own shell state.
func SimpleCommands(input Input, facts Facts) []SimpleCommand {
	result := simpleCommandsOfCall(input, facts)
	if input.Command == "" && facts.Parse.Status == StatusInvalid && containsIssue(facts.Parse.Issues, IssueInvalidSyntax) &&
		slices.ContainsFunc(result, func(simple SimpleCommand) bool { return simple.EvaluationFailure != "" }) {
		// The POSIX reader rejected the call (a construct only Bash has) and
		// the shell parse reads it only to add readings (simpleCommands): a
		// call it cannot read in full keeps the judgment it had without them.
		return nil
	}
	return result
}

func simpleCommandsOfCall(input Input, facts Facts) []SimpleCommand {
	result := simpleCommands(input, facts, 0, "", nil, false)
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
	for _, guessed := range simpleCommands(input, facts, 0, "", nil, true) {
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
func simpleCommands(input Input, facts Facts, depth int, interpreter string, inherited map[string]string, guess bool) []SimpleCommand {
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
	if !strings.ContainsAny(source, ";&|(){}<>\n`$=!") &&
		!strings.Contains(source, "eval") && !strings.Contains(source, "trap") &&
		!strings.Contains(source, " -") {
		return nil
	}
	parts, reduced, ok := sequenceStatementDetails(source, true, true)
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
	if !reduced && len(parts) == 1 {
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
		if !prefix && !duplication && !nested && !inheritsUser {
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
		"0": {{cwd: input.CWD, vars: initialVars}},
	}
	result := make([]SimpleCommand, 0, len(parts))
	changed := reduced || len(parts) != 1
	unproven := false
	previousScope := "0"
	unreadLoops := make(map[string]bool)
	var plainWords simplePlainWords
	for partIndex, part := range parts {
		// A conditional or loop body runs in its parent's shell when selected.
		// Keep both its resulting state and the path that skipped the body.
		for previousScope != part.scope && !strings.HasPrefix(part.scope, previousScope+"/") {
			index := strings.LastIndexByte(previousScope, '/')
			if index < 0 {
				return []SimpleCommand{{EvaluationFailure: "parse"}}
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
			return []SimpleCommand{{EvaluationFailure: "parse"}}
		}
		variants := simpleScopeStates(states, part.scope)
		if variants == nil {
			return []SimpleCommand{{EvaluationFailure: "parse"}}
		}
		file, parsed := shellparse.Parse(part.text)
		if !parsed || len(file.Stmts) != 1 {
			return []SimpleCommand{{EvaluationFailure: "parse"}}
		}
		stmt := file.Stmts[0]
		nextVariants := make([]simpleShellState, 0, len(variants))
		emitted := make(map[SimpleCommand]bool)
		for _, prior := range variants {
			if simpleReboundReading(prior, part) {
				continue
			}
			state := prior.clone()
			simpleApplyLoopBinds(state.vars, part.binds, login)
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) == 0 && len(call.Assigns) != 0 && len(stmt.Redirs) == 0 {
				updateSimpleVariables(state.vars, call.Assigns)
				changed = true
				nextVariants = append(nextVariants, state)
				if part.maySkip && len(prior.forked) != 0 {
					// The assignment may not run: the word of the loop stays.
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
					return []SimpleCommand{{EvaluationFailure: "parse"}}
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
			resolve := func(text string) string {
				if resolved, ok := simpleResolvedVariables(text, state.vars); ok {
					text = resolved
					changed = true
				}
				if resolved, ok := simpleResolvedDirectoryStackTildes(text, &state); ok {
					text = resolved
					changed = true
				}
				if stripped, ok := withoutDescriptorDuplications(text); ok {
					text = stripped
					changed = true
				}
				return text
			}
			text = resolve(text)
			if strings.TrimSpace(text) == "" {
				return []SimpleCommand{{EvaluationFailure: "parse"}}
			}
			relative := state.cwdUnknown && simpleRelativePathOperand(text)
			if relative {
				unproven = true
			}
			call, _ := stmt.Cmd.(*syntax.CallExpr)
			command := SimpleCommand{Text: text, CWD: state.cwd,
				ZshHistoryBuiltin:       simpleZshHistoryCall(call, effective, interpreter),
				LoginGuess:              loopRead,
				LoopReading:             loopRead,
				UnresolvedBoundVariable: simpleUnresolvedBoundVariable(text, effective, bound),
				UnboundUser:             simpleUnboundUser(text, effective, bound),
				AbsoluteOnly:            state.cwdUnknown && !relative}
			if !emitted[command] {
				result = append(result, command)
				emitted[command] = true
				if len(result) > maxSimpleEvaluations {
					return []SimpleCommand{{EvaluationFailure: "limit"}}
				}
			}
			if unprefixed != "" {
				if reading := resolve(unprefixed); strings.TrimSpace(reading) != "" {
					alone := SimpleCommand{Text: reading, CWD: state.cwd,
						ZshHistoryBuiltin:       command.ZshHistoryBuiltin,
						LoginGuess:              command.LoginGuess,
						LoopReading:             command.LoopReading,
						UnresolvedBoundVariable: simpleUnresolvedBoundVariable(reading, effective, bound),
						UnboundUser:             simpleUnboundUser(reading, effective, bound),
						AbsoluteOnly:            command.AbsoluteOnly}
					if !emitted[alone] {
						result = append(result, alone)
						emitted[alone] = true
						changed = true
						if len(result) > maxSimpleEvaluations {
							return []SimpleCommand{{EvaluationFailure: "limit"}}
						}
					}
				}
			}
			if call != nil {
				var innerCWDUnknown bool
				var innerInterpreter string
				script, shared, nested, static := simpleNestedScript(call, effective, &innerCWDUnknown, &innerInterpreter)
				if nested {
					if !static || len(script) > maxCommandBytes {
						return []SimpleCommand{{EvaluationFailure: "parse"}}
					}
					innerInput := input
					innerInput.Command, innerInput.Args, innerInput.Argv = script, nil, nil
					innerInput.CWD = state.cwd
					if innerCWDUnknown {
						innerInput.CWD = ""
					}
					if shared {
						if resolved, ok := simpleResolvedVariables(script, effective); ok {
							innerInput.Command = resolved
						}
					}
					if _, ok := shellparse.Parse(innerInput.Command); !ok {
						return []SimpleCommand{{EvaluationFailure: "parse"}}
					}
					innerFacts := Analyze(innerInput)
					if innerInterpreter == "" {
						innerInterpreter = interpreter
					}
					inner := simpleCommands(innerInput, innerFacts, depth+1, innerInterpreter,
						simpleChildUserVars(call, effective, shared, innerInterpreter, login), guess)
					if len(inner) == 0 && strings.TrimSpace(innerInput.Command) != "" {
						zshHistory := innerInterpreter == "zsh" && len(innerFacts.Commands) == 1 &&
							innerFacts.Commands[0].Executable == "history"
						inner = []SimpleCommand{{Text: innerInput.Command, CWD: innerInput.CWD,
							ZshHistoryBuiltin: zshHistory}}
					}
					changed = changed || len(inner) != 0
					for _, child := range inner {
						if child.EvaluationFailure != "" {
							unproven = true
							continue
						}
						child.UnresolvedBoundVariable = child.UnresolvedBoundVariable ||
							simpleUnresolvedBoundVariable(child.Text, effective, bound)
						child.UnboundUser = child.UnboundUser || simpleUnboundUser(child.Text, effective, bound)
						result = append(result, child)
						if len(result) > maxSimpleEvaluations {
							return []SimpleCommand{{EvaluationFailure: "limit"}}
						}
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
				updateSimpleDeclVariables(&state, decl, part.scope)
			}
			if call != nil {
				simpleForgetUserVars(state.vars, CallBindsUserNames(call))
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
			nextVariants = append(nextVariants, state)
			if part.maySkip && len(prior.forked) != 0 {
				// The statement may not run: the word of the loop stays.
				nextVariants = append(nextVariants, prior)
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
	state := simpleWindowsState{cwd: input.CWD}
	failed := false
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
	appendPart := func(part string, start, end int) {
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
		state.next(part, dialect, childInput, variables)
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
		appendPart(part, begin, lexeme.start)
		begin = lexeme.end
		if lexeme.kind == windowsPipeLexeme || lexeme.operator == "&&" || lexeme.operator == "||" {
			// A pipeline stage has a separate scope; conditional assignments
			// may not have run. Do not carry either into a later command.
			clear(variables)
		}
		if len(result) >= maxStatementsAlone {
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
	appendPart(last, begin, len(runes))
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
				slices.Equal(previous.locals, state.locals)
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
	for _, assign := range decl.Args {
		if assign == nil || assign.Name != nil {
			continue
		}
		if assign.Value == nil {
			known = false
			continue
		}
		option := projectPOSIXWord(assign.Value)
		if decl.Variant.Value == "export" && !option.Expands && option.Value == "-n" {
			continue
		}
		if !homeDeclOption(option) {
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
			}
			continue
		}
		updateSimpleVariables(vars, []*syntax.Assign{assign})
	}
}

// simpleDeclGlobal reports a static -g option word of a declaration.
func simpleDeclGlobal(decl *syntax.DeclClause) bool {
	for _, assign := range decl.Args {
		if assign == nil || assign.Name != nil || assign.Value == nil {
			continue
		}
		option := projectPOSIXWord(assign.Value)
		if !option.Expands && strings.HasPrefix(option.Value, "-") && strings.ContainsRune(option.Value[1:], 103) {
			return true
		}
	}
	return false
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

func updateSimpleVariables(vars map[string]string, assigns []*syntax.Assign) {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil || assign.Index != nil || assign.Array != nil {
			continue
		}
		name := assign.Name.Value
		if assign.Value == nil {
			vars[name] = ""
		} else if value, known := simpleStaticWord(assign.Value, vars); known {
			vars[name] = value
		} else if name != "HOME" {
			delete(vars, name)
		}
		// A HOME value the walk cannot read (HOME=$(echo $HOME), HOME=$X)
		// keeps the previous HOME: an unknown HOME dropped every later ~
		// write (GAP-2476). A home that a run-time value really moves to is
		// outside what the static check can follow.
	}
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
	if call == nil || len(call.Args) == 0 {
		return nil
	}
	program, known := simpleStaticWord(call.Args[0], nil)
	if !known {
		return nil
	}
	var names []string
	add := func(name string) {
		if slices.Contains(simpleUserNames, name) && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	switch program {
	case "printf":
		if len(call.Args) >= 3 && call.Args[1].Lit() == "-v" {
			if name, known := simpleStaticWord(call.Args[2], nil); known {
				add(name)
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
				for _, user := range simpleUserNames {
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
		for _, name := range simpleUserNames {
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
				for _, name := range simpleUserNames {
					add(name)
				}
				return names
			}
			words = append(words, text)
		}
		for _, name := range evalCodeBindsUser(strings.Join(words, " "), 0) {
			add(name)
		}
	}
	return names
}

// simpleStaticWordOrEmpty reports a static word that starts with prefix.
func simpleStaticWordOrEmpty(word *syntax.Word, prefix byte) bool {
	text, known := simpleStaticWord(word, nil)
	return known && text != "" && text[0] == prefix
}

// evalCodeBindsUser returns the names of USER and LOGNAME that the shell
// code text binds: an assignment, a loop name, or a call that binds one
// (CallBindsUserNames). Code that does not parse may bind any.
func evalCodeBindsUser(text string, depth int) []string {
	file, ok := shellparse.Parse(text)
	if !ok || depth >= 4 {
		return simpleUserNames
	}
	var names []string
	add := func(name string) {
		if slices.Contains(simpleUserNames, name) && !slices.Contains(names, name) {
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
			for _, name := range CallBindsUserNames(node) {
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
			if !known || part.Excl || part.Length || part.Width || part.IsSet || part.Index != nil ||
				part.Slice != nil || part.Repl != nil || part.Names != 0 || part.Exp != nil ||
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
	syntax.Walk(file, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok &&
			(redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc) {
			return false
		}
		word, ok := node.(*syntax.Word)
		if !ok {
			return true
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
// left as written.
func simpleResolvedDirectoryStackTildes(source string, state *simpleShellState) (string, bool) {
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

// simpleNestedScript returns a static shell -c or eval body. eval shares the
// caller's variables and directory; a -c shell starts a child shell.
func simpleNestedScript(call *syntax.CallExpr, vars map[string]string, cwdUnknown *bool, interpreter *string) (script string, shared, nested, static bool) {
	if call == nil || len(call.Args) == 0 {
		return "", false, false, false
	}
	return simpleNestedScriptArgs(call.Args, vars, 0, cwdUnknown, interpreter)
}

func simpleNestedScriptArgs(args []*syntax.Word, vars map[string]string, depth int, cwdUnknown *bool, interpreter *string) (script string, shared, nested, static bool) {
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
	if program == "su" && simplePotentialShellScript(args) {
		// The target account can change both startup files and directory.
		return "", false, true, false
	}
	wrapper := filepath.Base(program)
	if simpleNestedWrapper(wrapper) {
		argv := make([]string, len(args))
		for index, arg := range args {
			value, known := simpleStaticScriptWord(arg, vars)
			if !known {
				if simplePotentialShellScript(args) {
					return "", false, true, false
				}
				return "", false, false, false
			}
			argv[index] = value
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
		case "env":
			if split, ok := simpleEnvSplitString(argv); ok {
				return split, false, true, true
			}
			childIndex = simpleEnvChildIndex(argv)
		default:
			child, found, uncertain := staticPOSIXWrapperArgv(argv, wrapper)
			if uncertain {
				if simplePotentialShellScript(args) {
					return "", false, true, false
				}
				return "", false, false, false
			}
			if !found {
				return "", false, false, false
			}
			childIndex = len(argv) - len(child)
		}
		if childIndex <= 0 || childIndex >= len(args) {
			return "", false, true, false
		}
		if program, ok := simpleWrappedProgram(wrapper, argv, childIndex); ok {
			return program, false, true, true
		}
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
		option := args[index].Lit()
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
			if simplePotentialShellScript(args) {
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

func simpleNestedWrapper(program string) bool {
	switch program {
	case "env", "sudo", "exec", "command", "nohup", "timeout", "nsenter", "chroot":
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
// NAME=value (PATH may change which program runs), nohup and timeout. A
// shell or another wrapper as the program is read as a nested script
// instead. The argv is static, so the call is judged as a simple command,
// where a match can only over-block (GAP-1200, #1189). env NAME=value prog
// is written as NAME=value prog, so the assignments are judged as the same
// prefix assignments are.
func simpleWrappedProgram(wrapper string, argv []string, childIndex int) (string, bool) {
	if childIndex <= 0 || childIndex >= len(argv) {
		return "", false
	}
	var assignments []string
	switch wrapper {
	case "nohup", "timeout":
	case "env":
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
		if len(assignments) == 0 {
			return "", false
		}
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

func simplePotentialShellScript(args []*syntax.Word) bool {
	for _, arg := range args {
		option := arg.Lit()
		if option == "-c" || len(option) > 2 && strings.HasPrefix(option, "-") && option[1] != '-' &&
			strings.ContainsRune(option[1:], 'c') {
			return true
		}
	}
	return false
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
		program, known = simpleStaticWord(call.Args[argStart], vars)
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
	if program == "cd" && vars["CDPATH"] != "" &&
		!strings.HasPrefix(dir, "./") && !strings.HasPrefix(dir, "../") {
		return "", true
	}
	if state.cwd == "" {
		return "", true
	}
	if simplePOSIXAbs(state.cwd) {
		return path.Join(state.cwd, dir), true
	}
	return filepath.Clean(filepath.Join(state.cwd, dir)), true
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
