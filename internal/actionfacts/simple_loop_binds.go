// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// A for or select variable takes one word of its list in each iteration,
// with the value that word has where the loop starts: the rule an
// assignment (u=$USER) already follows. SimpleCommands reads a statement of
// the loop body once for each value the walk can read, so an operand spelled
// through the variable is judged as the path it names (GAP-0880). USER and
// LOGNAME keep their own login rule (simpleApplyLoopBinds).
//
// The walk forks its states once, where it enters the loop (simpleForkLoopBind),
// and drops the name where the loop ends. The readings are proof-only, so they
// have a bound of their own and do not count against maxSimpleStates. The
// words that can name DefenseClaw state are read first: an expansion, the
// login, a path or a dotted name. Of the other words the first
// maxPlainReadings are read. The rest, and a list the walk cannot read at all,
// stay unread and follow the compound-limit rule: the walk does not report a
// limit for them, because a long ordinary list is not an over-limit call.
const (
	// maxLoopReadings is the most distinct values one loop variable is read as
	// from one state; maxPlainReadings of them may be plain words, which only
	// name state through a link. Each reading costs a check of its own, and a
	// hook answers within a bound of its time.
	maxLoopReadings  = 48
	maxPlainReadings = 4
	// maxForkedStates is the most states, forked readings included, that a
	// scope holds.
	maxForkedStates = 256
	// forkedLoopScopeKind is the scope kind of the body of such a loop; the
	// name of its variable follows the kind and an equals sign.
	forkedLoopScopeKind = byte('l')
)

// simpleLoopForks reports a for or select loop whose variable is read per
// word: an explicit list and a name the body does not bind again. A function
// the body calls is code the body runs, so it counts as a binding.
func simpleLoopForks(loop *syntax.ForClause, iteration *syntax.WordIter, functionNames []string) bool {
	if iteration.Name == nil || slices.Contains(simpleUserNames, iteration.Name.Value) ||
		!iteration.InPos.IsValid() || len(iteration.Items) == 0 {
		return false
	}
	return !simpleMayBind(loop.Do, iteration.Name.Value, functionNames, nil)
}

// simpleMayBind reports code in stmts that can give name another value than
// the loop does: an assignment, a loop or declaration of the name,
// arithmetic, a default assignment, a command that reads into a variable, a
// call of a function the action declares, and code the walk does not read.
// skip is one call that is left out (the read of a while read loop).
func simpleMayBind(stmts []*syntax.Stmt, name string, functionNames []string, skip *syntax.CallExpr) bool {
	binds := false
	for _, stmt := range stmts {
		syntax.Walk(stmt, func(node syntax.Node) bool {
			switch node := node.(type) {
			case *syntax.Assign:
				binds = binds || node.Name == nil || node.Name.Value == name
			case *syntax.WordIter:
				binds = binds || node.Name == nil || node.Name.Value == name
			case *syntax.DeclClause:
				binds = binds || slices.ContainsFunc(node.Args, func(arg *syntax.Assign) bool { return arg.Name == nil })
			case *syntax.ArithmCmd, *syntax.ArithmExp, *syntax.LetClause, *syntax.CStyleLoop:
				binds = true
			case *syntax.ParamExp:
				binds = binds || node.Exp != nil && node.Param != nil && node.Param.Value == name &&
					(node.Exp.Op == syntax.AssignUnset || node.Exp.Op == syntax.AssignUnsetOrNull)
			case *syntax.CallExpr:
				if node == skip {
					return false
				}
				binds = binds || simpleCallMayBind(node, name, functionNames)
			}
			return !binds
		})
		if binds {
			return true
		}
	}
	return false
}

// simpleCallMayBind reports a call that can bind name: a program the walk
// cannot read, a function of the action, code it runs from text (eval,
// source, trap), or a builtin that names variables, given a word that is
// name or that the walk cannot read.
func simpleCallMayBind(call *syntax.CallExpr, name string, functionNames []string) bool {
	if len(call.Args) == 0 {
		return false
	}
	program, known := simpleStaticWord(call.Args[0], nil)
	if !known || slices.Contains(functionNames, program) {
		return true
	}
	switch program {
	case "eval", "source", ".", "trap", "alias", "enable", "coproc":
		return true
	case "printf":
		// Only printf -v names a variable; a quoted format word is one word,
		// never the option.
		for index, arg := range call.Args[1:] {
			value, static := simpleStaticWord(arg, nil)
			if static && value == "-v" || !static && index == 0 && !simpleQuotedWord(arg) {
				return true
			}
		}
	case "read", "mapfile", "readarray", "getopts", "unset", "export", "readonly", "declare", "typeset", "local", "set", "shift":
		for _, arg := range call.Args[1:] {
			if value, static := simpleStaticWord(arg, nil); !static || value == name {
				return true
			}
		}
	}
	return false
}

// simpleForkLoopBind returns the states a forked loop starts its body with:
// each of entry as it is (the variable unread, as for a list the walk cannot
// read), and with the variable read once for every list word the walk can
// read, up to maxLoopReadings distinct values. A word with several fields or
// a pattern is left to the first reading. fits is false when the readings
// would pass maxForkedStates; the variable then stays unread.
func simpleForkLoopBind(entry []simpleShellState, bind simpleLoopBind) (forked []simpleShellState, fits bool) {
	for _, prior := range entry {
		forked = append(forked, prior)
		type candidate struct {
			value    string
			priority bool
		}
		var candidates []candidate
		login := path.Base(prior.vars["HOME"])
		for _, word := range bind.items {
			value, known := simpleStaticWord(word, prior.vars)
			if !known || strings.ContainsAny(value, " \t\n*?[") {
				continue
			}
			for _, reading := range bind.readings(value) {
				if !slices.ContainsFunc(candidates, func(seen candidate) bool { return seen.value == reading }) {
					candidates = append(candidates, candidate{reading, reading == login ||
						strings.ContainsAny(reading, "/.") || !simpleLiteralWord(word)})
				}
			}
		}
		// The words that can name state come first when the list is long.
		slices.SortStableFunc(candidates, func(a, b candidate) int {
			switch {
			case a.priority == b.priority:
				return 0
			case a.priority:
				return -1
			}
			return 1
		})
		plain := 0
		for index, read := range candidates {
			if index == maxLoopReadings {
				break
			}
			if !read.priority {
				if plain++; plain > maxPlainReadings {
					break
				}
			}
			alt := prior.clone()
			alt.vars[bind.name] = read.value
			if !slices.Contains(alt.forked, bind.name) {
				alt.forked = append(alt.forked, bind.name)
			}
			forked = append(forked, alt)
		}
	}
	forked = uniqueSimpleStates(forked)
	return forked, len(forked) <= maxForkedStates
}

// simpleLiteralWord reports a word that is plain text, with no expansion.
func simpleLiteralWord(word *syntax.Word) bool {
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				if _, literal := inner.(*syntax.Lit); !literal {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// readings are the values a read loop variable takes from one input word:
// the word, and the word less its last character when the IFS of the read
// ends the line with it (read drops one trailing delimiter).
func (bind simpleLoopBind) readings(value string) []string {
	if value != "" && strings.IndexByte(bind.ifs, value[len(value)-1]) >= 0 {
		return []string{value, value[:len(value)-1]}
	}
	return []string{value}
}

// simpleEnterForkedLoops forks the states at the start of each forked loop
// around part that the walk has not entered yet. A loop whose readings do not
// fit stays unread. ok is false when the scopes and the loops of part do not
// match.
func simpleEnterForkedLoops(states map[string][]simpleShellState, part sequenceStatement, unread map[string]bool) bool {
	scopes := simpleForkedScopes(part.scope)
	var binds []simpleLoopBind
	for _, bind := range part.binds {
		if bind.fork {
			binds = append(binds, bind)
		}
	}
	if len(scopes) != len(binds) {
		return false
	}
	for index, scope := range scopes {
		if _, entered := states[scope]; entered || unread[scope] {
			continue
		}
		entry := simpleScopeStates(states, scope)
		if entry == nil {
			return false
		}
		if forked, fits := simpleForkLoopBind(entry, binds[index]); fits {
			states[scope] = forked
		} else {
			unread[scope] = true
		}
	}
	return true
}

// simpleOverStateBound reports more states than a scope may hold: the states
// no forked loop reads are bounded by maxSimpleStates, the forked readings by
// maxForkedStates.
func simpleOverStateBound(states []simpleShellState) bool {
	plain := 0
	for _, state := range states {
		if len(state.forked) == 0 {
			plain++
		}
	}
	return plain > maxSimpleStates || len(states) > maxForkedStates
}

// simpleForkedScopes returns the scopes of forked loops that scope is in,
// outermost first.
func simpleForkedScopes(scope string) []string {
	var scopes []string
	parts := strings.Split(scope, "/")
	for index := 1; index < len(parts); index++ {
		if parts[index] != "" && parts[index][0] == forkedLoopScopeKind {
			scopes = append(scopes, strings.Join(parts[:index+1], "/"))
		}
	}
	return scopes
}

// simpleForkedScopeName returns the variable of the forked loop of scope.
func simpleForkedScopeName(scope string) string {
	_, name, _ := strings.Cut(scope[strings.LastIndexByte(scope, '/')+1:], "=")
	return name
}

// simpleQuotedWord reports a word that is one quoted string.
func simpleQuotedWord(word *syntax.Word) bool {
	if len(word.Parts) != 1 {
		return false
	}
	switch word.Parts[0].(type) {
	case *syntax.DblQuoted, *syntax.SglQuoted:
		return true
	}
	return false
}

// simpleParamNames returns the variables text expands. A statement in a
// forked state is one iteration of its loop where it spells the variable, and
// only proves a write to DefenseClaw state (SimpleCommand.LoginGuess): the
// whole action keeps deciding every other rule, as before.
func simpleParamNames(text string) []string {
	if !strings.ContainsRune(text, '$') {
		return nil
	}
	file, ok := shellparse.Parse(text)
	if !ok {
		return nil
	}
	var names []string
	syntax.Walk(file, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok && param.Param != nil && !slices.Contains(names, param.Param.Value) {
			names = append(names, param.Param.Value)
		}
		return true
	})
	return names
}

// simpleReadLoopBind returns the binding of a while read [-r] name loop whose
// input is one static echo or printf stage: name takes that one word, as an
// iteration of a for loop over it would. The read may have an IFS prefix
// (while IFS= read -r name). A longer input, other options, a backslash
// (read without -r reads it as an escape), and a body or an action that
// binds the name or IFS in a way the walk cannot read leave it unread.
func simpleReadLoopBind(loop *syntax.WhileClause, input *syntax.Stmt, file *syntax.File, functionNames []string) (simpleLoopBind, bool) {
	if input == nil || loop.Until || len(loop.Cond) != 1 || input.Negated || input.Background || len(input.Redirs) != 0 {
		return simpleLoopBind{}, false
	}
	read, ok := loop.Cond[0].Cmd.(*syntax.CallExpr)
	if !ok || loop.Cond[0].Negated || loop.Cond[0].Background || len(loop.Cond[0].Redirs) != 0 ||
		len(read.Args) < 2 || len(read.Args) > 3 {
		return simpleLoopBind{}, false
	}
	ifs, ok := simpleReadIFS(read.Assigns)
	if !ok {
		return simpleLoopBind{}, false
	}
	if program, static := simpleStaticWord(read.Args[0], nil); !static || program != "read" {
		return simpleLoopBind{}, false
	}
	name, static := simpleStaticWord(read.Args[len(read.Args)-1], nil)
	if !static || !simpleVariableName(name) || slices.Contains(simpleUserNames, name) {
		return simpleLoopBind{}, false
	}
	if len(read.Args) == 3 {
		if option, static := simpleStaticWord(read.Args[1], nil); !static || option != "-r" {
			return simpleLoopBind{}, false
		}
	}
	echo, ok := input.Cmd.(*syntax.CallExpr)
	if !ok || len(echo.Assigns) != 0 || len(echo.Args) < 2 {
		return simpleLoopBind{}, false
	}
	program, static := simpleStaticWord(echo.Args[0], nil)
	if !static {
		return simpleLoopBind{}, false
	}
	var word *syntax.Word
	switch {
	case program == "echo" && len(echo.Args) == 2:
		word = echo.Args[1]
	case program == "printf" && len(echo.Args) == 3:
		if format, static := simpleStaticWord(echo.Args[1], nil); static && (format == "%s\\n" || format == "%s") {
			word = echo.Args[2]
		}
	}
	if word == nil || simpleMayBind(loop.Do, name, functionNames, nil) ||
		simpleMayBind(file.Stmts, "IFS", functionNames, read) {
		return simpleLoopBind{}, false
	}
	if text, static := simpleStaticWord(word, nil); static && (strings.HasPrefix(text, "-") || strings.Contains(text, "\\")) {
		return simpleLoopBind{}, false
	}
	return simpleLoopBind{name: name, items: []*syntax.Word{word}, fork: true, ifs: ifs}, true
}

// simpleReadIFS returns the IFS a read call sets for itself with a prefix
// assignment, "" when it sets none. Any other prefix is not read.
func simpleReadIFS(assigns []*syntax.Assign) (string, bool) {
	switch len(assigns) {
	case 0:
		return "", true
	case 1:
		assign := assigns[0]
		if assign.Name == nil || assign.Name.Value != "IFS" || assign.Append || assign.Naked ||
			assign.Array != nil || assign.Index != nil {
			return "", false
		}
		if assign.Value == nil {
			return "", true
		}
		return simpleStaticWord(assign.Value, nil)
	}
	return "", false
}
