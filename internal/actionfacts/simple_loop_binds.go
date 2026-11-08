// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
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
const (
	// maxLoopBindItems bounds the words of a list read this way; a longer
	// list leaves its variable unknown, as every loop variable was before.
	maxLoopBindItems = 8
	// forkedLoopScopeKind is the scope kind of the body of such a loop.
	forkedLoopScopeKind = byte('l')
)

// simpleLoopForks reports a for or select loop whose variable is read per
// word: an explicit list of a few words, a name the body does not bind
// again, and no function the body could call to bind it.
func simpleLoopForks(loop *syntax.ForClause, iteration *syntax.WordIter, functions bool) bool {
	if functions || iteration.Name == nil || slices.Contains(simpleUserNames, iteration.Name.Value) ||
		!iteration.InPos.IsValid() || len(iteration.Items) == 0 || len(iteration.Items) > maxLoopBindItems {
		return false
	}
	return !simpleLoopBodyMayBind(loop.Do, iteration.Name.Value)
}

// simpleLoopBodyMayBind reports code in body that can give name another
// value than the loop does: an assignment, a loop or declaration of the
// name, arithmetic, a default assignment, a command that reads into a
// variable, and code the walk does not read.
func simpleLoopBodyMayBind(body []*syntax.Stmt, name string) bool {
	binds := false
	for _, stmt := range body {
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
				binds = binds || simpleCallMayBind(node, name)
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
// cannot read, code it runs from text (eval, source, trap), or a builtin
// that names variables, given a word that is name or that the walk cannot
// read.
func simpleCallMayBind(call *syntax.CallExpr, name string) bool {
	if len(call.Args) == 0 {
		return false
	}
	program, known := simpleStaticWord(call.Args[0], nil)
	if !known {
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

// simpleForkLoopBinds returns variants with each forked loop variable read
// once for every list word the walk can read, next to the reading that
// leaves it as it was (unread, as for a list it cannot read). A word with
// several fields or a pattern is left to that reading. When the readings
// would pass the state bound, the variable stays unread.
func simpleForkLoopBinds(variants []simpleShellState, binds []simpleLoopBind) []simpleShellState {
	for _, bind := range binds {
		if !bind.fork {
			continue
		}
		var forked []simpleShellState
		for _, prior := range variants {
			forked = append(forked, prior)
			for _, word := range bind.items {
				value, known := simpleStaticWord(word, prior.vars)
				if !known || strings.ContainsAny(value, " \t\n*?[") {
					continue
				}
				alt := prior.clone()
				alt.vars[bind.name] = value
				alt.forked = true
				forked = append(forked, alt)
			}
		}
		if unique := uniqueSimpleStates(forked); len(unique) <= maxSimpleStates {
			variants = unique
		}
	}
	return variants
}

// simpleForkedNames are the variables the forked loops of binds read.
func simpleForkedNames(parts []sequenceStatement) []string {
	var names []string
	for _, part := range parts {
		for _, bind := range part.binds {
			if bind.fork && !slices.Contains(names, bind.name) {
				names = append(names, bind.name)
			}
		}
	}
	return names
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

// simpleReadsForkedName reports a statement that reads a variable of a
// forked loop around it. Its reading in a forked state is one iteration, and
// only proves a write to DefenseClaw state (SimpleCommand.LoginGuess): the
// whole action keeps deciding every other rule, as before.
func simpleReadsForkedName(text string, binds []simpleLoopBind) bool {
	var names []string
	for _, bind := range binds {
		if bind.fork {
			names = append(names, bind.name)
		}
	}
	if len(names) == 0 || !strings.ContainsRune(text, '$') {
		return false
	}
	file, ok := shellparse.Parse(text)
	if !ok {
		return false
	}
	reads := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok && param.Param != nil && slices.Contains(names, param.Param.Value) {
			reads = true
		}
		return !reads
	})
	return reads
}

// simpleReadLoopBind returns the binding of a while read [-r] name loop whose
// input is one static echo or printf stage: name takes that one word, as an
// iteration of a for loop over it would. A longer input, other options, a
// changed IFS, a backslash (read without -r reads it as an escape) and a body
// that binds the name again leave it unread.
func simpleReadLoopBind(loop *syntax.WhileClause, input *syntax.Stmt, source string, functions bool) (simpleLoopBind, bool) {
	if functions || input == nil || loop.Until || len(loop.Cond) != 1 || strings.Contains(source, "IFS") ||
		input.Negated || input.Background || len(input.Redirs) != 0 {
		return simpleLoopBind{}, false
	}
	read, ok := loop.Cond[0].Cmd.(*syntax.CallExpr)
	if !ok || len(read.Assigns) != 0 || len(loop.Cond[0].Redirs) != 0 || len(read.Args) < 2 || len(read.Args) > 3 {
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
	if word == nil || simpleLoopBodyMayBind(loop.Do, name) {
		return simpleLoopBind{}, false
	}
	if text, static := simpleStaticWord(word, nil); static && (strings.HasPrefix(text, "-") || strings.Contains(text, "\\")) {
		return simpleLoopBind{}, false
	}
	return simpleLoopBind{name: name, items: []*syntax.Word{word}, fork: true}, true
}
