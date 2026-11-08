// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

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
// and drops the name where the loop ends. A statement that runs after code
// that can bind the name again is not read with the word (simpleReboundAt):
// the statements before that code keep it. The readings are proof-only, so
// they have a bound of their own and do not count against maxSimpleStates.
// Every distinct word is read; when the readings would pass maxForkedStates
// the words that can name state come first (the login, an expansion, a path
// or a dotted name), and a list the walk cannot read at all stays unread and
// follows the compound-limit rule: the walk does not report a limit for it,
// because a long ordinary list is not an over-limit call.
//
// The plain words of a list (letters, digits and underscores, no login) only
// name state through a link, and each state costs a walk of its own. When the
// body only runs programs that take the word as an operand and never as a
// program, a directory or an option, the words share one state that holds a
// placeholder for the variable, and each command the walk reads from it is
// written once per word (simpleExpandPlainWords).
const (
	// maxForkedStates is the most states, forked readings included, that a
	// scope holds.
	maxForkedStates = 256
	// forkedLoopScopeKind is the scope kind of the body of such a loop; the
	// name of its variable follows the kind and an equals sign.
	forkedLoopScopeKind = byte('l')
)

// simpleLoopForks reports a for or select loop whose variable is read per
// word: an explicit list for a name other than USER and LOGNAME.
func simpleLoopForks(iteration *syntax.WordIter) bool {
	return iteration.Name != nil && !slices.Contains(simpleUserNames, iteration.Name.Value) &&
		iteration.InPos.IsValid() && len(iteration.Items) != 0
}

// simpleSpan is a range of source offsets.
type simpleSpan struct{ from, to int }

// simpleReboundAt reports a statement that starts where the loop variable may
// hold another value than the loop gave it (simpleReboundSpans).
func (bind simpleLoopBind) reboundAt(offset int) bool {
	return slices.ContainsFunc(bind.rebound, func(span simpleSpan) bool { return offset >= span.from && offset < span.to })
}

// simpleReboundSpans returns where in stmts, the body of a loop, name may hold
// another value than the loop gave it: after any code that can bind it again,
// and all of a nested loop or declared function that holds such code (it runs
// again, or later). A statement before every such code keeps the word of the
// loop. A function the action only declares binds nothing until it is called,
// and a prefix assignment (u=x cmd) sets the environment of cmd only. skip is
// one call that is left out (the read of a while read loop).
func simpleReboundSpans(stmts []*syntax.Stmt, name string, functionNames []string, skip *syntax.CallExpr) []simpleSpan {
	if len(stmts) == 0 {
		return nil
	}
	end := int(stmts[len(stmts)-1].End().Offset())
	var binders []int
	var wraps []syntax.Node
	var visit func(node syntax.Node) bool
	visit = func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.ForClause, *syntax.WhileClause:
			wraps = append(wraps, node)
			if _, declared := node.(*syntax.FuncDecl); declared {
				return false
			}
		case *syntax.CallExpr:
			if node == skip {
				return false
			}
			if len(node.Args) != 0 {
				// The prefix assignments are not walked; the words are.
				if simpleCallMayBind(node, name, functionNames) {
					binders = append(binders, int(node.Pos().Offset()))
				}
				for _, arg := range node.Args {
					syntax.Walk(arg, visit)
				}
				return false
			}
		}
		if simpleNodeBinds(node, name) {
			binders = append(binders, int(node.Pos().Offset()))
		}
		return true
	}
	for _, stmt := range stmts {
		syntax.Walk(stmt, visit)
	}
	if len(binders) == 0 {
		return nil
	}
	var spans []simpleSpan
	for _, offset := range binders {
		spans = append(spans, simpleSpan{offset + 1, end})
	}
	for _, wrap := range wraps {
		from, to := int(wrap.Pos().Offset()), int(wrap.End().Offset())
		if _, declared := wrap.(*syntax.FuncDecl); declared || slices.ContainsFunc(binders, func(offset int) bool { return offset >= from && offset < to }) {
			spans = append(spans, simpleSpan{from, to})
		}
	}
	return spans
}

// simpleNodeBinds reports a node that gives name another value, in a way the
// walk does not follow as an assignment of its own: a loop, a declaration,
// arithmetic, or a default assignment. A command that binds is
// simpleCallMayBind.
func simpleNodeBinds(node syntax.Node, name string) bool {
	switch node := node.(type) {
	case *syntax.Assign:
		return node.Name == nil || node.Name.Value == name
	case *syntax.WordIter:
		return node.Name == nil || node.Name.Value == name
	case *syntax.DeclClause:
		return slices.ContainsFunc(node.Args, func(arg *syntax.Assign) bool { return arg.Name == nil })
	case *syntax.ArithmCmd, *syntax.ArithmExp, *syntax.LetClause, *syntax.CStyleLoop:
		return true
	case *syntax.ParamExp:
		return node.Exp != nil && node.Param != nil && node.Param.Value == name &&
			(node.Exp.Op == syntax.AssignUnset || node.Exp.Op == syntax.AssignUnsetOrNull)
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
// read. A word with several fields or a pattern is left to the first
// reading. When the readings would pass maxForkedStates the words that can
// name state come first; fits is false when not even one reading fits, and
// the variable then stays unread.
func simpleForkLoopBind(entry []simpleShellState, bind simpleLoopBind, plain *simplePlainWords) (forked []simpleShellState, fits bool) {
	room := maxForkedStates/len(entry) - 1
	if room < 1 {
		return nil, false
	}
	for _, prior := range entry {
		forked = append(forked, prior)
		type candidate struct {
			value string
			tier  int
		}
		var candidates []candidate
		var shared []string
		login := path.Base(prior.vars["HOME"])
		for _, word := range bind.items {
			value, known := simpleStaticWord(word, prior.vars)
			if !known || strings.ContainsAny(value, " \t\n*?[") {
				continue
			}
			reading := bind.reading(value)
			if slices.ContainsFunc(candidates, func(seen candidate) bool { return seen.value == reading }) ||
				slices.Contains(shared, reading) {
				continue
			}
			tier := 2
			switch {
			case reading == login || !simpleLiteralWord(word):
				tier = 0
			case strings.ContainsAny(reading, "/."):
				tier = 1
			}
			if tier == 2 && bind.token != "" && simplePlainName(reading) {
				shared = append(shared, reading)
				continue
			}
			candidates = append(candidates, candidate{reading, tier})
		}
		// The words that can name state come first when the list is long.
		slices.SortStableFunc(candidates, func(a, b candidate) int { return a.tier - b.tier })
		values := make([]string, 0, len(candidates)+1)
		for _, read := range candidates[:min(len(candidates), room-min(len(shared), 1))] {
			values = append(values, read.value)
		}
		if len(shared) != 0 {
			values = append(values, bind.token)
			for _, word := range shared {
				plain.add(bind.token, word)
			}
		}
		for _, value := range values {
			alt := prior.clone()
			alt.vars[bind.name] = value
			if !slices.Contains(alt.forked, bind.name) {
				alt.forked = append(alt.forked, bind.name)
			}
			forked = append(forked, alt)
		}
	}
	forked = uniqueSimpleStates(forked)
	return forked, len(forked) <= maxForkedStates
}

// simplePlainName reports a word of letters, digits and underscores that
// starts with a letter: the one kind of value that every consumer of a
// reading treats as any other, so a placeholder stands for it.
func simplePlainName(word string) bool {
	if word == "" || word[0] >= '0' && word[0] <= '9' {
		return false
	}
	for _, r := range word {
		if r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// simplePlaceholderForks lets the plain words of a list share one state
// (simplePlaceholderToken); a test turns it off to compare both readings.
var simplePlaceholderForks = true

var simplePlaceholderSequence atomic.Uint64

// simplePlaceholderPrograms are the programs a body may run when its plain
// words share a state: each takes the word only as a file operand or as text
// it writes, and runs no program from its arguments.
var simplePlaceholderPrograms = []string{"cp", "mv", "rm", "ln", "sed", "tee", "echo", "printf", "cat", "touch",
	"mkdir", "chmod", "chown", "install", "truncate", "dd", "ls", "head", "tail"}

// simplePlaceholderToken returns the placeholder for the plain words of a
// loop over name, "" when the body does more with the variable than name a
// file operand: any command but the programs above, a substitution, a
// compound command, or an expansion of the name that is not the plain value.
// The token is a name the action does not spell.
func simplePlaceholderToken(body []*syntax.Stmt, name, source string) string {
	if !simplePlaceholderForks {
		return ""
	}
	safe := true
	for _, stmt := range body {
		syntax.Walk(stmt, func(node syntax.Node) bool {
			switch node := node.(type) {
			case nil:
			case *syntax.Stmt, *syntax.BinaryCmd, *syntax.Redirect, *syntax.Word, *syntax.Lit,
				*syntax.DblQuoted, *syntax.SglQuoted, *syntax.Assign:
			case *syntax.CallExpr:
				if len(node.Args) != 0 {
					program, static := simpleStaticWord(node.Args[0], nil)
					safe = safe && static && slices.Contains(simplePlaceholderPrograms, program)
				}
			case *syntax.ParamExp:
				safe = safe && node.Param != nil && (node.Param.Value != name ||
					node.Exp == nil && node.Repl == nil && node.Slice == nil && node.Index == nil && !node.Length &&
						!node.Excl && !node.IsSet && !node.Width && node.Names == 0 && node.Flags == nil &&
						node.NestedParam == nil && len(node.Modifiers) == 0)
			default:
				safe = false
			}
			return safe
		})
		if !safe {
			return ""
		}
	}
	for {
		token := "DCLOOPWORD" + strconv.FormatUint(simplePlaceholderSequence.Add(1), 36) + "X"
		if !strings.Contains(source, token) {
			return token
		}
	}
}

// simplePlainWords holds the plain words each placeholder stands for, in the
// order the walk met the placeholders: two walks of one action write their
// commands in the same order.
type simplePlainWords struct {
	tokens []string
	words  map[string][]string
}

func (plain *simplePlainWords) add(token, word string) {
	if plain.words == nil {
		plain.words = make(map[string][]string)
	}
	if _, met := plain.words[token]; !met {
		plain.tokens = append(plain.tokens, token)
	}
	if !slices.Contains(plain.words[token], word) {
		plain.words[token] = append(plain.words[token], word)
	}
}

// simpleExpandPlainWords writes each command that holds a placeholder once
// for every plain word it stands for. ok is false when the commands would
// pass maxSimpleEvaluations.
func simpleExpandPlainWords(commands []SimpleCommand, plain *simplePlainWords) ([]SimpleCommand, bool) {
	if len(plain.tokens) == 0 {
		return commands, true
	}
	var expanded []SimpleCommand
	for _, command := range commands {
		variants := []SimpleCommand{command}
		for _, token := range plain.tokens {
			var next []SimpleCommand
			for _, variant := range variants {
				if !strings.Contains(variant.Text, token) && !strings.Contains(variant.CWD, token) {
					next = append(next, variant)
					continue
				}
				for _, word := range plain.words[token] {
					written := variant
					written.Text, written.CWD = strings.ReplaceAll(variant.Text, token, word), strings.ReplaceAll(variant.CWD, token, word)
					next = append(next, written)
				}
			}
			variants = next
		}
		for _, variant := range variants {
			if !slices.Contains(expanded, variant) {
				expanded = append(expanded, variant)
			}
		}
		if len(expanded) > maxSimpleEvaluations {
			return nil, false
		}
	}
	return expanded, true
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

// reading is the value a read loop variable takes from one input word. read
// drops one trailing delimiter of its IFS (while IFS=r read -r d, fed
// aliasdir, reads aliasdi), only when that is the one delimiter in the word:
// with another, the variable keeps the word as it is.
func (bind simpleLoopBind) reading(value string) string {
	if last := len(value) - 1; last >= 0 && strings.IndexByte(bind.ifs, value[last]) >= 0 &&
		!strings.ContainsAny(value[:last], bind.ifs) {
		return value[:last]
	}
	return value
}

// simpleEnterForkedLoops forks the states at the start of each forked loop
// around part that the walk has not entered yet. A loop whose readings do not
// fit stays unread. ok is false when the scopes and the loops of part do not
// match.
func simpleEnterForkedLoops(states map[string][]simpleShellState, part sequenceStatement, unread map[string]bool, plain *simplePlainWords) bool {
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
		if forked, fits := simpleForkLoopBind(entry, binds[index], plain); fits {
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
	if word == nil || len(read.Assigns) == 0 && simpleIFSMayBeBound(file, loop, functionNames, read) {
		return simpleLoopBind{}, false
	}
	if text, static := simpleStaticWord(word, nil); static && (strings.HasPrefix(text, "-") || strings.Contains(text, "\\")) {
		return simpleLoopBind{}, false
	}
	return simpleLoopBind{name: name, items: []*syntax.Word{word}, fork: true, ifs: ifs,
		rebound: simpleReboundSpans(loop.Do, name, functionNames, nil)}, true
}

// simpleIFSMayBeBound reports code that can give IFS a value the walk does not
// read before the read of loop runs (a read with an IFS prefix of its own does
// not depend on it): code that starts before the loop, any
// code of the action when the loop runs again (inside a loop or a function),
// and a call of a declared function. The pipeline gives the read one line, so code
// after the loop, in its body, or in a function the action only declares
// does not change what the read reads.
func simpleIFSMayBeBound(file *syntax.File, loop *syntax.WhileClause, functionNames []string, read *syntax.CallExpr) bool {
	var stack []syntax.Node
	var repeats []syntax.Node
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if node == loop {
			for _, ancestor := range stack {
				switch ancestor.(type) {
				case *syntax.FuncDecl, *syntax.WhileClause, *syntax.ForClause:
					repeats = append(repeats, ancestor)
				}
			}
		}
		stack = append(stack, node)
		return true
	})
	start := int(loop.Pos().Offset())
	binds := false
	var visit func(node syntax.Node) bool
	visit = func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			// Declared code binds nothing until it is called, unless it is
			// the code the loop runs in.
			return slices.Contains(repeats, syntax.Node(node))
		case *syntax.CallExpr:
			if node == read {
				return false
			}
			if len(node.Args) != 0 {
				// The prefix assignments set the environment of the command.
				if simpleCallMayBind(node, "IFS", functionNames) {
					binds = binds || len(repeats) != 0 || int(node.Pos().Offset()) < start
				}
				for _, arg := range node.Args {
					syntax.Walk(arg, visit)
				}
				return false
			}
		}
		if simpleNodeBinds(node, "IFS") {
			binds = binds || len(repeats) != 0 || int(node.Pos().Offset()) < start
		}
		return !binds
	}
	syntax.Walk(file, visit)
	return binds
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
