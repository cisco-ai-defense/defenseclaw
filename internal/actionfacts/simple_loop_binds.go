// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

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

// simpleReboundSpans returns where in stmts, the body of a loop, name holds
// another value than the loop gave it for certain: after a statement that
// runs on every pass through the body and binds it again (u=x, export u=x,
// read u). Code that may or may not run (a branch, the right side of && or ||,
// a case arm, a nested loop, a function body, a subshell or a pipeline stage)
// and code the walk cannot read (eval, a function call, a program named by a
// variable) end nothing: the walk keeps both values of a branch it reads, and
// a binding it cannot follow is no reason to leave a write through the name
// unjudged (rel-1-0-6:GAP-0880 review 3).
func simpleReboundSpans(stmts []*syntax.Stmt, name string) []simpleSpan {
	if len(stmts) == 0 {
		return nil
	}
	end := int(stmts[len(stmts)-1].End().Offset())
	var spans []simpleSpan
	var visit func(stmt *syntax.Stmt)
	visit = func(stmt *syntax.Stmt) {
		if stmt == nil || stmt.Background || stmt.Coprocess {
			return
		}
		binds := false
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			binds = simpleCallBinds(cmd, name)
		case *syntax.DeclClause:
			binds = slices.ContainsFunc(cmd.Args, func(arg *syntax.Assign) bool {
				return arg.Name != nil && arg.Name.Value == name && !arg.Naked
			})
		case *syntax.Block:
			for _, inner := range cmd.Stmts {
				visit(inner)
			}
		case *syntax.BinaryCmd:
			// The left side always runs; the right side may not.
			if cmd.Op == syntax.AndStmt || cmd.Op == syntax.OrStmt {
				visit(cmd.X)
			}
		case *syntax.IfClause:
			for _, cond := range cmd.Cond {
				visit(cond)
			}
		case *syntax.WhileClause:
			for _, cond := range cmd.Cond {
				visit(cond)
			}
		}
		if binds {
			spans = append(spans, simpleSpan{int(stmt.Pos().Offset()) + 1, end})
		}
	}
	for _, stmt := range stmts {
		visit(stmt)
	}
	return spans
}

// simpleCallBinds reports a call that gives name another value as the call
// itself: a plain assignment (u=x), or read with name among its variables.
// A prefix assignment (u=x cmd) sets the environment of cmd only.
func simpleCallBinds(call *syntax.CallExpr, name string) bool {
	if len(call.Args) == 0 {
		return slices.ContainsFunc(call.Assigns, func(assign *syntax.Assign) bool {
			return assign.Name != nil && assign.Name.Value == name
		})
	}
	if program, static := simpleStaticWord(call.Args[0], nil); !static || program != "read" {
		return false
	}
	for index := 1; index < len(call.Args); index++ {
		value, static := simpleStaticWord(call.Args[index], nil)
		switch {
		case !static:
			return false
		case strings.HasPrefix(value, "-") && len(value) > 1:
			// An option that takes a word (-p prompt) consumes the next one.
			if strings.ContainsAny(value[len(value)-1:], "ptdnNui") {
				index++
			}
		case value == name:
			return true
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
			for _, reading := range bind.readings(value) {
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

// readings are the values a read loop variable takes from one input word,
// one for each IFS the read can have (ifs). read drops one trailing delimiter
// of its IFS (while IFS=r read -r d, fed aliasdir, reads aliasdi), only when
// that character is the one delimiter in the word: with another, the variable
// keeps the word as it is. A for loop (no ifs) reads the word.
func (bind simpleLoopBind) readings(value string) []string {
	if len(bind.ifs) == 0 {
		return []string{value}
	}
	var out []string
	for _, ifs := range bind.ifs {
		reading := value
		if last, size := utf8.DecodeLastRuneInString(value); size > 0 && last != utf8.RuneError &&
			strings.ContainsRune(ifs, last) && !strings.ContainsAny(value[:len(value)-size], ifs) {
			reading = value[:len(value)-size]
		}
		if !slices.Contains(out, reading) {
			out = append(out, reading)
		}
	}
	return out
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
// input is one static word: name takes that word, as an iteration of a for
// loop over it would. input is that word, from one static echo or printf
// stage before the loop or a here-string after it (simpleEchoWord). The read
// may have an IFS prefix (while IFS= read -r name). A backslash (read without
// -r reads it as an escape), other options and a longer input leave it
// unread.
func simpleReadLoopBind(loop *syntax.WhileClause, input *syntax.Word, file *syntax.File) (simpleLoopBind, bool) {
	if input == nil || loop.Until || len(loop.Cond) != 1 {
		return simpleLoopBind{}, false
	}
	read, ok := loop.Cond[0].Cmd.(*syntax.CallExpr)
	if !ok || loop.Cond[0].Negated || loop.Cond[0].Background || len(loop.Cond[0].Redirs) != 0 ||
		len(read.Args) < 2 || len(read.Args) > 3 {
		return simpleLoopBind{}, false
	}
	ifs, own, ok := simpleReadIFS(read.Assigns)
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
	if text, static := simpleStaticWord(input, nil); static && strings.Contains(text, "\\") {
		return simpleLoopBind{}, false
	}
	// A read with an IFS of its own reads with that one; any other read has
	// the default IFS, or one the action assigned anywhere (simpleIFSValues).
	sets := []string{ifs}
	if !own {
		sets = simpleIFSValues(file)
	}
	return simpleLoopBind{name: name, items: []*syntax.Word{input}, fork: true, ifs: sets,
		rebound: simpleReboundSpans(loop.Do, name)}, true
}

// simpleEchoWord returns the one word that a static echo or printf stage
// writes, nil for any other stage: the input a read loop after a pipe reads.
func simpleEchoWord(input *syntax.Stmt) *syntax.Word {
	if input == nil || input.Negated || input.Background || len(input.Redirs) != 0 {
		return nil
	}
	echo, ok := input.Cmd.(*syntax.CallExpr)
	if !ok || len(echo.Assigns) != 0 || len(echo.Args) < 2 {
		return nil
	}
	program, static := simpleStaticWord(echo.Args[0], nil)
	if !static {
		return nil
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
	if word == nil {
		return nil
	}
	// echo takes a leading -n, -e or -E as an option.
	if text, static := simpleStaticWord(word, nil); static && strings.HasPrefix(text, "-") {
		return nil
	}
	return word
}

// simpleIFSValues returns the values IFS can have where a read without an IFS
// of its own runs: the default (written as an empty value here, which strips
// nothing a word of the loop spells) and every static value the action assigns
// it (IFS=x, export IFS=x). An assignment the walk cannot read adds none, and
// a prefix assignment (IFS=x cmd) sets the environment of cmd only. The
// readings of all of them are kept: where a branch or the order decides which
// IFS the read has, the write is judged under each.
func simpleIFSValues(file *syntax.File) []string {
	values := []string{""}
	add := func(assign *syntax.Assign) {
		if assign.Name == nil || assign.Name.Value != "IFS" || assign.Append || assign.Array != nil || assign.Index != nil {
			return
		}
		value := ""
		if assign.Value != nil {
			var static bool
			if value, static = simpleStaticWord(assign.Value, nil); !static {
				return
			}
		}
		if !slices.Contains(values, value) {
			values = append(values, value)
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				for _, assign := range node.Assigns {
					add(assign)
				}
			}
		case *syntax.DeclClause:
			for _, assign := range node.Args {
				add(assign)
			}
		}
		return true
	})
	return values
}

// simpleReadIFS returns the IFS a read call sets for itself with a prefix
// assignment, and whether it sets one. Any other prefix is not read (ok is
// false).
func simpleReadIFS(assigns []*syntax.Assign) (ifs string, own, ok bool) {
	switch len(assigns) {
	case 0:
		return "", false, true
	case 1:
		assign := assigns[0]
		if assign.Name == nil || assign.Name.Value != "IFS" || assign.Append || assign.Naked ||
			assign.Array != nil || assign.Index != nil {
			return "", false, false
		}
		if assign.Value == nil {
			return "", true, true
		}
		value, static := simpleStaticWord(assign.Value, nil)
		return value, true, static
	}
	return "", false, false
}
