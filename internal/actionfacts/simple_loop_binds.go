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

// simpleReboundAt reports a statement that starts where the loop variable
// holds another value than the loop gave it (simpleReboundSpans).
func (bind simpleLoopBind) reboundAt(offset int) bool {
	return slices.ContainsFunc(bind.rebound, func(span simpleSpan) bool { return offset >= span.from && offset < span.to })
}

// simpleBinder finds where code gives a variable another value for certain.
// order tells which call a function the action declares replaces: a function
// named read, printf, true, false or : that is declared before the call (or
// that an earlier pass or an earlier call of the enclosing function can have
// declared) replaces the builtin, so the call proves nothing about the
// variable.
type simpleBinder struct {
	name  string
	order *simpleScriptOrder
}

// simpleReboundSpans returns where in stmts, the body of a loop, name holds
// another value than the loop gave it for certain: the statements that run
// after code which binds it on every path (u=x, export u=x, read u, printf
// -v u, an if whose condition is true or whose branches all bind it, true &&
// u=x). Code that may or may not run, and code the walk cannot read (eval, a
// function call, a program named by a variable), ends nothing: the walk keeps
// both values, and a binding it cannot follow is no reason to leave a write
// through the name unjudged (rel-1-0-6:GAP-0880 review 3). A binding that
// certainly runs is no reason to keep a value the shell no longer has
// (review 4).
func simpleReboundSpans(stmts []*syntax.Stmt, name string, order *simpleScriptOrder) []simpleSpan {
	var spans []simpleSpan
	simpleBinder{name: name, order: order}.list(stmts, &spans)
	return spans
}

// list adds the spans of the statements of one list: after a statement that
// always binds the name, the rest of the list holds the other value.
func (b simpleBinder) list(stmts []*syntax.Stmt, spans *[]simpleSpan) {
	if len(stmts) == 0 {
		return
	}
	end := int(stmts[len(stmts)-1].End().Offset())
	for _, stmt := range stmts {
		b.stmt(stmt, spans)
		if b.always(stmt) {
			*spans = append(*spans, simpleSpan{int(stmt.End().Offset()), end})
		}
	}
}

// stmt adds the spans inside the lists and operands of a compound statement.
func (b simpleBinder) stmt(stmt *syntax.Stmt, spans *[]simpleSpan) {
	if stmt == nil {
		return
	}
	// after adds the span from the end of a part that always binds the name
	// to the end of the compound statement it is part of.
	after := func(part *syntax.Stmt, to syntax.Pos) {
		if b.always(part) {
			*spans = append(*spans, simpleSpan{int(part.End().Offset()), int(to.Offset())})
		}
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.Block:
		b.list(cmd.Stmts, spans)
	case *syntax.Subshell:
		b.list(cmd.Stmts, spans)
	case *syntax.BinaryCmd:
		b.stmt(cmd.X, spans)
		b.stmt(cmd.Y, spans)
		if cmd.Op == syntax.AndStmt || cmd.Op == syntax.OrStmt {
			after(cmd.X, cmd.End())
		}
	case *syntax.IfClause:
		for clause := cmd; clause != nil; clause = clause.Else {
			for _, cond := range clause.Cond {
				b.stmt(cond, spans)
				after(cond, cmd.End())
			}
			b.list(clause.Then, spans)
		}
	case *syntax.WhileClause:
		for _, cond := range cmd.Cond {
			b.stmt(cond, spans)
			after(cond, cmd.End())
		}
		b.list(cmd.Do, spans)
	case *syntax.ForClause:
		b.list(cmd.Do, spans)
	case *syntax.CaseClause:
		for _, item := range cmd.Items {
			b.list(item.Stmts, spans)
		}
	case *syntax.FuncDecl:
		b.stmt(cmd.Body, spans)
	case *syntax.TimeClause:
		b.stmt(cmd.Stmt, spans)
	}
}

// always reports a statement after which the name has another value on every
// path through it.
func (b simpleBinder) always(stmt *syntax.Stmt) bool {
	if stmt == nil || stmt.Background || stmt.Coprocess {
		return false
	}
	// A redirection that fails ends the command before it runs, whatever it
	// would have bound; only a command that is a bare assignment still sets
	// its variables.
	if call, ok := stmt.Cmd.(*syntax.CallExpr); (!ok || len(call.Args) != 0) && !simpleRedirectsHold(stmt.Redirs) {
		return false
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		return b.callBinds(cmd)
	case *syntax.DeclClause:
		return b.declBinds(cmd)
	case *syntax.Block:
		return b.anyAlways(cmd.Stmts)
	case *syntax.TimeClause:
		return b.always(cmd.Stmt)
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.AndStmt:
			return b.always(cmd.X) || b.status(cmd.X) == 0 && b.always(cmd.Y)
		case syntax.OrStmt:
			return b.always(cmd.X) || b.status(cmd.X) == 1 && b.always(cmd.Y)
		}
	case *syntax.IfClause:
		return b.ifAlways(cmd)
	case *syntax.WhileClause:
		// The condition runs at least once.
		return b.anyAlways(cmd.Cond)
	case *syntax.CaseClause:
		// Every arm binds it and one arm takes any word.
		hasDefault := false
		for _, item := range cmd.Items {
			if !b.anyAlways(item.Stmts) {
				return false
			}
			hasDefault = hasDefault || len(item.Patterns) == 1 && item.Patterns[0].Lit() == "*"
		}
		return hasDefault
	}
	return false
}

func (b simpleBinder) anyAlways(stmts []*syntax.Stmt) bool {
	return slices.ContainsFunc(stmts, b.always)
}

// ifAlways reports an if whose condition binds the name, or whose branch that
// runs does: the branch of a condition that is certainly true or false, or
// every branch when the condition is not known.
func (b simpleBinder) ifAlways(clause *syntax.IfClause) bool {
	if b.anyAlways(clause.Cond) {
		return true
	}
	then := b.anyAlways(clause.Then)
	if len(clause.Cond) == 0 {
		return then
	}
	other := clause.Else != nil && b.ifAlways(clause.Else)
	switch b.status(clause.Cond[len(clause.Cond)-1]) {
	case 0:
		return then
	case 1:
		return other
	}
	return then && other
}

// status returns the exit status of a statement that is certainly true (0) or
// false (1): the true and false builtins and :, not shadowed by a function,
// with no redirect that could fail. Any other statement is -1.
func (b simpleBinder) status(stmt *syntax.Stmt) int {
	program, status := simpleLiteralStatus(stmt)
	if status < 0 || b.order.shadows(program, stmt) {
		return -1
	}
	return status
}

// simpleLiteralStatus returns the program of a statement that is the true or
// false builtin or : with no redirect, and the exit status it has when no
// function replaces it. Any other statement has status -1.
func simpleLiteralStatus(stmt *syntax.Stmt) (program string, status int) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Background || stmt.Coprocess || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return "", -1
	}
	program, static := simpleStaticWord(call.Args[0], nil)
	if !static {
		return "", -1
	}
	status = -1
	switch program {
	case "true", ":":
		status = 0
	case "false":
		status = 1
	}
	if stmt.Negated && status >= 0 {
		status = 1 - status
	}
	return program, status
}

// callBinds reports a call that gives the name another value as the call
// itself: a plain assignment (u=x), read with the name among its variables,
// or printf -v name. A prefix assignment (u=x cmd) sets the environment of cmd
// only.
func (b simpleBinder) callBinds(call *syntax.CallExpr) bool {
	if len(call.Args) == 0 {
		return slices.ContainsFunc(call.Assigns, func(assign *syntax.Assign) bool {
			return assign.Name != nil && assign.Name.Value == b.name
		})
	}
	program, static := simpleStaticWord(call.Args[0], nil)
	if !static || b.order.shadows(program, call) {
		return false
	}
	switch program {
	case "printf":
		// printf -v name format: without the format it sets nothing.
		if len(call.Args) < 4 {
			return false
		}
		option, static := simpleStaticWord(call.Args[1], nil)
		target, named := simpleStaticWord(call.Args[2], nil)
		return static && named && option == "-v" && target == b.name
	case "read":
		for index := 1; index < len(call.Args); index++ {
			value, static := simpleStaticWord(call.Args[index], nil)
			switch {
			case !static:
				return false
			case strings.HasPrefix(value, "-") && len(value) > 1:
				// Only -r and -s read a line into the names. With another option
				// (a prompt, a timeout, a delimiter, a count, a descriptor) the
				// read may end without setting them.
				if strings.Trim(value[1:], "rs") != "" {
					return false
				}
			case value == b.name:
				return true
			}
		}
	}
	return false
}

// declBinds reports a declaration (export u=x, readonly, declare) that gives
// the name a value. local binds only inside a function.
func (b simpleBinder) declBinds(decl *syntax.DeclClause) bool {
	if decl.Variant != nil && decl.Variant.Value == "local" && !b.order.inFunction(decl) {
		return false
	}
	return slices.ContainsFunc(decl.Args, func(arg *syntax.Assign) bool {
		return arg.Name != nil && arg.Name.Value == b.name && !arg.Naked
	})
}

// simpleReadWord is the value that a read of a here-string leaves in its
// variable.
type simpleReadWord struct{ name, word string }

// simpleHereStringRead returns the variable and value of read [-r] name <<<
// word, for one plain word, the default IFS and the builtin: the shell holds
// the word in name from the next statement on. via is the chain of calls that
// run the function the read is in, outermost first (empty at the top level):
// the read has the state of that call. The walk then reads a write through the
// name as the path it names, instead of as an unresolved variable. Any other
// form is left unread.
func simpleHereStringRead(call *syntax.CallExpr, redirs []*syntax.Redirect, order func() *simpleScriptOrder, via []*syntax.CallExpr) *simpleReadWord {
	if len(redirs) != 1 || redirs[0].Op != syntax.WordHdoc || redirs[0].N != nil {
		return nil
	}
	name, word, ok := HereStringRead(call, redirs[0].Word)
	if !ok {
		return nil
	}
	if !order().readsHereString(call, via) {
		return nil
	}
	return &simpleReadWord{name: name, word: word}
}

// readsHereString reports a call of read that runs the builtin with the
// default IFS: no function of that name can replace it (shadows) and no IFS
// reaches it (ifsReachesAt). Without via, that must hold in every run of the
// call; with the chain of calls that run it, in the run that chain makes.
func (order *simpleScriptOrder) readsHereString(call *syntax.CallExpr, via []*syntax.CallExpr) bool {
	runs := order.runsVia(call, via)
	return !order.ifsReachesAt(call, runs) && !order.shadowsAt("read", call, runs)
}

// ReadBindsHereString returns a test for a call of read whose here-string
// word is the value of its variable: whether the builtin runs, with the
// default IFS, in every run of the call (all), and in at least one (some). A
// function that is called twice runs its read twice, with the state of each
// call. It reads file once, so it stays right while the caller rewrites
// statements. straight is Input.LoopBindsStraightLine.
func ReadBindsHereString(file *syntax.File, straight bool) func(call *syntax.CallExpr) (all, some bool) {
	order := newSimpleScriptOrder(file, straight)
	return func(call *syntax.CallExpr) (all, some bool) {
		runs := order.runsAt(call)
		if !straight || len(runs) < 2 {
			reads := order.readsHereString(call, nil)
			return reads, reads
		}
		all = true
		for _, run := range runs {
			reads := !order.ifsReachesAt(call, []int{run}) && !order.shadowsAt("read", call, []int{run})
			all, some = all && reads, some || reads
		}
		return all, some
	}
}

// HereStringRead returns the variable and value of a call read [-r|-s] name
// whose input is the here-string word: one plain word (letters, digits and
// . / _ : @ % + , = -) that the default IFS leaves as it is. ok is false for
// any other call or word, and for USER and LOGNAME, which have their own
// rule. The caller checks the IFS, a function named read and the redirects
// (ReadBindsHereString).
func HereStringRead(call *syntax.CallExpr, word *syntax.Word) (name, value string, ok bool) {
	if call == nil || word == nil || len(call.Assigns) != 0 || len(call.Args) < 2 || len(call.Args) > 3 {
		return "", "", false
	}
	if program, static := simpleStaticWord(call.Args[0], nil); !static || program != "read" {
		return "", "", false
	}
	if len(call.Args) == 3 {
		if option, static := simpleStaticWord(call.Args[1], nil); !static || option != "-r" && option != "-s" {
			return "", "", false
		}
	}
	name, static := simpleStaticWord(call.Args[len(call.Args)-1], nil)
	if !static || !simpleVariableName(name) || slices.Contains(simpleUserNames, name) {
		return "", "", false
	}
	value, static = simpleStaticWord(word, nil)
	if !static || !simplePlainLiteral(value) {
		return "", "", false
	}
	return name, value, true
}

// simpleRedirectsHold reports redirections that cannot fail: a here-document
// or here-string, /dev/null, and a copy of a standard descriptor.
func simpleRedirectsHold(redirs []*syntax.Redirect) bool {
	for _, redir := range redirs {
		switch redir.Op {
		case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		case syntax.RdrIn, syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob:
			if target, static := simpleStaticWord(redir.Word, nil); !static || target != "/dev/null" {
				return false
			}
		case syntax.DplIn, syntax.DplOut:
			if target, static := simpleStaticWord(redir.Word, nil); !static || target != "0" && target != "1" && target != "2" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// simpleScriptOrder is the code of one call in source order: the functions it
// declares and the loops it runs. The shell runs a declaration where it
// stands, so only a call that comes after it, or one that a loop or a
// function can run again after it, meets the function.
type simpleScriptOrder struct {
	funcs []*syntax.FuncDecl
	loops []syntax.Node
	// ifs is set when the call spells the name IFS anywhere: its words then
	// split by a delimiter the walk does not know.
	ifs bool
	// straight is the straight-line reading (Input.LoopBindsStraightLine):
	// only a top-level statement before a call can replace a builtin of it or
	// set its IFS. top holds the declarations of such statements, and steps
	// the statements among them that spell IFS, in source order.
	straight bool
	top      map[*syntax.FuncDecl]bool
	steps    []simpleIFSStep
	// calls holds the calls with a command word, for the statement of the
	// script that runs a function (runsAt).
	calls []*syntax.CallExpr
	// dead holds the code the shell never runs for certain (simpleDeadSpans):
	// a call there is no run of its function.
	dead []simpleSpan
}

// simpleIFSStep is the IFS a straight-line reading holds after a top-level
// statement that spells the name: value, and exact false when the statement
// does more with it than set it (unset, eval, read IFS, an array or an
// append), so that no value is known.
type simpleIFSStep struct {
	end   int
	value string
	exact bool
}

func newSimpleScriptOrder(file *syntax.File, straight bool) *simpleScriptOrder {
	order := &simpleScriptOrder{straight: straight}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			order.funcs = append(order.funcs, node)
		case *syntax.ForClause, *syntax.WhileClause:
			order.loops = append(order.loops, node)
		case *syntax.CallExpr:
			if straight && len(node.Args) != 0 {
				order.calls = append(order.calls, node)
			}
		default:
			order.ifs = order.ifs || simpleNodeSpellsIFS(node)
		}
		return true
	})
	if straight {
		order.dead = order.deadSpans(file)
		order.top = make(map[*syntax.FuncDecl]bool)
		value, exact := "", true
		for _, stmt := range file.Stmts {
			switch cmd := stmt.Cmd.(type) {
			case *syntax.FuncDecl:
				order.top[cmd] = true
			case *syntax.CallExpr, *syntax.DeclClause:
				if simpleSpellsIFSIn(stmt) && simpleMayChangeIFS(stmt) {
					value, exact = simpleIFSAfter(stmt, value, exact)
					order.steps = append(order.steps, simpleIFSStep{end: int(stmt.End().Offset()), value: value, exact: exact})
				}
			}
		}
	}
	return order
}

// simpleMayChangeIFS reports a top-level statement that spells the name IFS
// and can change the IFS of the shell. An assignment of its own
// (IFS=x), a declaration (export IFS=x) and a builtin that sets, unsets or
// evaluates a variable can; the name as an argument of a command that only
// prints or runs (echo IFS=x, printf "%s" IFS=x, declare -p IFS), or as a
// prefix assignment of a command (IFS=x env true), leaves the IFS of the shell
// as it is.
func simpleMayChangeIFS(stmt *syntax.Stmt) bool {
	changes := false
	syntax.Walk(stmt, func(node syntax.Node) bool {
		// ${IFS:=x} assigns where it expands.
		if exp, ok := node.(*syntax.ParamExp); ok && exp.Param != nil && exp.Param.Value == "IFS" && exp.Exp != nil &&
			(exp.Exp.Op == syntax.AssignUnset || exp.Exp.Op == syntax.AssignUnsetOrNull) {
			changes = true
		}
		return !changes
	})
	if changes {
		return true
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		return len(cmd.Args) == 0 || simpleCallMayChangeIFS(cmd.Args)
	case *syntax.DeclClause:
		// declare reads its options up to the first name or assignment: -p, -f
		// and -F there print what they are given, and one after a name
		// (declare IFS=x -p) is no option.
		if cmd.Variant != nil && (cmd.Variant.Value == "declare" || cmd.Variant.Value == "typeset") {
			for _, arg := range cmd.Args {
				if arg.Name != nil || arg.Value == nil {
					break
				}
				option, static := simpleStaticWord(arg.Value, nil)
				if !static || !strings.HasPrefix(option, "-") || option == "--" {
					break
				}
				if strings.ContainsAny(option, "pfF") {
					return false
				}
			}
		}
	}
	return true
}

// simpleCallMayChangeIFS reports a command, given by its words, that can
// change the IFS of the shell.
func simpleCallMayChangeIFS(args []*syntax.Word) bool {
	program, static := simpleStaticWord(args[0], nil)
	if !static {
		return true
	}
	switch program {
	case "eval", "source", ".", "command", "builtin", "exec", "let":
		return true
	case "printf":
		// Only printf -v name (or -vname) assigns; the format and the rest are text.
		if len(args) < 2 {
			return false
		}
		option, static := simpleStaticWord(args[1], nil)
		if !static {
			return true
		}
		if !strings.HasPrefix(option, "-v") {
			return false
		}
		name := option[2:]
		if name == "" && len(args) > 2 {
			if name, static = simpleStaticWord(args[2], nil); !static {
				return true
			}
		}
		return simpleSpellsIFS(name)
	case "read", "unset", "mapfile", "readarray", "getopts", "wait", "declare", "typeset", "local", "export", "readonly":
		// These set or unset the variables they name.
		return simpleNamesIFS(args[1:])
	}
	return false
}

// simpleNamesIFS reports a word that names the variable IFS (IFS or IFS=x),
// or one the walk cannot read.
func simpleNamesIFS(args []*syntax.Word) bool {
	return slices.ContainsFunc(args, func(arg *syntax.Word) bool {
		name, static := simpleStaticWord(arg, nil)
		name, _, _ = strings.Cut(name, "=")
		return !static || name == "IFS"
	})
}

// simpleNodeSpellsIFS reports a node that is the name IFS.
func simpleNodeSpellsIFS(node syntax.Node) bool {
	switch node := node.(type) {
	case *syntax.Lit:
		return simpleSpellsIFS(node.Value)
	case *syntax.SglQuoted:
		return simpleSpellsIFS(node.Value)
	case *syntax.ParamExp:
		return node.Param != nil && node.Param.Value == "IFS"
	}
	return false
}

// simpleSpellsIFSIn reports code that spells the name IFS anywhere.
func simpleSpellsIFSIn(root syntax.Node) bool {
	spells := false
	syntax.Walk(root, func(node syntax.Node) bool {
		spells = spells || simpleNodeSpellsIFS(node)
		return !spells
	})
	return spells
}

// simpleIFSAfter returns the IFS after a top-level statement that spells the
// name, given the one before it: the value an assignment (IFS=x, export
// IFS=x) sets, and no known value (exact false) for any other statement,
// which may do more with it (unset, eval, read IFS, a command with an IFS
// argument). The default is written as the empty value, which strips nothing a
// word of a loop spells.
func simpleIFSAfter(stmt *syntax.Stmt, value string, exact bool) (string, bool) {
	if stmt.Background || stmt.Coprocess {
		return value, false
	}
	set := func(assign *syntax.Assign) {
		switch {
		case assign.Name == nil || assign.Name.Value != "IFS":
		case assign.Naked:
		case assign.Append || assign.Array != nil || assign.Index != nil:
			exact = false
		case assign.Value == nil:
			value = ""
		default:
			if static, known := simpleStaticWord(assign.Value, nil); known {
				value = static
			} else {
				exact = false
			}
		}
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(cmd.Args) == 0 {
			for _, assign := range cmd.Assigns {
				set(assign)
			}
			return value, exact
		}
	case *syntax.DeclClause:
		for _, assign := range cmd.Args {
			set(assign)
		}
		return value, exact
	}
	return value, false
}

// straightIFS returns the IFS that the top-level statements ending before the
// node runs leave, one for each run of the node (runsAt), and whether every
// one is known. A script read in full (not the straight-line reading) knows
// none.
func (order *simpleScriptOrder) straightIFS(node syntax.Node) (values []string, exact bool) {
	if !order.straight {
		return nil, false
	}
	exact = true
	for _, before := range order.runsAt(node) {
		value, known := "", true
		for _, step := range order.steps {
			if step.end > before {
				break
			}
			value, known = step.value, step.exact
		}
		exact = exact && known
		if !slices.Contains(values, value) {
			values = append(values, value)
		}
	}
	return values, exact
}

// ifsReachesAt reports a call whose IFS may not be the default: the call spells
// IFS, or, in the straight-line reading, a top-level statement before one of
// its runs does. Otherwise it spells it anywhere in the script. runs are the
// runs to judge (runsVia); nil is every run of the call.
func (order *simpleScriptOrder) ifsReachesAt(call syntax.Node, runs []int) bool {
	if !order.straight {
		return order.ifs
	}
	if simpleSpellsIFSIn(call) {
		return true
	}
	if runs == nil {
		runs = order.runsAt(call)
	}
	return slices.ContainsFunc(runs, func(before int) bool {
		return slices.ContainsFunc(order.steps, func(step simpleIFSStep) bool { return step.end <= before })
	})
}

// simpleSpellsIFS reports text with IFS as a name of its own: not inside a
// longer name, so a path that merely contains the letters is not one.
func simpleSpellsIFS(text string) bool {
	identifier := func(char byte) bool {
		return char == '_' || char >= '0' && char <= '9' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
	}
	for from := 0; ; {
		index := strings.Index(text[from:], "IFS")
		if index < 0 {
			return false
		}
		start, end := from+index, from+index+3
		if (start == 0 || !identifier(text[start-1])) && (end == len(text) || !identifier(text[end])) {
			return true
		}
		from = end
	}
}

// simpleWithin reports inner spelled inside outer.
func simpleWithin(outer, inner syntax.Node) bool {
	return outer.Pos().Offset() <= inner.Pos().Offset() && inner.End().Offset() <= outer.End().Offset()
}

// enclosing returns the innermost declared function whose body spells node,
// nil for the top level.
func (order *simpleScriptOrder) enclosing(node syntax.Node) *syntax.FuncDecl {
	var inner *syntax.FuncDecl
	for _, decl := range order.funcs {
		if simpleWithin(decl, node) && (inner == nil || simpleWithin(inner, decl)) {
			inner = decl
		}
	}
	return inner
}

// runsAt returns the offsets of the top-level statements in front of which
// the straight-line reading holds the shell when it runs node, one for each
// run. That is the node itself at the top level. The body of a function runs
// each time a call of the function does, with the state that call has (a
// later call can see a later state, and does not replace an earlier one); a
// call from the body of another function counts where that function runs. A
// call the shell never reaches (deadSpans, a function nothing calls) is no
// run. A function that no statement runs keeps the offset of its own code.
func (order *simpleScriptOrder) runsAt(node syntax.Node) []int {
	if at := order.runs(node, nil); len(at) != 0 {
		return at
	}
	return []int{int(node.Pos().Offset())}
}

// runsVia is runsAt for the run that the chain of calls via makes of the
// function node is in, outermost call first: the state is the one of the
// statement that makes the outermost call. It is nil, every run (runsAt), for
// a chain that is empty, one whose call the shell never reaches, or code
// outside a function.
func (order *simpleScriptOrder) runsVia(node syntax.Node, via []*syntax.CallExpr) []int {
	if !order.straight || len(via) == 0 || order.enclosing(node) == nil || order.enclosing(via[0]) != nil || order.neverRuns(via[0]) {
		return nil
	}
	return []int{int(via[0].Pos().Offset())}
}

func (order *simpleScriptOrder) runs(node syntax.Node, running []*syntax.FuncDecl) []int {
	decl := order.enclosing(node)
	if decl == nil || decl.Name == nil || slices.Contains(running, decl) {
		return []int{int(node.Pos().Offset())}
	}
	running = append(running, decl)
	var at []int
	for _, call := range order.calls {
		if name, static := simpleStaticWord(call.Args[0], nil); !static || name != decl.Name.Value || simpleWithin(decl, call) || order.neverRuns(call) {
			continue
		}
		// A call at the top level before the declaration runs no such function.
		if order.enclosing(call) == nil && call.Pos().Offset() < decl.End().Offset() {
			continue
		}
		for _, offset := range order.runs(call, running) {
			if !slices.Contains(at, offset) {
				at = append(at, offset)
			}
		}
	}
	return at
}

// neverRuns reports code inside a span the shell skips for certain.
func (order *simpleScriptOrder) neverRuns(node syntax.Node) bool {
	offset := int(node.Pos().Offset())
	return slices.ContainsFunc(order.dead, func(dead simpleSpan) bool { return offset >= dead.from && offset < dead.to })
}

// deadSpans returns where file holds code the shell never runs, for what the
// straight-line reading proves with the true and false builtins: the branch
// an if does not take, the right side of && after a command that fails and of
// || after one that succeeds, and the body of a loop whose condition never
// holds. A function of the name of such a builtin, wherever it is declared,
// ends the proof.
func (order *simpleScriptOrder) deadSpans(file *syntax.File) []simpleSpan {
	var spans []simpleSpan
	var status func(stmt *syntax.Stmt) int
	status = func(stmt *syntax.Stmt) int {
		result := -1
		if bin, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && !stmt.Background && !stmt.Coprocess && len(stmt.Redirs) == 0 {
			switch {
			case bin.Op == syntax.AndStmt && status(bin.X) == 1:
				result = 1
			case bin.Op == syntax.OrStmt && status(bin.X) == 0:
				result = 0
			}
			if result >= 0 && stmt.Negated {
				result = 1 - result
			}
			return result
		}
		program, result := simpleLiteralStatus(stmt)
		if result >= 0 && slices.ContainsFunc(order.funcs, func(decl *syntax.FuncDecl) bool { return decl.Name != nil && decl.Name.Value == program }) {
			return -1
		}
		return result
	}
	skip := func(from, to syntax.Node) {
		spans = append(spans, simpleSpan{int(from.Pos().Offset()), int(to.End().Offset())})
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.IfClause:
			if len(node.Cond) == 0 {
				break
			}
			switch status(node.Cond[len(node.Cond)-1]) {
			case 0:
				if node.Else != nil {
					skip(node.Else, node.Else)
				}
			case 1:
				if len(node.Then) != 0 {
					skip(node.Then[0], node.Then[len(node.Then)-1])
				}
			}
		case *syntax.BinaryCmd:
			if node.Op == syntax.AndStmt && status(node.X) == 1 || node.Op == syntax.OrStmt && status(node.X) == 0 {
				skip(node.Y, node.Y)
			}
		case *syntax.WhileClause:
			// The body of while never runs when the condition fails, that of
			// until when it succeeds.
			never := 1
			if node.Until {
				never = 0
			}
			if len(node.Cond) != 0 && len(node.Do) != 0 && status(node.Cond[len(node.Cond)-1]) == never {
				skip(node.Do[0], node.Do[len(node.Do)-1])
			}
		}
		return true
	})
	return spans
}

// inFunction reports code spelled in the body of a declared function.
func (order *simpleScriptOrder) inFunction(node syntax.Node) bool {
	return slices.ContainsFunc(order.funcs, func(decl *syntax.FuncDecl) bool { return simpleWithin(decl, node) })
}

// shadows reports a call of the builtin name that a function of that name can
// replace: one declared before the call, one declared in a loop that also
// runs the call (the next pass), and any in the action when the call is in a
// function body (the function may be called after the declaration). A
// declaration after the call, outside every such loop, replaces nothing the
// call runs. In the straight-line reading only a declaration that is a
// top-level statement before the call replaces it: a declaration in a
// function body, a branch or a loop, or after the call, is not followed.
func (order *simpleScriptOrder) shadows(name string, call syntax.Node) bool {
	return order.shadowsAt(name, call, nil)
}

// shadowsAt is shadows for the runs given (runsVia); nil is every run.
func (order *simpleScriptOrder) shadowsAt(name string, call syntax.Node, runs []int) bool {
	for _, decl := range order.funcs {
		if decl.Name == nil || decl.Name.Value != name {
			continue
		}
		if order.straight {
			if order.top[decl] {
				if runs == nil {
					runs = order.runsAt(call)
				}
				if slices.ContainsFunc(runs, func(at int) bool { return int(decl.Pos().Offset()) < at }) {
					return true
				}
			}
			continue
		}
		if decl.Pos().Offset() < call.Pos().Offset() || order.inFunction(call) ||
			slices.ContainsFunc(order.loops, func(loop syntax.Node) bool { return simpleWithin(loop, call) && simpleWithin(loop, decl) }) {
			return true
		}
	}
	return false
}

// calledFrom returns the declared functions that the code of root can call,
// directly or through the functions it calls. skip is not read.
func (order *simpleScriptOrder) calledFrom(root, skip syntax.Node) []*syntax.FuncDecl {
	var called []*syntax.FuncDecl
	var names []string
	pending := []syntax.Node{root}
	for len(pending) > 0 {
		next := pending[0]
		pending = pending[1:]
		syntax.Walk(next, func(node syntax.Node) bool {
			if node == skip {
				return false
			}
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if name, static := simpleStaticWord(call.Args[0], nil); static && !slices.Contains(names, name) {
				names = append(names, name)
				for _, decl := range order.funcs {
					if decl.Name != nil && decl.Name.Value == name {
						called = append(called, decl)
						pending = append(pending, decl.Body)
					}
				}
			}
			return true
		})
	}
	return called
}

// simpleForkLoopBind returns the states a forked loop starts its body with:
// each of entry as it is (the variable unread, as for a list the walk cannot
// read; not for a loop that is certain to read its word), and with the
// variable read once for every list word the walk can read. A word with several fields or a pattern is left to the first
// reading. When the readings would pass maxForkedStates the words that can
// name state come first; fits is false when not even one reading fits, and
// the variable then stays unread.
func simpleForkLoopBind(entry []simpleShellState, bind simpleLoopBind, plain *simplePlainWords) (forked []simpleShellState, fits bool) {
	room := maxForkedStates/len(entry) - 1
	if room < 1 {
		return nil, false
	}
	for _, prior := range entry {
		first := len(forked)
		if !bind.certain {
			forked = append(forked, prior)
		}
		type candidate struct {
			value string
			tier  int
		}
		var candidates []candidate
		var shared []string
		login := path.Base(prior.vars["HOME"])
		ifs := bind.readIFS(prior.vars)
		for _, word := range bind.items {
			value, known := simpleStaticWord(word, prior.vars)
			if !known || strings.ContainsAny(value, " \t\n*?[") {
				continue
			}
			for _, reading := range bind.readings(value, ifs) {
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
		if len(forked) == first {
			forked = append(forked, prior)
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
// one for each IFS the read can have (ifsValues, from readIFS). read drops one trailing delimiter
// of its IFS (while IFS=r read -r d, fed aliasdir, reads aliasdi), only when
// that character is the one delimiter in the word: with another, the variable
// keeps the word as it is. A for loop (no ifs) reads the word.
func (bind simpleLoopBind) readings(value string, ifsValues []string) []string {
	if len(ifsValues) == 0 {
		return []string{value}
	}
	var out []string
	for _, ifs := range ifsValues {
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
func simpleReadLoopBind(loop *syntax.WhileClause, input *syntax.Word, order *simpleScriptOrder, loops []syntax.Node) (simpleLoopBind, bool) {
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
	// A read with an IFS of its own reads with that one. In the straight-line
	// reading any other read has the IFS the top-level statements before the
	// loop leave, when they leave a known one. Else it has the IFS the walk
	// holds where the loop starts, and the ones the code around it can set
	// (readIFS).
	bind := simpleLoopBind{name: name, items: []*syntax.Word{input}, fork: true, read: true, fixedIFS: own,
		rebound: simpleReboundSpans(loop.Do, name, order)}
	if own {
		bind.ifs = []string{ifs}
	} else if values, exact := order.straightIFS(loop); exact {
		bind.fixedIFS, bind.ifs = true, values
	} else {
		bind.outerIFS = simpleEnclosingIFS(order, loops, loop)
	}
	bind.certain = order.straight && !order.shadows("read", read)
	return bind, true
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

// readIFS returns the IFS values a read can have where the walk starts the
// loop: the one IFS the read has (fixedIFS), or the value the walk holds
// for the state (the default, written as an empty value here, which strips
// nothing a word of the loop spells) and every static value an enclosing loop
// or function assigns, which an earlier pass may have left. Code the walk has
// not reached (after the loop, in the body, in a function it does not call
// yet) cannot reach the read. A for loop has none.
func (bind simpleLoopBind) readIFS(vars map[string]string) []string {
	if !bind.read {
		return nil
	}
	if bind.fixedIFS {
		return bind.ifs
	}
	sets := []string{vars["IFS"]}
	for _, assign := range bind.outerIFS {
		value := ""
		if assign.Value != nil {
			var known bool
			if value, known = simpleStaticWord(assign.Value, vars); !known {
				continue
			}
		}
		if !slices.Contains(sets, value) {
			sets = append(sets, value)
		}
	}
	return sets
}

// simpleEnclosingIFS returns the IFS assignments that can reach a read loop
// from code the walk meets after the loop: those in the outermost loop that
// can run again around it (the next pass), and in the functions that loop
// calls, directly or through other functions. A function that nothing in the
// loop calls, code after every enclosing loop, and the body of the read loop
// cannot reach the read. A for loop over one static word runs once and is no
// earlier pass.
func simpleEnclosingIFS(order *simpleScriptOrder, loops []syntax.Node, loop *syntax.WhileClause) []*syntax.Assign {
	var outer syntax.Node
	for _, enclosing := range loops {
		if clause, ok := enclosing.(*syntax.ForClause); ok {
			if iteration, ok := clause.Loop.(*syntax.WordIter); ok && len(iteration.Items) == 1 && simpleLiteralWord(iteration.Items[0]) {
				continue
			}
		}
		outer = enclosing
		break
	}
	if outer == nil {
		return nil
	}
	var assigns []*syntax.Assign
	add := func(assign *syntax.Assign) {
		if assign != nil && assign.Name != nil && assign.Name.Value == "IFS" && !assign.Append && !assign.Naked &&
			assign.Array == nil && assign.Index == nil && !slices.Contains(assigns, assign) {
			assigns = append(assigns, assign)
		}
	}
	// collect reads the assignments of root; a function declared inside it
	// counts only where it is called, and its local declarations are its own.
	collect := func(root syntax.Node, inFunction bool) {
		syntax.Walk(root, func(node syntax.Node) bool {
			switch node := node.(type) {
			case *syntax.WhileClause:
				return node != loop
			case *syntax.FuncDecl:
				return false
			case *syntax.CallExpr:
				if len(node.Args) == 0 {
					for _, assign := range node.Assigns {
						add(assign)
					}
				}
			case *syntax.DeclClause:
				if node.Variant != nil && (node.Variant.Value == "local" ||
					inFunction && (node.Variant.Value == "declare" || node.Variant.Value == "typeset")) {
					break
				}
				for _, assign := range node.Args {
					add(assign)
				}
			}
			return true
		})
	}
	collect(outer, false)
	for _, decl := range order.calledFrom(outer, loop) {
		collect(decl.Body, true)
	}
	return assigns
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
