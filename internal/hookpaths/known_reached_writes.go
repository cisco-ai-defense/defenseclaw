// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// knownReachedMaxReads bounds the full statement readings of one compound
// command. Past it the reader keeps following the shell but reads each
// statement by the words it expands (knownReached.assume), which closes on
// every protected value that reaches a statement instead of losing it.
const knownReachedMaxReads = 256

// knownReached reads a compound command of a tool call with known values in
// the order the shell runs it. Each statement is read with the value states
// that reach it, and a fixed for list body once for each item it reaches,
// with the item bound. A statement after an exit, a break or continue, or in
// a branch a static condition skips, is not read. A form it does not follow
// is read as if it may run. Only targets include accepts are kept.
//
// The flow it follows rests on the meaning of exit, break, continue, true,
// false and ":". Once a statement it reaches can redefine one of them
// (knownShadow), that name is renamed in the parsed command, so the reader
// sees an unknown command from then on and reads every statement as if it
// may run. A function body is read only when a state that reaches the call
// has the definition, so a definition in a branch the shell skips, or made
// after the call, is not a call target. A function body is scanned for
// redefinitions only where the command calls the function. The body of a for
// loop over a list the command fixes is scanned statement by statement in the
// order the shell runs it, so a definition the shell does not reach before a
// guard changes nothing for it; a loop that may run any number of times is
// scanned whole before its first pass.
type knownReached struct {
	cwd, home   string
	depth       int
	include     func(string) bool
	shadow      *knownShadow
	definitions []*knownFunction
	ifsAssigned bool
	loops       int
	inexact     bool
	steps       int
	reads       int
	incomplete  bool
	writes      []string
}

// knownFunction is a function definition of the command and its printed
// source, which is printed again when a rename changes it.
type knownFunction struct {
	decl    *syntax.FuncDecl
	stmt    *syntax.Stmt
	text    string
	version int
}

// knownShadowable names the builtins whose result the reader reads from the
// command word alone.
var knownShadowable = map[string]bool{"exit": true, "break": true, "continue": true, "true": true, "false": true, ":": true}

// knownShadowPrefix starts the name a renamed builtin or function has in the
// parsed command.
const knownShadowPrefix = "shadowed-"

// knownUnshadowed returns the name a function had before a rename, which the
// tables built from the command before the reading are keyed by.
func knownUnshadowed(name string) string {
	if original := strings.TrimPrefix(name, knownShadowPrefix); knownShadowable[original] {
		return original
	}
	return name
}

// knownShadow follows the commands that can give one of those builtins
// another meaning, in the order the shell reaches them: a function of that
// name, or a command that defines or enables names at run time (alias, enable,
// source, a computed command word, or eval of text it cannot read). An eval
// of fixed text redefines only the names that text defines. Each name it
// finds is renamed once, in the definitions and in the command words of the
// parsed command and of the eval texts it read, to a name with no meaning to
// the reader. The parsed command is changed in place; only the known-value
// reader, which parses its own copy, uses it.
//
// A call of a function scans the body of the definitions the shell can have
// made when it reaches the call (current): a definition the scan has not
// reached, one in a branch a static condition skips, and one a later
// definition the shell certainly runs has replaced, are not scanned, and the
// statements of a body are followed the way the reader follows the command.
// A statement is certainly run (maybe is zero) when the shell reaches it in
// straight-line order: not in a branch an unknown condition decides, a loop,
// a subshell, a background list, or the body of a function. A function of the
// name eval (sure) takes the place of the builtin, so the text of its call is
// not eval text, unless a command may have removed the function.
type knownShadow struct {
	trees      []*syntax.File
	home       string
	shadowed   map[string]bool
	current    map[string][]*syntax.FuncDecl
	sure       map[string]bool
	maybe      int
	scanned    map[*syntax.FuncDecl]int
	generation int
	opaque     bool
	bodies     int
	version    int
	depth      int
}

// knownShadowMaxBodies bounds the function bodies one command scans; past it
// every builtin counts as redefined.
const knownShadowMaxBodies = 512

func newKnownShadow(file *syntax.File, home string) *knownShadow {
	s := &knownShadow{home: home, shadowed: map[string]bool{}, current: map[string][]*syntax.FuncDecl{},
		sure: map[string]bool{}, scanned: map[*syntax.FuncDecl]int{}}
	s.trees = append(s.trees, file)
	return s
}

// reach records a definition the scan has reached: a call may run it from now
// on, and a definition the shell certainly runs replaces the earlier ones.
func (s *knownShadow) reach(function *syntax.FuncDecl, certain bool) {
	name := knownUnshadowed(function.Name.Value)
	known := s.current[name]
	if certain {
		s.sure[name] = true
		if len(known) == 1 && known[0] == function {
			return
		}
		s.current[name] = []*syntax.FuncDecl{function}
	} else if slices.Contains(known, function) {
		return
	} else {
		s.current[name] = append(known, function)
	}
	s.generation++
}

// stamp changes whenever a rename changes the printed source of the command.
func (s *knownShadow) stamp() int {
	if s == nil {
		return 0
	}
	return s.version
}

// scan applies what every command inside node can redefine. The body of a
// function declared inside node runs only where a command calls it. When node
// is a statement the shell certainly runs, its own command is certain.
func (s *knownShadow) scan(node syntax.Node) {
	if s == nil || node == nil {
		return
	}
	var certain syntax.Node
	if stmt, ok := node.(*syntax.Stmt); ok && s.maybe == 0 && !stmt.Background && !stmt.Coprocess {
		certain = stmt.Cmd
	}
	syntax.Walk(node, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if node.Name != nil {
				if knownShadowable[node.Name.Value] && !s.keepsOutcome(node) {
					s.rename(node.Name.Value)
				}
				s.reach(node, node == certain)
			}
			return false
		case *syntax.CallExpr:
			s.call(node, node == certain)
		}
		return len(s.shadowed) != len(knownShadowable)
	})
}

// scanStmts scans a list the shell runs in order: a branch a static condition
// skips is not scanned, and nothing after a return or exit is. It reports
// whether the shell can run on past the list.
func (s *knownShadow) scanStmts(stmts []*syntax.Stmt) bool {
	for _, stmt := range stmts {
		if !s.scanStmt(stmt) {
			return false
		}
	}
	return true
}

// scanStmt scans one statement the way scanStmts does. Where it is not sure
// that the shell leaves, it reports that the shell goes on.
func (s *knownShadow) scanStmt(stmt *syntax.Stmt) bool {
	if stmt == nil || len(s.shadowed) == len(knownShadowable) {
		return true
	}
	for _, redirect := range stmt.Redirs {
		s.scan(redirect)
	}
	switch command := stmt.Cmd.(type) {
	case *syntax.Block:
		return s.scanStmts(command.Stmts)
	case *syntax.Subshell:
		s.possibly(func() { s.scanStmts(command.Stmts) })
	case *syntax.IfClause:
		return s.scanIf(command)
	case *syntax.WhileClause:
		if !s.scanStmts(command.Cond) {
			return false
		}
		truth := 0
		if len(command.Cond) > 0 {
			truth = actionStaticCondition(command.Cond[len(command.Cond)-1], s.home)
		}
		if command.Until {
			truth = -truth
		}
		if truth >= 0 {
			s.possibly(func() { s.passes(func() { s.scanStmts(command.Do); s.scanStmts(command.Cond) }) })
		}
	case *syntax.ForClause:
		s.scan(command.Loop)
		s.possibly(func() { s.passes(func() { s.scanStmts(command.Do) }) })
	case *syntax.CaseClause:
		s.scan(command.Word)
		s.possibly(func() {
			for _, item := range command.Items {
				s.scanStmts(item.Stmts)
			}
		})
	case *syntax.TimeClause:
		return s.scanStmt(command.Stmt)
	case *syntax.BinaryCmd:
		if command.Op != syntax.AndStmt && command.Op != syntax.OrStmt {
			s.scan(stmt)
			return true
		}
		if !s.scanStmt(command.X) {
			return false
		}
		truth := actionStaticCondition(command.X, s.home)
		and := command.Op == syntax.AndStmt
		skipped := truth == 0 || and && truth < 0 || !and && truth > 0
		if truth == 0 || and && truth > 0 || !and && truth < 0 {
			continues := false
			if truth == 0 {
				s.possibly(func() { continues = s.scanStmt(command.Y) })
			} else {
				continues = s.scanStmt(command.Y)
			}
			return continues || skipped
		}
	default:
		s.scan(stmt)
		return !s.leaves(stmt)
	}
	return true
}

// possibly runs a scan of statements the shell may or may not reach.
func (s *knownShadow) possibly(scan func()) {
	if s == nil {
		scan()
		return
	}
	s.maybe++
	defer func() { s.maybe-- }()
	scan()
}

// passes scans a loop body again while a pass has redefined something, as a
// later pass of the loop reaches what an earlier statement of the body
// redefines before its first statement.
func (s *knownShadow) passes(body func()) {
	for pass := 0; ; pass++ {
		generation := s.generation
		body()
		if s.generation == generation {
			return
		}
		if pass == 4 {
			s.renameAll()
			return
		}
	}
}

// leaves reports a statement that is a plain return or exit, after which the
// shell runs no further statement of the list it is in.
func (s *knownShadow) leaves(stmt *syntax.Stmt) bool {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Background || stmt.Coprocess || len(call.Args) == 0 || s.opaque {
		return false
	}
	name, known := StaticWord(call.Args[0], s.home)
	return known && (name == "exit" || name == "return" && len(s.current[name]) == 0)
}

func (s *knownShadow) scanIf(clause *syntax.IfClause) bool {
	if len(clause.Cond) == 0 { // else
		return s.scanStmts(clause.Then)
	}
	if !s.scanStmts(clause.Cond) {
		return false
	}
	truth := actionStaticCondition(clause.Cond[len(clause.Cond)-1], s.home)
	if truth == 0 {
		// An unknown condition: either branch may be the one that runs.
		s.maybe++
		defer func() { s.maybe-- }()
	}
	continues := false
	if truth >= 0 {
		continues = s.scanStmts(clause.Then)
	}
	if truth <= 0 {
		continues = clause.Else == nil || s.scanIf(clause.Else) || continues
	}
	return continues
}

// keepsOutcome reports a function of true, false or ":" that only runs the
// no-op builtins and ends with the outcome the builtin of that name has, so
// the reader's reading of a call by its word stays right. Its body is read
// where it is called like any other function.
func (s *knownShadow) keepsOutcome(function *syntax.FuncDecl) bool {
	name := function.Name.Value
	if name != "true" && name != "false" && name != ":" || function.Body == nil || function.Body.Background ||
		function.Body.Negated || function.Body.Coprocess || len(function.Body.Redirs) != 0 {
		return false
	}
	block, ok := function.Body.Cmd.(*syntax.Block)
	if !ok || len(block.Stmts) == 0 {
		return false
	}
	for _, stmt := range block.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || stmt.Background || stmt.Coprocess || len(call.Assigns) != 0 || len(call.Args) == 0 {
			return false
		}
		if program, known := StaticWord(call.Args[0], s.home); !known || program != "true" && program != "false" && program != ":" {
			return false
		}
	}
	last := block.Stmts[len(block.Stmts)-1]
	truth := actionStaticCondition(last, s.home)
	return name == "false" && truth < 0 || name != "false" && truth > 0
}

// call applies one command: the program word, through command and builtin,
// which skip a function of the name they are given. certain is true when the
// shell certainly runs the command.
func (s *knownShadow) call(call *syntax.CallExpr, certain bool) {
	args := call.Args
	skipsFunctions := false
	for len(args) > 0 {
		name, known := StaticWord(args[0], s.home)
		if !known {
			// The command word is computed: it may be eval or alias.
			if knownWordComputes(args[0]) {
				s.renameAll()
			}
			return
		}
		switch name {
		case "command", "builtin":
			skipsFunctions = true
			args = args[1:]
			for len(args) > 0 {
				option, fixed := StaticWord(args[0], s.home)
				if !fixed || !strings.HasPrefix(option, "-") {
					break
				}
				if name == "command" && option != "--" && strings.ContainsAny(option, "vV") {
					// command -v and command -V only describe the next word.
					return
				}
				args = args[1:]
			}
			continue
		case "eval":
			if !skipsFunctions {
				s.functionBodies(name, certain)
			}
			if skipsFunctions || !s.sure[name] {
				// A function of that name reads its arguments as parameters;
				// the builtin reads them as text.
				s.eval(args[1:], certain)
			}
		case "unset":
			if !skipsFunctions && s.sure[name] {
				// A function named unset runs in its place.
				s.functionBodies(name, certain)
				return
			}
			s.unset(args[1:])
		case "alias", "enable", "source", ".":
			s.renameAll()
		default:
			if !skipsFunctions {
				s.functionBodies(name, certain)
			}
		}
		return
	}
}

// unset applies a call of the builtin: a removed function gives the name back
// to the builtin. With -v or -n and no -f the operands are variables, so no
// function is removed; any other option, or none, can remove one.
func (s *knownShadow) unset(args []*syntax.Word) {
	variables, functions := false, false
	for len(args) > 0 {
		option, known := StaticWord(args[0], s.home)
		if !known || !strings.HasPrefix(option, "-") || option == "-" {
			break
		}
		args = args[1:]
		if option == "--" {
			break
		}
		variables = variables || strings.ContainsAny(option, "vn")
		functions = functions || strings.Contains(option, "f")
	}
	if variables && !functions {
		return
	}
	for _, arg := range args {
		if word, known := StaticWord(arg, s.home); known {
			delete(s.sure, word)
		} else {
			clear(s.sure)
		}
	}
}

// functionBodies applies what the definitions of a function a call can run
// redefine. The name may be the one a rename gave the function. A body is
// read again only after the scan has reached another definition or renamed
// another builtin, which can change what it reaches.
func (s *knownShadow) functionBodies(name string, certain bool) {
	name = knownUnshadowed(name)
	candidates := slices.Clone(s.current[name])
	// The body of the one definition the shell certainly made runs in
	// straight-line order unless it can return early.
	if certain && len(candidates) == 1 && s.sure[name] && !knownLeavesEarly(candidates[0].Body, s.home) {
		s.bodiesOf(candidates)
		return
	}
	s.possibly(func() { s.bodiesOf(candidates) })
}

func (s *knownShadow) bodiesOf(candidates []*syntax.FuncDecl) {
	for _, function := range candidates {
		if s.scanned[function] == s.generation+1 {
			continue
		}
		if s.bodies++; s.bodies > knownShadowMaxBodies {
			s.renameAll()
			return
		}
		s.scanned[function] = s.generation + 1
		s.scanStmt(function.Body)
	}
}

// knownWordComputes reports a word whose value the shell computes.
func knownWordComputes(word *syntax.Word) bool {
	computed := false
	syntax.Walk(word, func(node syntax.Node) bool {
		switch node.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst:
			computed = true
		}
		return !computed
	})
	return computed
}

// eval applies the commands of fixed eval text; any other text may define
// any name. Its definitions are certain when the eval is and the text has no
// return or loop control that can end it before its last command.
func (s *knownShadow) eval(args []*syntax.Word, certain bool) {
	words := make([]string, 0, len(args))
	for _, arg := range args {
		word, known := StaticWord(arg, s.home)
		if !known {
			s.renameAll()
			return
		}
		words = append(words, word)
	}
	parsed, ok := parseShell(strings.Join(words, " "))
	if !ok || s.depth >= 8 {
		s.renameAll()
		return
	}
	// The text reads the names renamed so far as the command does.
	s.trees = append(s.trees, parsed)
	s.renameTree(parsed, s.shadowed)
	s.depth++
	if certain && !knownLeavesEarly(parsed, s.home) {
		s.scanStmts(parsed.Stmts)
	} else {
		s.possibly(func() { s.scanStmts(parsed.Stmts) })
	}
	s.depth--
}

// knownLeavesEarly reports text with a return or a loop control, which can end
// it before its last command.
func knownLeavesEarly(tree syntax.Node, home string) bool {
	leaves := false
	knownWalkRun(tree, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) != 0 {
			name, known := StaticWord(call.Args[0], home)
			leaves = leaves || !known || name == "return" || name == "break" || name == "continue"
		}
		return !leaves
	})
	return leaves
}

// knownWalkRun visits the nodes the shell runs when it reaches the tree. A
// function definition runs none of its body: a return or loop control in it
// matters only where the function is called.
func knownWalkRun(tree syntax.Node, visit func(syntax.Node) bool) {
	syntax.Walk(tree, func(node syntax.Node) bool {
		if _, defines := node.(*syntax.FuncDecl); defines {
			return false
		}
		return visit(node)
	})
}

// calledFunctionsEndLoop reports that a function the loop can call has a loop
// control (or a command the reader cannot name), which ends the pass of the
// loop that calls it. A return only leaves the function, and a function the
// loop does not call changes nothing for it. Commands that run text or a
// handler the reader cannot follow (eval, trap, source) may call any function.
func (r *knownReached) calledFunctionsEndLoop(loop syntax.Node) bool {
	byName := map[string][]*syntax.FuncDecl{}
	for _, definition := range r.definitions {
		if definition.decl.Name != nil {
			name := knownUnshadowed(definition.decl.Name.Value)
			byName[name] = append(byName[name], definition.decl)
		}
	}
	seen := map[string]bool{}
	for pending := []syntax.Node{loop}; len(pending) != 0; {
		tree := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		var names []string
		anyFunction := false
		knownWalkRun(tree, func(node syntax.Node) bool {
			if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) != 0 {
				name, known := StaticWord(call.Args[0], r.home)
				switch name {
				case "eval", "trap", "source", ".", "alias":
					anyFunction = true
				}
				names = append(names, knownUnshadowed(name))
				anyFunction = anyFunction || !known
			}
			return true
		})
		if anyFunction {
			for _, decls := range byName {
				for _, decl := range decls {
					if knownBreaksOut(decl.Body, r.home) {
						return true
					}
				}
			}
			return false
		}
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
			for _, decl := range byName[name] {
				if knownBreaksOut(decl.Body, r.home) {
					return true
				}
				pending = append(pending, decl.Body)
			}
		}
	}
	return false
}

// knownBreaksOut reports a loop control or a command the reader cannot name
// in the tree of a function a loop calls.
func knownBreaksOut(tree syntax.Node, home string) bool {
	leaves := false
	knownWalkRun(tree, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) != 0 {
			name, known := StaticWord(call.Args[0], home)
			leaves = leaves || !known || name == "break" || name == "continue"
		}
		return !leaves
	})
	return leaves
}

func (s *knownShadow) renameAll() {
	// A name the reader does not rely on, such as return, may be redefined too.
	s.opaque = true
	var names []string
	for name := range knownShadowable {
		names = append(names, name)
	}
	s.rename(names...)
}

// rename gives the names that are not yet shadowed the unknown name.
func (s *knownShadow) rename(names ...string) {
	fresh := map[string]bool{}
	for _, name := range names {
		if !s.shadowed[name] {
			s.shadowed[name], fresh[name] = true, true
		}
	}
	if len(fresh) == 0 {
		return
	}
	s.version++
	s.generation++
	for _, tree := range s.trees {
		s.renameTree(tree, fresh)
	}
}

// renameTree renames the definitions and the command words of names in tree.
func (s *knownShadow) renameTree(tree *syntax.File, names map[string]bool) {
	if len(names) == 0 {
		return
	}
	syntax.Walk(tree, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if node.Name != nil && names[node.Name.Value] {
				node.Name.Value = knownShadowPrefix + node.Name.Value
			}
		case *syntax.CallExpr:
			if len(node.Args) != 0 {
				if name, known := StaticWord(node.Args[0], s.home); known && names[name] {
					node.Args[0].Parts = []syntax.WordPart{&syntax.Lit{Value: knownShadowPrefix + name}}
				}
			}
		}
		return true
	})
}

// knownReachedCompound reports a statement form the reader follows itself.
// Every other form is read as one statement by the shared writer reader.
func knownReachedCompound(stmt *syntax.Stmt) bool {
	switch command := stmt.Cmd.(type) {
	case *syntax.Block, *syntax.IfClause, *syntax.CaseClause, *syntax.ForClause, *syntax.WhileClause, *syntax.Subshell:
		return true
	case *syntax.BinaryCmd:
		return command.Op == syntax.AndStmt || command.Op == syntax.OrStmt
	case *syntax.TimeClause:
		return command.Stmt != nil
	}
	return false
}

// knownReachedWrites returns the targets root writes or changes on the
// paths the shell can take through it, and the value states that follow it.
// complete is false when the reading passed its bounds; continues is false
// when every path through root leaves the shell.
func knownReachedWrites(root *syntax.Stmt, file *syntax.File, states []actionValues, cwd, home string, depth int, include func(string) bool, shadow *knownShadow) (writes []string, after []actionValues, complete, continues bool) {
	reader := &knownReached{cwd: cwd, home: home, depth: depth, include: include, shadow: shadow}
	syntax.Walk(file, func(node syntax.Node) bool {
		if assign, ok := node.(*syntax.Assign); ok && assign.Name != nil && assign.Name.Value == "IFS" {
			reader.ifsAssigned = true
		}
		return !reader.ifsAssigned
	})
	// A call reaches the definitions the shell has made when it runs, in
	// whatever statement it makes them (r.prelude).
	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, ok := node.(*syntax.Stmt); ok {
			if function, ok := stmt.Cmd.(*syntax.FuncDecl); ok && function.Name != nil {
				reader.definitions = append(reader.definitions, &knownFunction{decl: function, stmt: stmt, version: -1})
				return false
			}
		}
		return true
	})
	flow := reader.statement(root, states)
	if reader.incomplete {
		// Past a bound the rest of the command was not followed: whatever it
		// redefines counts, and every protected value it may hold counts as
		// written.
		shadow.scan(root)
		for _, state := range states {
			reader.close(root, state)
		}
	}
	// A loop control outside a loop does not stop the shell.
	continues = len(flow.ended) != 0 || len(flow.continued) != 0 || len(flow.broken) != 0
	for _, beyond := range flow.beyond {
		continues = continues || len(beyond) != 0
	}
	if reader.inexact {
		return reader.writes, nil, !reader.incomplete, continues
	}
	return reader.writes, flow.ended, !reader.incomplete, continues
}

// knownExitStatement reports a plain exit, after which the shell runs no
// further statement of its list.
func knownExitStatement(stmt *syntax.Stmt, home string) bool {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(stmt.Redirs) != 0 || stmt.Background || stmt.Coprocess || len(call.Assigns) != 0 ||
		len(call.Args) == 0 || len(call.Args) > 2 {
		return false
	}
	name, known := StaticWord(call.Args[0], home)
	return known && name == "exit"
}

// read applies the shared writer reader to one statement for each state.
func (r *knownReached) read(stmt *syntax.Stmt, states []actionValues) {
	var source strings.Builder
	if syntax.NewPrinter().Print(&source, &syntax.File{Stmts: []*syntax.Stmt{stmt}}) != nil {
		r.incomplete = true
		return
	}
	for _, state := range states {
		if r.reads++; r.reads > knownReachedMaxReads {
			r.assume(stmt, state)
			continue
		}
		prelude, printed := r.prelude(state)
		if !printed {
			r.incomplete = true
			return
		}
		text := prelude + source.String()
		found, _ := literalWriteOperandsWithParsedKnown(text, r.cwd, r.home, r.depth+1, nil, state, r.include)
		for _, target := range found {
			if r.include(target) {
				r.writes = append(r.writes, target)
			}
		}
	}
}

// assume reads a statement past the reading bound by the words it expands:
// a word that expands to a protected target, in the statement or in a
// function it may call, counts as written. It reads more than the writers do
// (an echo of a protected path counts), but it never loses a protected value
// that reaches the statement.
func (r *knownReached) assume(stmt *syntax.Stmt, state actionValues) {
	check := func(root syntax.Node) {
		syntax.Walk(root, func(node syntax.Node) bool {
			if word, ok := node.(*syntax.Word); ok {
				if value, known := actionWordValue(word, state, r.cwd, r.home); known && r.include(OperandPath(value, r.cwd)) {
					r.writes = append(r.writes, value)
				}
			}
			return true
		})
	}
	check(stmt)
	for _, definition := range r.definitions {
		check(definition.decl)
	}
}

// prelude returns the source of the function definitions a state has: the
// ones the shell has made by the time it reaches the statement being read.
func (r *knownReached) prelude(state actionValues) (string, bool) {
	var out strings.Builder
	for _, definition := range r.definitions {
		if _, defined := state[actionFunctionValuePrefix+definition.decl.Name.Value]; !defined {
			continue
		}
		if stamp := r.shadow.stamp(); definition.version != stamp {
			var source strings.Builder
			if syntax.NewPrinter().Print(&source, &syntax.File{Stmts: []*syntax.Stmt{definition.stmt}}) != nil {
				return "", false
			}
			definition.text, definition.version = source.String()+"\n", stamp
		}
		out.WriteString(definition.text)
	}
	return out.String(), true
}

// function names the one definition of a function the command has, which a
// call of it runs. A name defined twice is not named.
func (r *knownReached) function(name string) *syntax.FuncDecl {
	var found *syntax.FuncDecl
	for _, definition := range r.definitions {
		if definition.decl.Name.Value == name {
			if found != nil {
				return nil
			}
			found = definition.decl
		}
	}
	return found
}

// close records the protected values a root the reader could not follow to
// its end may reach: a value in scope when it starts, or one its assignments
// build from those. Which statement uses one is not known, so the value
// counts as written; this blocks a long command that merely holds a protected
// value, which the reading could not clear.
func (r *knownReached) close(root *syntax.Stmt, state actionValues) {
	env := maps.Clone(state)
	check := func(value string) {
		if r.include(OperandPath(value, r.cwd)) {
			r.writes = append(r.writes, value)
		}
	}
	for name, value := range env {
		if !strings.HasPrefix(name, "\x00") {
			check(value)
		}
	}
	syntax.Walk(root, func(node syntax.Node) bool {
		if assign, ok := node.(*syntax.Assign); ok && assign.Name != nil && assign.Value != nil {
			if value, known := actionWordValue(assign.Value, env, r.cwd, r.home); known {
				env[assign.Name.Value] = value
				check(value)
			}
		}
		return true
	})
}

// redirects records the known output targets of a compound statement.
func (r *knownReached) redirects(stmt *syntax.Stmt, states []actionValues) {
	for _, redirect := range stmt.Redirs {
		if redirect.Word == nil || !actionOutputRedirect(redirect.Op) {
			continue
		}
		for _, state := range states {
			for _, read := range []func(*syntax.Word, actionValues, string, string) (string, bool){actionClientRedirectWordValue, actionOptionalEmptyPrefix} {
				if name, known := read(redirect.Word, state, r.cwd, r.home); known && r.include(OperandPath(name, r.cwd)) {
					r.writes = append(r.writes, OperandPath(name, r.cwd))
				}
			}
		}
	}
}

func (r *knownReached) update(stmt *syntax.Stmt, states []actionValues) []actionValues {
	next := actionKeepAcrossFunctionCall(stmt, states, actionUpdateValuesKept(stmt, states, r.cwd, r.home, &r.steps), r.function, r.cwd, r.home, &r.steps)
	if actionKeptSaturated(next) {
		r.incomplete = true
	}
	return next
}

func (r *knownReached) merge(a, b []actionValues) []actionValues {
	merged := actionAppendValueCandidates(a, b)
	if actionKeptSaturated(merged) {
		r.incomplete = true
	}
	return merged
}

func (r *knownReached) body(statements []*syntax.Stmt, states []actionValues) actionLoopFlow {
	var flow actionLoopFlow
	for _, stmt := range statements {
		if len(states) == 0 || r.incomplete {
			break
		}
		part := r.statement(stmt, states)
		flow.continued = r.merge(flow.continued, part.continued)
		flow.broken = r.merge(flow.broken, part.broken)
		for level, beyond := range part.beyond {
			flow.addBeyond(level, beyond)
		}
		states = part.ended
	}
	flow.ended = r.merge(nil, states)
	return flow
}

func (r *knownReached) statement(stmt *syntax.Stmt, states []actionValues) actionLoopFlow {
	if len(states) == 0 || r.incomplete {
		return actionLoopFlow{}
	}
	if !knownReachedCompound(stmt) {
		r.shadow.scan(stmt)
		if knownExitStatement(stmt, r.home) {
			return actionLoopFlow{}
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && r.loops > 0 && len(stmt.Redirs) == 0 && !stmt.Background && !stmt.Coprocess && !stmt.Negated {
			// A break or continue with no loop to leave does not stop the
			// shell, and a count past the loops it is in names the outermost.
			control, count := actionLoopControlCall(call, r.home)
			count = min(count, r.loops)
			switch {
			case control == "break" && count == 1:
				return actionLoopFlow{broken: r.merge(nil, states)}
			case control == "break":
				var flow actionLoopFlow
				flow.addBeyond(count-2, states)
				return flow
			case control == "continue" && count == 1:
				return actionLoopFlow{continued: r.merge(nil, states)}
			case control == "continue":
				// A counted continue leaves this loop for an enclosing one;
				// read on as if each outcome may follow. The states after
				// the statement are then not the ones the shell reaches.
				r.inexact = true
				return actionLoopFlow{ended: states, continued: states, broken: states}
			}
		}
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
			// Each side of a pipeline runs in its own subshell; the whole
			// pipeline keeps its own reading as well.
			for _, side := range []*syntax.Stmt{binary.X, binary.Y} {
				if knownReachedCompound(side) {
					r.possibly(func() { r.statement(side, states) })
				}
			}
		}
		if _, definition := stmt.Cmd.(*syntax.FuncDecl); !definition {
			r.read(stmt, states)
		}
		return actionLoopFlow{ended: r.update(stmt, states)}
	}
	r.redirects(stmt, states)
	if stmt.Background || stmt.Coprocess {
		// An asynchronous list runs in a subshell: its loop controls,
		// definitions and assignments do not reach the statements after it.
		r.possibly(func() { r.compound(stmt, states) })
		return actionLoopFlow{ended: states}
	}
	return r.compound(stmt, states)
}

// possibly reads statements the shell may or may not reach, or reaches in a
// subshell: what they define is not certain for the statements after them.
func (r *knownReached) possibly(read func()) {
	r.shadow.possibly(read)
}

func (r *knownReached) compound(stmt *syntax.Stmt, states []actionValues) actionLoopFlow {
	switch command := stmt.Cmd.(type) {
	case *syntax.Block:
		return r.body(command.Stmts, states)
	case *syntax.Subshell:
		r.possibly(func() { r.body(command.Stmts, states) })
		return actionLoopFlow{ended: states}
	case *syntax.TimeClause:
		return r.statement(command.Stmt, states)
	case *syntax.IfClause:
		return r.ifClause(command, states)
	case *syntax.CaseClause:
		var flow actionLoopFlow
		for _, state := range states {
			items, fixed := actionFixedCaseItems(command, state, r.cwd, r.home)
			if !fixed {
				// Any item, or none, may run.
				flow.ended = r.merge(flow.ended, []actionValues{state})
				items = command.Items
				for _, item := range items {
					r.possibly(func() { flow.add(r.body(item.Stmts, []actionValues{state})) })
				}
				continue
			}
			var selected []*syntax.Stmt
			for _, item := range items {
				selected = append(selected, item.Stmts...)
			}
			flow.add(r.body(selected, []actionValues{state}))
		}
		return flow
	case *syntax.BinaryCmd:
		left := r.statement(command.X, states)
		truth := actionStaticCondition(command.X, r.home)
		flow := actionLoopFlow{continued: left.continued, broken: left.broken}
		for level, beyond := range left.beyond {
			flow.addBeyond(level, beyond)
		}
		and := command.Op == syntax.AndStmt
		if truth == 0 || and && truth < 0 || !and && truth > 0 {
			flow.ended = r.merge(flow.ended, left.ended)
		}
		if truth == 0 || and && truth > 0 || !and && truth < 0 {
			if truth == 0 {
				r.possibly(func() { flow.add(r.statement(command.Y, left.ended)) })
			} else {
				flow.add(r.statement(command.Y, left.ended))
			}
		}
		return flow
	case *syntax.ForClause:
		r.loops++
		defer func() { r.loops-- }()
		return r.forClause(command, states)
	case *syntax.WhileClause:
		r.loops++
		defer func() { r.loops-- }()
		var flow actionLoopFlow
		r.possibly(func() { flow = r.whileClause(command, states) })
		return flow
	}
	r.incomplete = true
	return actionLoopFlow{}
}

func (r *knownReached) ifClause(clause *syntax.IfClause, states []actionValues) actionLoopFlow {
	if len(clause.Cond) == 0 { // else
		return r.body(clause.Then, states)
	}
	condition := r.body(clause.Cond, states)
	flow := actionLoopFlow{continued: condition.continued, broken: condition.broken}
	for level, beyond := range condition.beyond {
		flow.addBeyond(level, beyond)
	}
	truth := actionStaticCondition(clause.Cond[len(clause.Cond)-1], r.home)
	if truth == 0 {
		// An unknown condition: either branch may be the one that runs.
		r.possibly(func() { flow = r.branches(clause, flow, condition.ended, truth) })
		return flow
	}
	return r.branches(clause, flow, condition.ended, truth)
}

// branches reads the branches of an if clause a condition of the given truth
// leaves open.
func (r *knownReached) branches(clause *syntax.IfClause, flow actionLoopFlow, states []actionValues, truth int) actionLoopFlow {
	if truth >= 0 {
		flow.add(r.body(clause.Then, states))
	}
	if truth <= 0 {
		if clause.Else == nil {
			flow.ended = r.merge(flow.ended, states)
		} else {
			flow.add(r.ifClause(clause.Else, states))
		}
	}
	return flow
}

// leave adds the outcomes of one loop body run to the flow of the loop
// statement: a break ends the loop and a counted break leaves the enclosing
// loops it names.
func (r *knownReached) leave(flow *actionLoopFlow, part actionLoopFlow) {
	flow.ended = r.merge(flow.ended, part.broken)
	for level, escaped := range part.beyond {
		if level == 0 {
			flow.broken = r.merge(flow.broken, escaped)
		} else {
			flow.addBeyond(level-1, escaped)
		}
	}
}

func (r *knownReached) forClause(clause *syntax.ForClause, states []actionValues) actionLoopFlow {
	var flow actionLoopFlow
	// The body of a loop over a fixed list runs in order, once for each item,
	// unless a loop control or return can end a pass early.
	early := knownLeavesEarly(clause, r.home) || r.calledFunctionsEndLoop(clause)
	for _, state := range states {
		name, items, fixed := actionFixedForItems(clause, state, r.cwd, r.home)
		if _, set := state["IFS"]; fixed && !set && r.ifsAssigned {
			// An IFS the reader lost track of splits the list at unknown places.
			fixed = false
		}
		if !fixed {
			// The body may run any number of times with any item. An item
			// may be a whole listed value, which a field separator that
			// does not occur in it leaves as it is.
			current := []actionValues{state}
			if loop, ok := clause.Loop.(*syntax.WordIter); ok && loop.Name != nil {
				unbound := maps.Clone(state)
				delete(unbound, loop.Name.Value)
				current = []actionValues{unbound}
				for _, word := range loop.Items {
					if value, known := actionWordValue(word, state, r.cwd, r.home); known && len(current) < 17 {
						bound := maps.Clone(state)
						bound[loop.Name.Value] = value
						current = r.merge(current, []actionValues{bound})
					}
				}
			}
			flow.ended = r.merge(flow.ended, []actionValues{state})
			// A later pass reaches what the body redefines before its first
			// statement.
			r.possibly(func() {
				r.shadow.scan(clause)
				r.passes(&flow, clause.Do, current)
			})
			continue
		}
		current := []actionValues{state}
		for _, item := range items {
			if len(current) == 0 || r.incomplete {
				break
			}
			bound := make([]actionValues, 0, len(current))
			for _, value := range current {
				value = maps.Clone(value)
				value[name] = item
				bound = append(bound, value)
			}
			var part actionLoopFlow
			if early {
				r.possibly(func() { part = r.body(clause.Do, bound) })
			} else {
				part = r.body(clause.Do, bound)
			}
			r.leave(&flow, part)
			current = r.merge(part.ended, part.continued)
		}
		flow.ended = r.merge(flow.ended, current)
	}
	return flow
}

// passes reads a loop body that may run any number of times until no new
// value state reaches it; the loop may end after any pass.
func (r *knownReached) passes(flow *actionLoopFlow, body []*syntax.Stmt, current []actionValues) {
	var seen []actionValues
	for pass := 0; len(current) != 0 && !r.incomplete; pass++ {
		if !r.fresh(seen, current) {
			return
		}
		if pass == 4 {
			r.incomplete = true
			return
		}
		seen = r.merge(seen, current)
		part := r.body(body, current)
		r.leave(flow, part)
		current = r.merge(part.ended, part.continued)
		flow.ended = r.merge(flow.ended, current)
	}
}

func (r *knownReached) fresh(seen, current []actionValues) bool {
	for _, state := range current {
		if !slicesContainsValues(seen, state) {
			return true
		}
	}
	return false
}

func (r *knownReached) whileClause(clause *syntax.WhileClause, states []actionValues) actionLoopFlow {
	var flow actionLoopFlow
	truth := 0
	if len(clause.Cond) > 0 {
		truth = actionStaticCondition(clause.Cond[len(clause.Cond)-1], r.home)
	}
	if clause.Until {
		truth = -truth
	}
	entered := r.body(clause.Cond, states)
	r.leave(&flow, entered)
	if truth <= 0 {
		flow.ended = r.merge(flow.ended, entered.ended)
	}
	if truth < 0 {
		return flow
	}
	// A later pass reaches what the body redefines before its first
	// statement.
	r.shadow.scan(clause)
	var seen []actionValues
	current := entered.ended
	for pass := 0; len(current) != 0 && !r.incomplete; pass++ {
		if !r.fresh(seen, current) {
			break
		}
		if pass == 4 {
			r.incomplete = true
			break
		}
		seen = r.merge(seen, current)
		part := r.body(clause.Do, current)
		r.leave(&flow, part)
		again := r.body(clause.Cond, r.merge(part.ended, part.continued))
		r.leave(&flow, again)
		if truth == 0 {
			flow.ended = r.merge(flow.ended, again.ended)
		}
		current = again.ended
	}
	return flow
}

func slicesContainsValues(list []actionValues, values actionValues) bool {
	for _, prior := range list {
		if maps.Equal(prior, values) {
			return true
		}
	}
	return false
}
