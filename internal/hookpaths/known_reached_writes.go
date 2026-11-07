// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
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
// false and ":". A command that can redefine one of them has them renamed
// first (knownNeutralizeShadowed), so the reader sees an unknown command and
// reads every statement as if it may run.
type knownReached struct {
	cwd, home   string
	depth       int
	include     func(string) bool
	prelude     string
	functions   []*syntax.FuncDecl
	ifsAssigned bool
	loops       int
	inexact     bool
	steps       int
	reads       int
	incomplete  bool
	writes      []string
}

// knownShadowable names the builtins whose result the reader reads from the
// command word alone.
var knownShadowable = map[string]bool{"exit": true, "break": true, "continue": true, "true": true, "false": true, ":": true}

// knownNeutralizeShadowed renames the builtins the reader relies on, in the
// definitions and in the command words of a command that can redefine them,
// to a name with no meaning to the reader. The parsed command is changed in
// place; only the known-value reader, which parses its own copy, calls it.
func knownNeutralizeShadowed(file *syntax.File, home string) {
	if !knownFlowShadowed(file, home) {
		return
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if node.Name != nil && knownShadowable[node.Name.Value] {
				node.Name.Value = "shadowed-" + node.Name.Value
			}
		case *syntax.CallExpr:
			if len(node.Args) != 0 {
				if name, known := StaticWord(node.Args[0], home); known && knownShadowable[name] {
					node.Args[0].Parts = []syntax.WordPart{&syntax.Lit{Value: "shadowed-" + name}}
				}
			}
		}
		return true
	})
}

// knownFlowShadowed reports a command that may give one of the builtins the
// reader relies on another meaning: a function of that name, or a command
// that defines or enables names at run time. The static flow of such a
// command is not known, so its reading must not skip a statement.
func knownFlowShadowed(file *syntax.File, home string) bool {
	shadowed := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if node.Name != nil && knownShadowable[node.Name.Value] {
				shadowed = true
			}
		case *syntax.CallExpr:
			if len(node.Args) != 0 {
				switch name, known := StaticWord(node.Args[0], home); {
				case !known:
					// The command word is computed: it may be eval or alias.
					shadowed = shadowed || wordExpandsParameter(node.Args[0])
				case name == "eval" || name == "alias" || name == "enable" || name == "source" || name == ".":
					shadowed = true
				}
			}
		}
		return !shadowed
	})
	return shadowed
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
func knownReachedWrites(root *syntax.Stmt, file *syntax.File, states []actionValues, cwd, home string, depth int, include func(string) bool) (writes []string, after []actionValues, complete, continues bool) {
	reader := &knownReached{cwd: cwd, home: home, depth: depth, include: include}
	syntax.Walk(file, func(node syntax.Node) bool {
		if assign, ok := node.(*syntax.Assign); ok && assign.Name != nil && assign.Name.Value == "IFS" {
			reader.ifsAssigned = true
		}
		return !reader.ifsAssigned
	})
	// A call in a body reaches the function definitions of the command,
	// wherever it makes them.
	var functions []*syntax.Stmt
	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, ok := node.(*syntax.Stmt); ok {
			if function, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
				functions = append(functions, stmt)
				reader.functions = append(reader.functions, function)
				return false
			}
		}
		return true
	})
	if len(functions) > 0 {
		var source strings.Builder
		if syntax.NewPrinter().Print(&source, &syntax.File{Stmts: functions}) != nil {
			return nil, nil, false, true
		}
		reader.prelude = source.String() + "\n"
	}
	flow := reader.statement(root, states)
	if reader.incomplete {
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
	text := r.prelude + source.String()
	for _, state := range states {
		if r.reads++; r.reads > knownReachedMaxReads {
			r.assume(stmt, state)
			continue
		}
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
	for _, function := range r.functions {
		check(function)
	}
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
	next := actionKeepAcrossFunctionCall(stmt, states, actionUpdateValuesKept(stmt, states, r.cwd, r.home, &r.steps), r.home)
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
					r.statement(side, states)
				}
			}
		}
		if _, definition := stmt.Cmd.(*syntax.FuncDecl); !definition {
			r.read(stmt, states)
		}
		return actionLoopFlow{ended: r.update(stmt, states)}
	}
	r.redirects(stmt, states)
	flow := r.compound(stmt, states)
	if stmt.Background || stmt.Coprocess {
		// An asynchronous list runs in a subshell: its loop controls and
		// assignments do not reach the statements after it.
		return actionLoopFlow{ended: states}
	}
	return flow
}

func (r *knownReached) compound(stmt *syntax.Stmt, states []actionValues) actionLoopFlow {
	switch command := stmt.Cmd.(type) {
	case *syntax.Block:
		return r.body(command.Stmts, states)
	case *syntax.Subshell:
		r.body(command.Stmts, states)
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
					flow.add(r.body(item.Stmts, []actionValues{state}))
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
			flow.add(r.statement(command.Y, left.ended))
		}
		return flow
	case *syntax.ForClause:
		r.loops++
		defer func() { r.loops-- }()
		return r.forClause(command, states)
	case *syntax.WhileClause:
		r.loops++
		defer func() { r.loops-- }()
		return r.whileClause(command, states)
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
	if truth >= 0 {
		flow.add(r.body(clause.Then, condition.ended))
	}
	if truth <= 0 {
		if clause.Else == nil {
			flow.ended = r.merge(flow.ended, condition.ended)
		} else {
			flow.add(r.ifClause(clause.Else, condition.ended))
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
			r.passes(&flow, clause.Do, current)
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
			part := r.body(clause.Do, bound)
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
