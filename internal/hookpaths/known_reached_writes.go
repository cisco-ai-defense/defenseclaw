// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// knownReachedMaxReads bounds the statement readings of one compound
// command. Past it the reader reports an incomplete reading and the caller
// reads the whole statement as if every part may run.
const knownReachedMaxReads = 256

// knownReached reads a compound command of a tool call with known values in
// the order the shell runs it. Each statement is read with the value states
// that reach it, and a fixed for list body once for each item it reaches,
// with the item bound. A statement after an exit, a break or continue, or in
// a branch a static condition skips, is not read. A form it does not follow is read
// as if it may run. Only targets include accepts are kept.
type knownReached struct {
	cwd, home  string
	depth      int
	include    func(string) bool
	prelude    string
	steps      int
	reads      int
	incomplete bool
	writes     []string
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
// paths the shell can take through it. complete is false when the reading
// passed its bounds; continues is false when every path through root
// leaves the shell.
func knownReachedWrites(root *syntax.Stmt, file *syntax.File, states []actionValues, cwd, home string, depth int, include func(string) bool) (writes []string, complete, continues bool) {
	reader := &knownReached{cwd: cwd, home: home, depth: depth, include: include}
	// A call in a body reaches the function definitions of the command.
	var functions []*syntax.Stmt
	for _, stmt := range file.Stmts {
		if _, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
			functions = append(functions, stmt)
		}
	}
	if len(functions) > 0 {
		var source strings.Builder
		if syntax.NewPrinter().Print(&source, &syntax.File{Stmts: functions}) != nil {
			return nil, false, true
		}
		reader.prelude = source.String() + "\n"
	}
	flow := reader.statement(root, states)
	// A loop control outside a loop does not stop the shell.
	continues = len(flow.ended) != 0 || len(flow.continued) != 0 || len(flow.broken) != 0
	for _, beyond := range flow.beyond {
		continues = continues || len(beyond) != 0
	}
	return reader.writes, !reader.incomplete, continues
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
			r.incomplete = true
			return
		}
		found, _ := literalWriteOperandsWithParsedKnown(text, r.cwd, r.home, r.depth+1, nil, state, r.include)
		for _, target := range found {
			if r.include(target) {
				r.writes = append(r.writes, target)
			}
		}
	}
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
	next := actionUpdateValuesKept(stmt, states, r.cwd, r.home, &r.steps)
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
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(stmt.Redirs) == 0 && !stmt.Background && !stmt.Coprocess && !stmt.Negated {
			switch control, count := actionLoopControlCall(call, r.home); {
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
				// read on as if each outcome may follow.
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
		return r.forClause(command, states)
	case *syntax.WhileClause:
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
		if !fixed {
			// The body may run any number of times with any item.
			current := []actionValues{state}
			if loop, ok := clause.Loop.(*syntax.WordIter); ok && loop.Name != nil {
				unbound := maps.Clone(state)
				delete(unbound, loop.Name.Value)
				current = []actionValues{unbound}
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
