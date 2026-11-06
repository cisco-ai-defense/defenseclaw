// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A redirect is read at the point its statement executes. Each branch gets
// its own known values, so an assignment in one branch cannot certify a
// redirect in another, and a later reassignment replaces the earlier path.
type declaredRedirectWalker struct {
	cwd, home string
	paths     []string
	steps     int
	functions map[string]*syntax.Stmt
	// exhausted is set when the step budget or the candidate bound ran out,
	// so some redirect may not have been read with its known values.
	exhausted bool
}

func newDeclaredRedirectWalker(file *syntax.File, cwd, home string) *declaredRedirectWalker {
	walker := &declaredRedirectWalker{cwd: cwd, home: home, functions: map[string]*syntax.Stmt{}}
	seen := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		function, ok := node.(*syntax.FuncDecl)
		if !ok || function.Name == nil {
			return true
		}
		name := function.Name.Value
		if seen[name] {
			walker.functions[name] = nil // Multiple definitions need a richer state.
		} else {
			seen[name] = true
			walker.functions[name] = function.Body
		}
		return true
	})
	return walker
}

func (w *declaredRedirectWalker) walkList(stmts []*syntax.Stmt, states []actionValues, depth int) []actionValues {
	for _, stmt := range stmts {
		var next []actionValues
		for _, values := range states {
			next = actionAppendValueCandidates(next, w.walkStmt(stmt, values, depth))
		}
		states = next
		if actionKeptSaturated(states) {
			w.exhausted = true
		}
		if len(states) == 0 {
			break
		}
	}
	return states
}

func (w *declaredRedirectWalker) walkStmt(stmt *syntax.Stmt, values actionValues, depth int) []actionValues {
	if stmt == nil {
		return []actionValues{values}
	}
	if depth > 32 || w.steps >= actionMaxValueSteps {
		w.exhausted = true
		return []actionValues{values}
	}
	w.steps++
	if stmt.Background || stmt.Coprocess {
		copyStmt := *stmt
		copyStmt.Background, copyStmt.Coprocess = false, false
		w.walkStmt(&copyStmt, maps.Clone(values), depth+1)
		return []actionValues{values}
	}
	w.collect(stmt, values)
	w.substitutions(stmt, values, depth)
	switch command := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		if command.Op == syntax.Pipe || command.Op == syntax.PipeAll {
			w.walkStmt(command.X, maps.Clone(values), depth+1)
			w.walkStmt(command.Y, maps.Clone(values), depth+1)
			return []actionValues{values}
		}
		left := w.walkStmt(command.X, values, depth+1)
		truth := declaredRedirectTruth(command.X, w.home)
		var next []actionValues
		for _, candidate := range left {
			if truth == 0 || command.Op == syntax.AndStmt && truth < 0 || command.Op == syntax.OrStmt && truth > 0 {
				next = actionAppendValueCandidates(next, []actionValues{candidate})
			}
			if truth == 0 || command.Op == syntax.AndStmt && truth > 0 || command.Op == syntax.OrStmt && truth < 0 {
				next = actionAppendValueCandidates(next, w.walkStmt(command.Y, candidate, depth+1))
			}
		}
		return next
	case *syntax.Block:
		return w.walkList(command.Stmts, []actionValues{values}, depth+1)
	case *syntax.Subshell:
		w.walkList(command.Stmts, []actionValues{maps.Clone(values)}, depth+1)
		return []actionValues{values}
	case *syntax.IfClause:
		return w.walkIf(command, values, depth+1)
	case *syntax.WhileClause:
		condition := w.walkList(command.Cond, []actionValues{values}, depth+1)
		truth := 0
		if len(command.Cond) > 0 {
			truth = declaredRedirectTruth(command.Cond[len(command.Cond)-1], w.home)
		}
		if truth < 0 && !command.Until || truth > 0 && command.Until {
			return condition
		}
		return actionAppendValueCandidates(condition, w.walkList(command.Do, condition, depth+1))
	case *syntax.ForClause:
		return actionAppendValueCandidates([]actionValues{values}, w.walkList(command.Do, []actionValues{values}, depth+1))
	case *syntax.CaseClause:
		return w.walkCase(command, values, depth+1)
	case *syntax.TimeClause:
		return w.walkStmt(command.Stmt, values, depth+1)
	case *syntax.FuncDecl:
		return actionKeptStatement(stmt, values, w.cwd, w.home, &w.steps)
	case *syntax.CallExpr:
		if len(command.Args) > 0 {
			if name, known := StaticWord(command.Args[0], w.home); known && values[actionFunctionValuePrefix+name] != "" {
				if body := w.functions[name]; body != nil && depth < actionFunctionMaxDepth {
					return w.walkFunction(body, values, depth+1)
				}
			}
		}
	}
	return actionKeptStatement(stmt, values, w.cwd, w.home, &w.steps)
}

func (w *declaredRedirectWalker) collect(stmt *syntax.Stmt, values actionValues) {
	for _, redirect := range stmt.Redirs {
		if redirect.Word == nil || !actionOutputRedirect(redirect.Op) || !wordExpandsParameter(redirect.Word) {
			continue
		}
		if value, known := actionWordValue(redirect.Word, values, w.cwd, w.home); known && value != "" {
			name := OperandPath(value, w.cwd)
			if !slices.Contains(w.paths, name) {
				w.paths = append(w.paths, name)
			}
		}
	}
}

// Command substitutions execute in a child shell. Inspect their redirects
// with the current values, then discard assignments made inside them.
func (w *declaredRedirectWalker) substitutions(stmt *syntax.Stmt, values actionValues, depth int) {
	syntax.Walk(stmt, func(node syntax.Node) bool {
		if nested, ok := node.(*syntax.Stmt); ok && nested != stmt {
			return false // Compound children are walked in execution order.
		}
		if substitution, ok := node.(*syntax.CmdSubst); ok {
			w.walkList(substitution.Stmts, []actionValues{maps.Clone(values)}, depth+1)
			return false
		}
		return true
	})
}

func (w *declaredRedirectWalker) walkIf(clause *syntax.IfClause, values actionValues, depth int) []actionValues {
	if len(clause.Cond) == 0 {
		return w.walkList(clause.Then, []actionValues{values}, depth)
	}
	condition := w.walkList(clause.Cond, []actionValues{values}, depth)
	truth := declaredRedirectTruth(clause.Cond[len(clause.Cond)-1], w.home)
	var next []actionValues
	for _, candidate := range condition {
		if truth >= 0 {
			next = actionAppendValueCandidates(next, w.walkList(clause.Then, []actionValues{candidate}, depth))
		}
		if truth <= 0 {
			if clause.Else == nil {
				next = actionAppendValueCandidates(next, []actionValues{candidate})
			} else {
				next = actionAppendValueCandidates(next, w.walkIf(clause.Else, candidate, depth))
			}
		}
	}
	return next
}

func (w *declaredRedirectWalker) walkCase(clause *syntax.CaseClause, values actionValues, depth int) []actionValues {
	word, fixed := actionWordValue(clause.Word, values, w.cwd, w.home)
	var next []actionValues
	for _, item := range clause.Items {
		possible := !fixed
		definite := false
		for _, pattern := range item.Patterns {
			value, known := StaticWord(pattern, w.home)
			if !known {
				possible = true
			} else if !fixed || casePatternMatches(value, word) {
				possible = true
				definite = fixed
			}
		}
		if possible {
			next = actionAppendValueCandidates(next, w.walkList(item.Stmts, []actionValues{maps.Clone(values)}, depth))
		}
		if definite {
			return next // A static case word takes the first matching arm.
		}
	}
	return actionAppendValueCandidates(next, []actionValues{values})
}

func casePatternMatches(pattern, word string) bool {
	// Shell case patterns match slashes too; path.Match treats them as a
	// separator, so use an internal rune that is not a separator.
	matched, err := path.Match(strings.ReplaceAll(pattern, "/", "\x01"), strings.ReplaceAll(word, "/", "\x01"))
	return err == nil && matched
}

// A successful literal assignment carries its value into the next AND-list
// member. Preserve that result across a chain so a later ordinary-path
// reassignment supersedes an earlier protected path.
func declaredRedirectTruth(stmt *syntax.Stmt, home string) int {
	if truth := actionStaticCondition(stmt, home); truth != 0 {
		return truth
	}
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return 0
	}
	switch command := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(command.Args) == 0 && len(command.Assigns) > 0 {
			return 1
		}
		if len(command.Args) > 1 {
			name, known := StaticWord(command.Args[0], home)
			if known && (name == "export" || name == "declare" || name == "local" || name == "typeset") {
				for _, arg := range command.Args[1:] {
					word, fixed := StaticWord(arg, home)
					if !fixed || word == "" || word[0] == '-' {
						return 0
					}
				}
				return 1
			}
		}
	case *syntax.DeclClause:
		if len(command.Args) > 0 {
			return 1
		}
	case *syntax.BinaryCmd:
		left := declaredRedirectTruth(command.X, home)
		switch command.Op {
		case syntax.AndStmt:
			if left < 0 {
				return -1
			}
			if left > 0 {
				return declaredRedirectTruth(command.Y, home)
			}
		case syntax.OrStmt:
			if left > 0 {
				return 1
			}
			if left < 0 {
				return declaredRedirectTruth(command.Y, home)
			}
		}
	}
	return 0
}

func (w *declaredRedirectWalker) walkFunction(body *syntax.Stmt, values actionValues, depth int) []actionValues {
	var local []string
	syntax.Walk(body, func(node syntax.Node) bool {
		if declaration, ok := node.(*syntax.DeclClause); ok && declaration.Variant != nil {
			switch declaration.Variant.Value {
			case "local", "declare", "typeset":
				for _, assign := range declaration.Args {
					if assign.Name != nil {
						local = append(local, assign.Name.Value)
					}
				}
			}
		}
		return true
	})
	result := w.walkStmt(body, maps.Clone(values), depth)
	for _, after := range result {
		for _, name := range local {
			if previous, had := values[name]; had {
				after[name] = previous
			} else {
				delete(after, name)
			}
		}
	}
	return result
}

// When the ordered walk ran out of budget, list every value that any
// assignment in the command gives a redirect's variable. The client's link
// proof then decides; an ordinary path stays ordinary.
func (w *declaredRedirectWalker) anyAssignedValue(file *syntax.File) {
	base := actionValues{"HOME": w.home, "PWD": w.cwd}
	assigned := map[string][]string{}
	total := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		assign, ok := node.(*syntax.Assign)
		if !ok || assign.Name == nil || assign.Value == nil || assign.Array != nil || assign.Index != nil || total >= 256 {
			return true
		}
		if value, known := actionWordValue(assign.Value, base, w.cwd, w.home); known && value != "" {
			name := assign.Name.Value
			if !slices.Contains(assigned[name], value) {
				assigned[name] = append(assigned[name], value)
				total++
			}
		}
		return true
	})
	if total == 0 {
		return
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		redirect, ok := node.(*syntax.Redirect)
		if !ok || redirect.Word == nil || !actionOutputRedirect(redirect.Op) || !wordExpandsParameter(redirect.Word) || len(w.paths) >= 512 {
			return true
		}
		for name, list := range assigned {
			for _, candidate := range list {
				values := maps.Clone(base)
				values[name] = candidate
				if value, known := actionWordValue(redirect.Word, values, w.cwd, w.home); known && value != "" {
					if path := OperandPath(value, w.cwd); !slices.Contains(w.paths, path) {
						w.paths = append(w.paths, path)
					}
				}
			}
		}
		return true
	})
}
