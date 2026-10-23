// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// ShortCircuitListReduction returns a complete view of a partial POSIX
// action with && or || lists, read as if every command of each list runs.
// facts must be Analyze(input).
//
// A block stops the whole tool call before any of it runs, so a command that
// runs only when the one before it succeeds (&&) or fails (||) is judged as
// if it runs: a rule that blocks `a; b` also blocks `a && b` and `a || b`.
// The view is the analysis of a twin of the command in which each && or ||
// list is the sequence of its commands, one statement per line. It has every
// command of the action and every fact they own; it differs from the action
// only in that every command is certain to run and the parse is complete, so
// a caller may count a semantic result on it, match or not, for an
// expression that reads neither (semantic.Program.ListReductionSafe).
//
// The view is unavailable unless every statement of every list is plain (not
// negated, in the background or a coprocess), the command defines no
// function and has no here-document, the twin analysis is complete, and
// every command in it is a plain POSIX process with a static argv.
func ShortCircuitListReduction(input Input, facts Facts) (view Facts, ok bool) {
	return sequenceReduction(input, facts, false)
}

// CompoundCommandReduction returns a complete view of a partial POSIX action
// whose simple commands sit in compound commands, read as if each of them
// runs alone: a subshell, a { } group, the bodies and conditions of if,
// while, until, for and case, a negated or background statement, and && or ||
// lists. A block stops the whole tool call before any of it runs, so a rule
// that blocks `rm -rf /` also blocks `(rm -rf /)` and
// `if true; then rm -rf /; fi`. facts must be Analyze(input).
//
// The view is the analysis of a twin of the command in which each simple
// command is a statement of its own, with the redirects of the compound
// commands around it, and without an exit that only ends a subshell. A
// subshell or group no longer scopes the directory or variables of its
// commands there, and a loop runs its body once, so callers may count only a
// match on the view, for an expression that more commands cannot turn off.
//
// The view is unavailable when a for or case word runs a command, a
// statement is a coprocess, the command defines a function or has a
// here-document, the twin analysis is not complete, or a command in it is not
// a plain POSIX process with a static argv.
func CompoundCommandReduction(input Input, facts Facts) (view Facts, ok bool) {
	return sequenceReduction(input, facts, true)
}

// maxStatementsAlone bounds the commands evaluated in one action.
const maxStatementsAlone = 128

// withoutDescriptorDuplications returns statement without its descriptor
// duplications (2>&1, <&3, >&-), and reports whether it had any.
func withoutDescriptorDuplications(statement string) (string, bool) {
	file, ok := shellparse.Parse(statement)
	if !ok {
		return "", false
	}
	var cuts [][2]int
	syntax.Walk(file, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok &&
			(redirect.Op == syntax.DplIn || redirect.Op == syntax.DplOut) {
			cuts = append(cuts, [2]int{int(redirect.Pos().Offset()), int(redirect.End().Offset())})
		}
		return true
	})
	if len(cuts) == 0 {
		return "", false
	}
	// Walk visits redirects in source order; cut from the last.
	for index := len(cuts) - 1; index >= 0; index-- {
		start, end := cuts[index][0], cuts[index][1]
		if start < 0 || end <= start || end > len(statement) {
			return "", false
		}
		statement = statement[:start] + statement[end:]
	}
	return statement, true
}

// shellDirectoryCommands are the POSIX commands that change the directory of
// the shell that runs them or run text that may.
var shellDirectoryCommands = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "source": true, ".": true,
	"eval": true, "exec": true, "builtin": true, "command": true,
	"alias": true, "trap": true,
}

// ChangesShellDirectory reports whether command may change the directory
// later commands of its action run in: a POSIX command that changes it or
// runs text that may, or one whose program is not static. A PowerShell or
// cmd.exe script shares its caller's location, so there any command may.
func ChangesShellDirectory(command CommandFact) bool {
	if command.Dialect != DialectPOSIX {
		return true
	}
	program := strings.ToLower(strings.TrimSpace(command.Program))
	return program == "" || shellDirectoryCommands[program]
}

func sequenceReduction(input Input, facts Facts, compound bool) (view Facts, ok bool) {
	defer func() {
		if recover() != nil {
			view, ok = Facts{}, false
		}
	}()
	if facts.Parse.Status != StatusPartial || len(facts.Commands) == 0 ||
		!containsIssue(facts.Parse.Issues, IssueUnsupportedConstruct) {
		return Facts{}, false
	}
	original, capture := analyzeWithRedirectTargets(input, "")
	if original.Parse.Status != StatusPartial {
		return Facts{}, false
	}
	twinSource, ok := shortCircuitListSequence(capture.source, compound)
	if !ok {
		return Facts{}, false
	}
	twin, _ := analyzeWithRedirectTargets(input, twinSource)
	if !twin.Authoritative() && containsIssue(twin.Parse.Issues, IssueDynamicWord) {
		// A list member may be a plain pipeline. Resolve its home operands
		// after flattening the list, so the existing complete-facts check
		// still controls whether this projection can prove a rule.
		home, _ := normalizeActiveHome(input.ActiveHome)
		if trustedPOSIXHomeLiteral.MatchString(home) {
			if resolved, ok := homeResolvedSource(twinSource, home); ok {
				twin, _ = analyzeWithRedirectTargets(input, resolved)
			}
		}
	}
	if !twin.Authoritative() || len(twin.Parse.Issues) != 0 ||
		twin.Parse.Dialect != facts.Parse.Dialect || len(twin.Commands) == 0 {
		return Facts{}, false
	}
	for _, command := range twin.Commands {
		if !plainPOSIXProcess(command) {
			return Facts{}, false
		}
	}
	return twin, true
}

// shortCircuitListSequence returns source with each top-level && or || list
// replaced by its commands, one statement per line; with compound, also each
// subshell, group, if, while, until, for and case, and each negated or
// background statement (sequenceStatements). It declines a source with
// nothing to replace.
func shortCircuitListSequence(source string, compound bool) (string, bool) {
	statements, reduced, ok := sequenceStatements(source, compound)
	if !ok || !reduced {
		return "", false
	}
	return strings.Join(statements, "\n"), true
}

// sequenceStatements returns the statements of source with each top-level &&
// or || list replaced by its commands, and reports whether it replaced
// anything. With compound, it also replaces each subshell, group, if, while,
// until, for and case by the statements in it, and a negated or background
// statement by its command. A redirect of a replaced compound command is
// moved onto each statement in it, which then writes or reads what the
// compound command did, and an exit in a subshell, which ends only that
// subshell, is left out. It declines a source with a negated, background
// (unless compound) or coprocess statement in a list, one where a dropped
// word could run a command (a for or case word with a command substitution),
// and one where a statement could change what another runs (a function
// definition) or where cutting the text could lose input (a here-document).
func sequenceStatements(source string, compound bool) (statements []string, reduced, ok bool) {
	parts, reduced, ok := sequenceStatementDetails(source, compound, false)
	if !ok {
		return nil, false, false
	}
	statements = make([]string, 0, len(parts))
	for _, part := range parts {
		statements = append(statements, part.text)
	}
	return statements, reduced, true
}

type sequenceStatement struct {
	text, scope string
}

// sequenceStatementDetails is the one full-parser flattening step. The
// reductions retain ordinary pipelines as a unit; simple-command policy
// evaluation asks it to expose their individual stages too. Scope identifies
// statements whose shell directory and variables are shared.
func sequenceStatementDetails(source string, compound, allSimple bool) (statements []sequenceStatement, reduced, ok bool) {
	if source == "" {
		return nil, false, false
	}
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return nil, false, false
	}
	declined := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.FuncDecl:
			declined = declined || !allSimple
		case *syntax.Redirect:
			declined = declined || !allSimple &&
				(typed.Op == syntax.Hdoc || typed.Op == syntax.DashHdoc)
		}
		return !declined
	})
	if declined {
		return nil, false, false
	}
	statements = make([]sequenceStatement, 0, len(file.Stmts))
	text := func(from, to syntax.Pos) (string, bool) {
		start, end := int(from.Offset()), int(to.Offset())
		if start < 0 || end <= start || end > len(source) {
			return "", false
		}
		return source[start:end], true
	}
	// redirects are those of the compound commands being replaced, outermost
	// first, as text to append to each statement.
	var redirects []string
	functions := make(map[string]*syntax.Stmt)
	// exported are the functions this action exported. A child shell imports
	// them, so each body is judged once, at the first later command that may
	// start one and call it; an export alone runs nothing.
	var exported []string
	// isolated runs walk in a separate shell process (a subshell, pipeline
	// stage, substitution or background job): a function it defines or
	// exports is gone when it ends.
	isolated := func(walk func() bool) bool {
		savedFunctions, savedExported := maps.Clone(functions), slices.Clone(exported)
		defer func() { functions, exported = savedFunctions, savedExported }()
		return walk()
	}
	scope := "0"
	nextScope := 0
	childScope := func(sharedShell bool, walk func() bool) bool {
		parent := scope
		nextScope++
		kind := "s"
		if sharedShell {
			kind = "c"
		}
		scope = parent + "/" + kind + strconv.Itoa(nextScope)
		defer func() { scope = parent }()
		if !sharedShell {
			return isolated(walk)
		}
		return walk()
	}
	// keep adds the text of node, or of a command and its redirects.
	keep := func(node syntax.Node, redirs ...*syntax.Redirect) bool {
		from, to := node.Pos(), node.End()
		for _, redirect := range redirs {
			if redirect.Pos().Offset() < from.Offset() {
				from = redirect.Pos()
			}
			if redirect.End().Offset() > to.Offset() {
				to = redirect.End()
			}
		}
		statement, ok := text(from, to)
		if !ok {
			return false
		}
		for index := len(redirects) - 1; index >= 0; index-- {
			statement += " " + redirects[index]
		}
		statements = append(statements, sequenceStatement{text: statement, scope: scope})
		return true
	}
	subshells := 0
	functionDepth := 0
	var importedBodies []*syntax.Stmt
	var flatten func(stmt *syntax.Stmt) bool
	flattenAll := func(stmts []*syntax.Stmt) bool {
		for _, stmt := range stmts {
			if !flatten(stmt) {
				return false
			}
		}
		return true
	}
	flattenSubstitutions := func(node syntax.Node) bool {
		var nested [][]*syntax.Stmt
		syntax.Walk(node, func(part syntax.Node) bool {
			switch part := part.(type) {
			case *syntax.CmdSubst:
				nested = append(nested, part.Stmts)
				return false
			case *syntax.ProcSubst:
				nested = append(nested, part.Stmts)
				return false
			}
			return true
		})
		for _, stmts := range nested {
			subshells++
			ok := childScope(false, func() bool { return flattenAll(stmts) })
			subshells--
			if !ok {
				return false
			}
		}
		return true
	}
	// flattenCompound replaces a compound command by its statements. It
	// reports whether command is one it replaces, and whether that worked.
	flattenCompound := func(command syntax.Command) (replaced, ok bool) {
		switch typed := command.(type) {
		case *syntax.BinaryCmd:
			if typed.Op != syntax.AndStmt && typed.Op != syntax.OrStmt &&
				(!compound || (typed.Op != syntax.Pipe && typed.Op != syntax.PipeAll) ||
					!allSimple &&
						!pipelineHasCompoundCommand(typed)) {
				return false, false
			}
			if allSimple && (typed.Op == syntax.Pipe || typed.Op == syntax.PipeAll) {
				return true, childScope(false, func() bool { return flatten(typed.X) }) &&
					childScope(false, func() bool { return flatten(typed.Y) })
			}
			return true, flatten(typed.X) && flatten(typed.Y)
		}
		if !compound {
			return false, false
		}
		switch typed := command.(type) {
		case *syntax.FuncDecl:
			if !allSimple || typed.Name == nil || typed.Body == nil {
				return true, false
			}
			if pipe, ok := typed.Body.Cmd.(*syntax.BinaryCmd); ok &&
				(pipe.Op == syntax.Pipe || pipe.Op == syntax.PipeAll) {
				// The parser reads `f() { ...; } | cat` as a definition whose
				// body is the pipeline. Bash runs a pipeline whose first stage
				// defines f in its own subshell, so f is gone after it, and
				// the other stages run.
				var stages func(stmt *syntax.Stmt) bool
				stages = func(stmt *syntax.Stmt) bool {
					binary, ok := stmt.Cmd.(*syntax.BinaryCmd)
					if !ok || binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll {
						return true
					}
					return stages(binary.X) && childScope(false, func() bool { return flatten(binary.Y) })
				}
				return true, stages(typed.Body)
			}
			functions[typed.Name.Value] = typed.Body
			return true, true
		case *syntax.Subshell:
			subshells++
			defer func() { subshells-- }()
			return true, childScope(false, func() bool { return flattenAll(typed.Stmts) })
		case *syntax.Block:
			return true, flattenAll(typed.Stmts)
		case *syntax.TimeClause:
			if !allSimple || typed.Stmt == nil {
				return true, false
			}
			return true, flatten(typed.Stmt)
		case *syntax.IfClause:
			for clause := typed; clause != nil; clause = clause.Else {
				if !flattenAll(clause.Cond) || !childScope(true, func() bool { return flattenAll(clause.Then) }) {
					return true, false
				}
			}
			return true, true
		case *syntax.WhileClause:
			return true, flattenAll(typed.Cond) &&
				childScope(true, func() bool { return flattenAll(typed.Do) })
		case *syntax.ForClause:
			switch iteration := typed.Loop.(type) {
			case *syntax.WordIter:
				if !allSimple && !inertPOSIXWords(iteration.Items...) ||
					allSimple && !flattenSubstitutions(iteration) {
					return true, false
				}
			case *syntax.CStyleLoop:
				// Arithmetic can contain command substitutions. Those run while
				// evaluating the loop header, before its body.
				if !allSimple || !flattenSubstitutions(iteration) {
					return true, false
				}
			default:
				return true, false
			}
			return true, childScope(true, func() bool { return flattenAll(typed.Do) })
		case *syntax.CaseClause:
			if !allSimple && !inertPOSIXWords(typed.Word) ||
				allSimple && !flattenSubstitutions(typed.Word) {
				return true, false
			}
			for _, item := range typed.Items {
				if !allSimple && !inertPOSIXWords(item.Patterns...) {
					return true, false
				}
				if allSimple {
					for _, pattern := range item.Patterns {
						if !flattenSubstitutions(pattern) {
							return true, false
						}
					}
				}
				if !childScope(true, func() bool { return flattenAll(item.Stmts) }) {
					return true, false
				}
			}
			return true, true
		}
		return false, false
	}
	// flattenRedirected replaces the compound command of stmt with its
	// redirects moved onto the statements in it.
	flattenRedirected := func(stmt *syntax.Stmt) (replaced, ok bool) {
		if len(stmt.Redirs) == 0 {
			return flattenCompound(stmt.Cmd)
		}
		if !compound {
			return false, false
		}
		moved, ok := text(stmt.Redirs[0].Pos(), stmt.Redirs[len(stmt.Redirs)-1].End())
		if !ok {
			return false, false
		}
		saved := redirects
		redirects = append(redirects[:len(redirects):len(redirects)], moved)
		defer func() { redirects = saved }()
		return flattenCompound(stmt.Cmd)
	}
	flatten = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Coprocess || stmt.Disown {
			return false
		}
		if compound && subshells > 0 && !stmt.Negated && !stmt.Background &&
			len(stmt.Redirs) == 0 && subshellExit(stmt.Cmd) {
			reduced = true
			return true
		}
		if stmt.Negated || stmt.Background {
			if !compound {
				return false
			}
			reduced = true
			if allSimple && stmt.Background {
				// A background job is a subshell: what it defines stays there.
				replaced, ok := false, false
				isolated(func() bool {
					replaced, ok = flattenRedirected(stmt)
					return ok
				})
				if replaced {
					return ok
				}
			} else if replaced, ok := flattenRedirected(stmt); replaced {
				return ok
			}
			if allSimple && !flattenSubstitutions(stmt) {
				return false
			}
			return stmt.Cmd != nil && keep(stmt.Cmd, stmt.Redirs...)
		}
		if replaced, ok := flattenRedirected(stmt); replaced {
			reduced = true
			return ok
		}
		if stmt.Cmd == nil {
			if allSimple && !flattenSubstitutions(stmt) {
				return false
			}
			return len(stmt.Redirs) != 0 && keep(stmt.Redirs[0], stmt.Redirs...)
		}
		if allSimple && !flattenSubstitutions(stmt) {
			return false
		}
		if allSimple {
			if decl, ok := stmt.Cmd.(*syntax.DeclClause); ok && len(functions) != 0 &&
				(decl.Variant.Value == "export" || decl.Variant.Value == "declare" ||
					decl.Variant.Value == "typeset") {
				names, known := simpleExportedFunctionNames(decl)
				if !known {
					return false
				}
				for _, exportedName := range names {
					// Bash refuses to export a name that is not yet a function.
					if _, found := functions[exportedName]; found && !slices.Contains(exported, exportedName) {
						exported = append(exported, exportedName)
					}
				}
			}
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) != 0 {
				name, known := simpleFunctionCallName(call)
				if !known && len(functions) != 0 {
					// A runtime program word may name any function defined in
					// this action. No complete per-command view exists.
					return false
				}
				var bodies []*syntax.Stmt
				if body, found := functions[name]; found {
					bodies = append(bodies, body)
				}
				// command eval and builtin trap still run their text in this
				// shell, where function lookup applies again.
				effective := call
				if args, runs, known := simpleLookupBypassArgs(call.Args); known && runs {
					effective = &syntax.CallExpr{Args: args}
				}
				program, _ := simpleStaticWord(effective.Args[0], nil)
				_, _, trapAction, _ := simpleNestedScript(effective, nil, nil, nil)
				if (program == "eval" || program == "trap" && trapAction) && len(functions) != 0 {
					called, ok := simpleEvalFunctionNames(effective)
					if !ok {
						return false
					}
					for _, calledName := range called {
						if body, found := functions[calledName]; found && !slices.Contains(bodies, body) {
							bodies = append(bodies, body)
						}
					}
				}
				if len(bodies) != 0 {
					if functionDepth >= 8 || !keep(stmt.Cmd, stmt.Redirs...) {
						return false
					}
					reduced = true
					if len(stmt.Redirs) != 0 {
						moved, ok := text(stmt.Redirs[0].Pos(), stmt.Redirs[len(stmt.Redirs)-1].End())
						if !ok {
							return false
						}
						saved := redirects
						redirects = append(redirects[:len(redirects):len(redirects)], moved)
						defer func() { redirects = saved }()
					}
					for _, body := range bodies {
						if functionDepth >= 8 {
							return false
						}
						functionDepth++
						ok := flatten(body)
						functionDepth--
						if !ok {
							return false
						}
					}
					return true
				}
			}
		}
		// Not stmt itself, whose text may end in a ; that a moved redirect
		// cannot follow.
		if !keep(stmt.Cmd, stmt.Redirs...) {
			return false
		}
		call, isCall := stmt.Cmd.(*syntax.CallExpr)
		if !allSimple || len(exported) == 0 || !isCall ||
			!simpleMayImportExportedFunctions(call, source, exported) {
			return true
		}
		var bodies []*syntax.Stmt
		for _, exportedName := range exported {
			if body := functions[exportedName]; body != nil && !slices.Contains(importedBodies, body) {
				bodies = append(bodies, body)
			}
		}
		if len(bodies) == 0 {
			return true
		}
		importedBodies = append(importedBodies, bodies...)
		reduced = true
		if len(stmt.Redirs) != 0 {
			moved, ok := text(stmt.Redirs[0].Pos(), stmt.Redirs[len(stmt.Redirs)-1].End())
			if !ok {
				return false
			}
			saved := redirects
			redirects = append(redirects[:len(redirects):len(redirects)], moved)
			defer func() { redirects = saved }()
		}
		for _, body := range bodies {
			if functionDepth >= 8 {
				return false
			}
			// The body runs in the child shell: its exit, directory and
			// variables stay there.
			functionDepth++
			subshells++
			ok := childScope(false, func() bool { return flatten(body) })
			subshells--
			functionDepth--
			if !ok {
				return false
			}
		}
		return true
	}
	if !flattenAll(file.Stmts) {
		return nil, false, false
	}
	return statements, reduced, true
}

// eval parses its static script in the caller's shell. Function definitions
// from the enclosing action remain visible to calls inside that script.
func simpleEvalFunctionNames(call *syntax.CallExpr) ([]string, bool) {
	script, _, nested, static := simpleNestedScript(call, nil, nil, nil)
	if !nested || !static {
		return nil, false
	}
	file, ok := shellparse.Parse(script)
	if !ok {
		return nil, false
	}
	var names []string
	known := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, definition := node.(*syntax.FuncDecl); definition {
			return false
		}
		inner, call := node.(*syntax.CallExpr)
		if !call || len(inner.Args) == 0 {
			return true
		}
		name, ok := simpleFunctionCallName(inner)
		if !ok {
			known = false
			return false
		}
		names = append(names, name)
		return true
	})
	return names, known
}

// simpleExportedFunctionNames returns the functions an export, declare -fx
// or typeset -fx statement exports. Only a later command that may start a
// shell can run them (simpleMayImportExportedFunctions).
func simpleExportedFunctionNames(decl *syntax.DeclClause) ([]string, bool) {
	if decl == nil || len(decl.Args) == 0 {
		return nil, true
	}
	values := make([]string, 0, len(decl.Args))
	for _, arg := range decl.Args {
		if arg == nil {
			return nil, false
		}
		if arg.Name != nil && arg.Naked {
			values = append(values, arg.Name.Value)
			continue
		}
		if arg.Name == nil && arg.Value != nil {
			value, known := simpleStaticWord(arg.Value, nil)
			if !known {
				return nil, false
			}
			values = append(values, value)
			continue
		}
		return nil, false
	}
	index := 0
	exportFunctions := false
	exportAttribute := decl.Variant.Value == "export"
	unexport := false
	for index < len(values) {
		option := values[index]
		if option == "--" {
			index++
			break
		}
		if len(option) < 2 || option[0] != '-' {
			break
		}
		for _, flag := range option[1:] {
			if flag == 'f' {
				exportFunctions = true
			} else if flag == 'x' {
				exportAttribute = true
			} else if flag == 'n' {
				unexport = true
			} else if !strings.ContainsRune("np", flag) {
				return nil, false
			}
		}
		index++
	}
	if !exportFunctions || !exportAttribute || unexport {
		return nil, true
	}
	var names []string
	for ; index < len(values); index++ {
		name := values[index]
		if name == "" || strings.ContainsRune(name, '=') {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

// simpleFunctionCallName returns the name call looks up as a function, or ""
// when it calls none. A literal program word is one, and so is the word eval
// or time runs. command and builtin skip function lookup: the word after them
// runs a builtin or a program (command) or only a builtin (builtin), never a
// function. An eval after them still runs its text with function lookup.
func simpleFunctionCallName(call *syntax.CallExpr) (string, bool) {
	args, runs, known := simpleLookupBypassArgs(call.Args)
	if !known {
		return "", false
	}
	if !runs {
		return "", true
	}
	name, ok := simpleStaticWord(args[0], nil)
	if !ok {
		return "", false
	}
	if len(args) != len(call.Args) && name != "eval" {
		return "", true
	}
	switch name {
	case "eval", "time":
		index := 1
		for index < len(args) && strings.HasPrefix(args[index].Lit(), "-") {
			index++
		}
		if index == len(args) {
			return name, true
		}
		return simpleStaticWord(args[index], nil)
	}
	return name, true
}

// simpleLookupBypassArgs strips the command and builtin prefixes of args,
// which make the next word skip function lookup. runs is false when the call
// runs nothing: command -v or -V only describes a name, and a bare prefix or
// an unknown option is an error.
func simpleLookupBypassArgs(args []*syntax.Word) (rest []*syntax.Word, runs, known bool) {
	for len(args) != 0 {
		name, ok := simpleStaticWord(args[0], nil)
		if !ok || name != "command" && name != "builtin" {
			return args, true, true
		}
		index := 1
		for index < len(args) {
			option, ok := simpleStaticWord(args[index], nil)
			if !ok {
				return nil, false, false
			}
			if option == "--" {
				index++
				break
			}
			if len(option) < 2 || option[0] != '-' {
				break
			}
			if name == "builtin" || strings.Trim(option[1:], "p") != "" {
				return nil, false, true
			}
			index++
		}
		args = args[index:]
	}
	return nil, false, true
}

// pipelineHasCompoundCommand keeps an ordinary pipeline intact. Its data
// flow can be part of an exact rule's proof. A compound element needs its
// inner statements exposed to the match-only pass.
func pipelineHasCompoundCommand(binary *syntax.BinaryCmd) bool {
	var contains func(*syntax.Stmt) bool
	contains = func(stmt *syntax.Stmt) bool {
		if stmt == nil {
			return false
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.Subshell, *syntax.Block, *syntax.IfClause,
			*syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
			return true
		case *syntax.BinaryCmd:
			if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
				return contains(cmd.X) || contains(cmd.Y)
			}
		}
		return false
	}
	return contains(binary.X) || contains(binary.Y)
}

// subshellExit reports whether command is a plain exit, which in a subshell
// ends only the subshell.
func subshellExit(command syntax.Command) bool {
	call, ok := command.(*syntax.CallExpr)
	return ok && len(call.Assigns) == 0 && len(call.Args) != 0 &&
		call.Args[0].Lit() == "exit" && inertPOSIXWords(call.Args...)
}

// inertPOSIXWords reports whether words run no command when the shell
// expands them.
func inertPOSIXWords(words ...*syntax.Word) bool {
	inert := true
	for _, word := range words {
		syntax.Walk(word, func(node syntax.Node) bool {
			switch node.(type) {
			case *syntax.CmdSubst, *syntax.ProcSubst:
				inert = false
			}
			return inert
		})
	}
	return inert
}

// simpleNonSpawningBuiltins are shell builtins that start no process, so no
// shell that could import an exported function.
var simpleNonSpawningBuiltins = map[string]bool{
	":": true, "true": true, "false": true, "echo": true, "printf": true,
	"test": true, "[": true, "export": true, "declare": true, "typeset": true,
	"local": true, "readonly": true, "unset": true, "set": true, "shift": true,
	"read": true, "cd": true, "pwd": true, "return": true, "exit": true,
	"type": true, "hash": true, "alias": true, "unalias": true, "umask": true,
	"wait": true, "jobs": true, "getopts": true, "let": true, "shopt": true,
}

// simpleSystemProgramDirs hold system utilities. A program run by a path
// elsewhere may be a shell script.
var simpleSystemProgramDirs = []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"}

// simpleShellPrograms are the shells a child may be. Only a shell runs a
// function, so only shell text can call an exported one.
var simpleShellPrograms = map[string]bool{
	"sh": true, "bash": true, "rbash": true, "dash": true, "ksh": true,
	"mksh": true, "zsh": true, "ash": true, "busybox": true,
}

// simpleCommandRunners run a command or shell text taken from their argv, in
// a form the static wrapper walk does not resolve.
var simpleCommandRunners = map[string]bool{
	"xargs": true, "find": true, "parallel": true, "watch": true, "flock": true,
	"su": true, "runuser": true, "sg": true, "script": true, "strace": true,
	"ltrace": true, "nice": true, "ionice": true, "stdbuf": true, "setsid": true,
	"taskset": true, "chrt": true, "unshare": true, "doas": true, "pkexec": true,
	"systemd-run": true, "ssh-agent": true, "dbus-run-session": true,
	"tmux": true, "screen": true, "fakeroot": true, "unbuffer": true,
	"time": true, "caffeinate": true, "sandbox-exec": true, "firejail": true,
	"bwrap": true, "expect": true,
}

// simpleInlineInterpreters run inline code that may start a shell.
var simpleInlineInterpreters = map[string]bool{
	"python": true, "python2": true, "python3": true, "perl": true, "ruby": true,
	"node": true, "nodejs": true, "deno": true, "bun": true, "php": true,
	"lua": true, "awk": true, "gawk": true, "mawk": true, "nawk": true,
	"tclsh": true, "Rscript": true, "osascript": true, "pwsh": true,
	"powershell": true,
}

// simpleMayImportExportedFunctions reports whether call may start a shell
// that imports the exported functions of its action and calls one of them.
// Only a shell runs a function, so a function name counts only where shell
// text is: the script of a -c shell (also through env, sudo, nohup, timeout,
// exec, eval or trap), and what a command runner such as xargs, find -exec or
// watch hands to a shell. A shell whose script this walk cannot read (a
// script file, stdin, a runtime word) may call any of them, and so may a
// program run by a path outside the system directories or named like a shell
// script. An interpreter's inline code may start a shell, so a shell or
// function name in it counts. Any other argv word is data: ls f runs no f.
func simpleMayImportExportedFunctions(call *syntax.CallExpr, source string, exported []string) bool {
	if call == nil {
		return false
	}
	return simpleArgvMayCallExported(call.Args, source, exported, 0)
}

func simpleArgvMayCallExported(args []*syntax.Word, source string, exported []string, depth int) bool {
	if depth >= 8 {
		return true
	}
	args, runs, known := simpleLookupBypassArgs(args)
	if !known {
		return true
	}
	if !runs || len(args) == 0 {
		return false
	}
	program, static := simpleStaticWord(args[0], nil)
	if !static {
		// A runtime program, such as $SHELL, may be a shell.
		return true
	}
	if simpleNonSpawningBuiltins[program] {
		return false
	}
	if script, _, nested, scriptStatic := simpleNestedScriptArgs(args, nil, 0, nil, nil); nested {
		return !scriptStatic || simpleScriptMayCallExported(script, exported, depth+1)
	}
	base := path.Base(program)
	switch {
	case program == "eval" || program == "trap" || program == "source" || program == ".":
		// Runtime text, or a file whose text this walk cannot read.
		return true
	case simpleShellPrograms[base]:
		// A script file or stdin, unless the shell only checks syntax.
		return base == "busybox" || base == "rbash" || !simpleShellNoExec(args, nil, base)
	case strings.Contains(program, "/") && !slices.ContainsFunc(simpleSystemProgramDirs,
		func(dir string) bool { return strings.HasPrefix(program, dir) }),
		simpleShellScriptName(program):
		return true
	case simpleNestedWrapper(base):
		if child, ok := simpleWrapperChildArgs(args); ok {
			return simpleArgvMayCallExported(child, source, exported, depth+1)
		}
		return simpleRunnerMayCallExported(args[1:], source, exported, depth+1)
	case simpleCommandRunners[base]:
		return simpleRunnerMayCallExported(args[1:], source, exported, depth+1)
	case simpleInlineInterpreters[base]:
		return simpleWordsNameShellOrFunction(args[1:], source, exported, 1)
	}
	// Shell text inside a word, such as tmux new 'bash -c f'.
	return simpleWordsNameShellOrFunction(args[1:], source, exported, 2)
}

// simpleScriptMayCallExported reports whether shell text may call an exported
// function: a call of its name, or a command that may start a shell that does.
func simpleScriptMayCallExported(script string, exported []string, depth int) bool {
	if depth >= 8 {
		return true
	}
	file, ok := shellparse.Parse(script)
	if !ok {
		return true
	}
	calls := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if calls || !isCall || len(call.Args) == 0 {
			return !calls
		}
		name, known := simpleFunctionCallName(call)
		calls = !known || slices.Contains(exported, name) ||
			simpleArgvMayCallExported(call.Args, script, exported, depth)
		return !calls
	})
	return calls
}

// simpleRunnerMayCallExported reads the argv a command runner may hand to a
// shell: a shell and its arguments, an exported function name, a script path,
// shell text, or a {} that xargs, find or parallel replaces with input.
func simpleRunnerMayCallExported(words []*syntax.Word, source string, exported []string, depth int) bool {
	for index, word := range words {
		value, static := simpleStaticScriptWord(word, nil)
		if !static || strings.Contains(value, "{}") {
			// Runtime text, or a placeholder for an input item.
			return true
		}
		if simpleShellPrograms[path.Base(value)] {
			return simpleArgvMayCallExported(words[index:], source, exported, depth)
		}
		if slices.Contains(exported, value) || strings.HasPrefix(value, "./") ||
			strings.HasPrefix(value, "../") || simpleShellScriptName(value) {
			return true
		}
		if strings.ContainsAny(value, " \t\n;&|()<>`$") && simpleScriptMayCallExported(value, exported, depth+1) {
			return true
		}
	}
	return false
}

// simpleWordsNameShellOrFunction reports whether a word of argv, as written,
// names a shell, $SHELL or $BASH, a shell script or an exported function among
// at least minTokens program-name tokens.
func simpleWordsNameShellOrFunction(words []*syntax.Word, source string, exported []string, minTokens int) bool {
	for _, word := range words {
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start < 0 || end <= start || end > len(source) {
			// No text to read: assume the worst.
			return true
		}
		tokens := strings.FieldsFunc(source[start:end], simpleNotWordTokenRune)
		if len(tokens) < minTokens {
			continue
		}
		for _, token := range tokens {
			if base := path.Base(token); simpleShellPrograms[base] || base == "SHELL" || base == "BASH" ||
				simpleShellScriptName(token) || slices.Contains(exported, token) {
				return true
			}
		}
	}
	return false
}

// simpleShellScriptName reports a .sh or .bash name that is not a pattern.
func simpleShellScriptName(name string) bool {
	return (strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".bash")) &&
		!strings.ContainsAny(name, "*?[")
}

// simpleWrapperChildArgs returns the command a static wrapper argv runs.
func simpleWrapperChildArgs(args []*syntax.Word) ([]*syntax.Word, bool) {
	argv := make([]string, len(args))
	for index, arg := range args {
		value, known := simpleStaticScriptWord(arg, nil)
		if !known {
			return nil, false
		}
		argv[index] = value
	}
	index, found, uncertain := simpleWrapperChild(argv, path.Base(argv[0]))
	if !found || uncertain || index <= 0 || index >= len(args) {
		return nil, false
	}
	return args[index:], true
}

// simpleNotWordTokenRune separates the program-name and path tokens of an
// argv word, including those inside script text.
func simpleNotWordTokenRune(r rune) bool {
	return r != '_' && r != '.' && r != '/' && r != '-' && r != '+' &&
		(r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
}
