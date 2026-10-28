// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// BoundedShellWriteOperands resolves redirects whose one variable has an
// exact value from a preceding printf assignment or a literal for list.
// Other control flow and word expansions remain outside this proof. unknown
// reports a bound redirect whose target is a pathname pattern: Bash expands
// an unquoted value or literal glob against the file system at run time, so
// the opened file cannot be named from the command text.
func BoundedShellWriteOperands(command, cwd, home string) (operands []string, unknown bool) {
	file, ok := parseShell(command)
	if !ok {
		return nil, false
	}
	if len(file.Stmts) == 2 {
		if name, value, ok := boundedPrintfAssignment(file.Stmts[0], home); ok {
			return boundedStatementRedirects(file.Stmts[1], cwd, home, name, value)
		}
	}
	if len(file.Stmts) == 4 {
		initial, _, initialOK := boundedSimpleAssignment(file.Stmts[0], home)
		declaration, declarationOK := file.Stmts[1].Cmd.(*syntax.FuncDecl)
		invoke, invokeOK := file.Stmts[2].Cmd.(*syntax.CallExpr)
		if initialOK && declarationOK && declaration.Name != nil && declaration.Body != nil &&
			invokeOK && len(invoke.Assigns) == 0 && len(invoke.Args) == 1 &&
			len(file.Stmts[2].Redirs) == 0 {
			if called, static := StaticWord(invoke.Args[0], home); static && called == declaration.Name.Value {
				if body, ok := declaration.Body.Cmd.(*syntax.Block); ok && len(body.Stmts) == 1 {
					if name, value, ok := boundedSimpleAssignment(body.Stmts[0], home); ok && name == initial {
						return boundedStatementRedirects(file.Stmts[3], cwd, home, name, value)
					}
				}
			}
		}
	}
	if len(file.Stmts) != 1 {
		return nil, false
	}
	loop, ok := file.Stmts[0].Cmd.(*syntax.ForClause)
	if !ok || loop.Select || len(loop.Do) != 1 {
		return nil, false
	}
	iteration, ok := loop.Loop.(*syntax.WordIter)
	if !ok || iteration.Name == nil || len(iteration.Items) == 0 || len(iteration.Items) > 8 {
		return nil, false
	}
	for _, item := range iteration.Items {
		value, static := StaticWord(item, home)
		if !static || strings.ContainsAny(value, "\x00\r\n") {
			return nil, false
		}
		redirects, pattern := boundedStatementRedirects(loop.Do[0], cwd, home, iteration.Name.Value, value)
		operands = append(operands, redirects...)
		unknown = unknown || pattern
	}
	return operands, unknown
}

func boundedSimpleAssignment(stmt *syntax.Stmt, home string) (name, value string, ok bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return "", "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return "", "", false
	}
	assignment := call.Assigns[0]
	if assignment.Name == nil || assignment.Value == nil || assignment.Append || assignment.Array != nil || assignment.Index != nil {
		return "", "", false
	}
	value, ok = StaticWord(assignment.Value, home)
	return assignment.Name.Value, value, ok
}

func boundedPrintfAssignment(stmt *syntax.Stmt, home string) (name, value string, ok bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return "", "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) < 5 || len(call.Args) > 6 {
		return "", "", false
	}
	words := make([]string, len(call.Args))
	for i, word := range call.Args {
		words[i], ok = StaticWord(word, home)
		if !ok {
			return "", "", false
		}
	}
	if words[0] != "printf" || words[1] != "-v" || words[2] == "" ||
		strings.ContainsAny(words[2], "/=\x00\r\n") {
		return "", "", false
	}
	format := words[3]
	if format != "%s" && format != "%s%s" || len(words)-4 != strings.Count(format, "%s") {
		return "", "", false
	}
	return words[2], strings.Join(words[4:], ""), true
}

func boundedStatementRedirects(stmt *syntax.Stmt, cwd, home, name, value string) (operands []string, unknown bool) {
	if stmt == nil || stmt.Background || stmt.Negated {
		return nil, false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 {
		return nil, false
	}
	for _, redirect := range stmt.Redirs {
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		default:
			continue
		}
		if !boundedWordUses(redirect.Word, name) {
			continue
		}
		if boundedWordPattern(redirect.Word, name, value) {
			unknown = true
			continue
		}
		if target, known := boundedWord(redirect.Word, home, name, value); known && target != "" {
			operands = append(operands, OperandPath(target, cwd))
		}
	}
	return operands, unknown
}

// boundedWordPattern reports a redirect word that Bash may expand as a
// pathname pattern: an unquoted literal glob, or an unquoted use of the bound
// value that holds pattern characters. Extended patterns count because
// startup files may enable extglob. In a value a backslash counts too: Bash
// 5.0 globs a word whose only pattern character is a backslash.
func boundedWordPattern(word *syntax.Word, name, value string) bool {
	pattern := func(text string) bool {
		return strings.ContainsAny(text, "*?[") ||
			strings.Contains(text, "+(") || strings.Contains(text, "@(") || strings.Contains(text, "!(")
	}
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if pattern(part.Value) {
				return true
			}
		case *syntax.ParamExp:
			if part.Param != nil && part.Param.Value == name && (pattern(value) || strings.Contains(value, "\\")) {
				return true
			}
		}
	}
	return false
}

func boundedWordUses(word *syntax.Word, name string) bool {
	for _, part := range word.Parts {
		if param, ok := part.(*syntax.ParamExp); ok && param.Param != nil && param.Param.Value == name {
			return true
		}
		if quoted, ok := part.(*syntax.DblQuoted); ok {
			for _, inner := range quoted.Parts {
				if param, ok := inner.(*syntax.ParamExp); ok && param.Param != nil && param.Param.Value == name {
					return true
				}
			}
		}
	}
	return false
}

func boundedWord(word *syntax.Word, home, name, value string) (string, bool) {
	validParts := func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit, *syntax.SglQuoted:
			case *syntax.ParamExp:
				if part.Param == nil || part.Param.Value != name || part.Excl || part.Length ||
					part.Index != nil || part.Slice != nil || part.Repl != nil || part.Exp != nil || len(part.Modifiers) != 0 {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	for _, part := range word.Parts {
		if quoted, ok := part.(*syntax.DblQuoted); ok {
			if !validParts(quoted.Parts) {
				return "", false
			}
			continue
		}
		if !validParts([]syntax.WordPart{part}) {
			return "", false
		}
	}
	fields, err := expand.Fields(&expand.Config{Env: expand.ListEnviron("HOME="+home, name+"="+value)}, word)
	if err != nil || len(fields) != 1 {
		return "", false
	}
	return fields[0], true
}
