// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// LateKnownCalls supplies literal operands for a local late answer. Each
// simple call keeps its own option boundary. A shell wrapper is read as a
// nested command, so its quoted body cannot hide a known path value.
func LateKnownCalls(command, cwd, home string) ([][]string, bool) {
	return lateKnownCalls(command, cwd, home, 0)
}

func lateKnownCalls(command, cwd, home string, depth int) ([][]string, bool) {
	if depth > 2 {
		return nil, false
	}
	file, parsed := parseShell(command)
	if !parsed || len(file.Stmts) == 0 {
		return nil, false
	}
	var calls [][]string
	for _, stmt := range file.Stmts {
		part, ok := lateKnownStatement(stmt, cwd, home, depth, len(file.Stmts) > 1)
		if !ok {
			return nil, false
		}
		calls = append(calls, part...)
	}
	return calls, true
}

func lateKnownStatement(stmt *syntax.Stmt, cwd, home string, depth int, compound bool) ([][]string, bool) {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess {
		return nil, false
	}
	var calls [][]string
	switch cmd := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		left, ok := lateKnownStatement(cmd.X, cwd, home, depth, true)
		if !ok {
			return nil, false
		}
		right, ok := lateKnownStatement(cmd.Y, cwd, home, depth, true)
		if !ok {
			return nil, false
		}
		calls = append(left, right...)
	case *syntax.CallExpr:
		if len(cmd.Assigns) != 0 || len(cmd.Args) == 0 {
			return nil, false
		}
		program, fixed := StaticWord(cmd.Args[0], home)
		if !fixed || compound && lateChangesShellContext(program) {
			return nil, false
		}
		if program == "bash" || program == "sh" || program == "zsh" {
			if len(cmd.Args) != 3 {
				return nil, false
			}
			option, optionOK := StaticWord(cmd.Args[1], home)
			body, bodyOK := lateKnownWord(cmd.Args[2], cwd, home)
			if !optionOK || !bodyOK || option != "-c" && option != "-lc" {
				return nil, false
			}
			inner, ok := lateKnownCalls(body, cwd, home, depth+1)
			if !ok {
				return nil, false
			}
			calls = append(calls, inner...)
		} else {
			display := program == "echo" || program == "printf"
			words := make([]string, 0, len(cmd.Args)+len(stmt.Redirs))
			for _, arg := range cmd.Args {
				if display && lateDisplayValueWord(arg) {
					words = append(words, "")
					continue
				}
				value, ok := lateKnownWord(arg, cwd, home)
				if !ok {
					return nil, false
				}
				words = append(words, value)
			}
			calls = append(calls, words)
		}
	default:
		return nil, false
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Hdoc != nil {
			return nil, false
		}
		if redirect.Word == nil {
			continue
		}
		value, ok := lateKnownWord(redirect.Word, cwd, home)
		if !ok {
			return nil, false
		}
		calls = append(calls, []string{"", value})
	}
	return calls, true
}

func lateChangesShellContext(program string) bool {
	switch program {
	case "cd", "pushd", "popd", "export", "unset", "set", "declare", "typeset", "readonly", "eval", "source", ".", "builtin", "command", "exec":
		return true
	default:
		return false
	}
}

func lateKnownWord(word *syntax.Word, cwd, home string) (string, bool) {
	if !lateKnownWordParts(word) {
		return "", false
	}
	fields, err := expand.Fields(&expand.Config{Env: expand.ListEnviron(
		"HOME="+home, "PWD="+cwd,
	)}, word)
	if err != nil || len(fields) != 1 {
		return "", false
	}
	return fields[0], true
}

func lateValueOnlyWord(word *syntax.Word) bool {
	if len(word.Parts) != 1 {
		return false
	}
	switch part := word.Parts[0].(type) {
	case *syntax.ParamExp:
		return latePlainParam(part) && lateValueParam(part.Param.Value)
	case *syntax.DblQuoted:
		if len(part.Parts) == 1 {
			if param, ok := part.Parts[0].(*syntax.ParamExp); ok {
				return latePlainParam(param) && lateValueParam(param.Param.Value)
			}
		}
	case *syntax.Lit:
		return part.Value == "~"
	}
	return false
}

// A displayed user or login name with surrounding text is still only a
// displayed value. A path separator or an unknown expansion keeps the word
// in the ordinary resolved-word path instead.
func lateDisplayValueWord(word *syntax.Word) bool {
	if lateValueOnlyWord(word) {
		return true
	}
	seen := false
	var visit func([]syntax.WordPart) bool
	visit = func(parts []syntax.WordPart) bool {
		for _, item := range parts {
			switch part := item.(type) {
			case *syntax.Lit:
				if strings.ContainsAny(part.Value, "/\\") {
					return false
				}
			case *syntax.SglQuoted:
				if strings.ContainsAny(part.Value, "/\\") {
					return false
				}
			case *syntax.DblQuoted:
				if !visit(part.Parts) {
					return false
				}
			case *syntax.ParamExp:
				if !latePlainParam(part) ||
					part.Param.Value != "USER" && part.Param.Value != "LOGNAME" {
					return false
				}
				seen = true
			default:
				return false
			}
		}
		return true
	}
	return visit(word.Parts) && seen
}

func lateValueParam(name string) bool {
	return name == "HOME" || name == "PWD" || name == "USER" || name == "LOGNAME"
}

func lateKnownWordParts(word *syntax.Word) bool {
	for _, item := range word.Parts {
		switch part := item.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") ||
				strings.HasPrefix(part.Value, "~") && part.Value != "~" && !strings.HasPrefix(part.Value, "~/") {
				return false
			}
		case *syntax.SglQuoted:
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				if !lateKnownWordPart(inner) {
					return false
				}
			}
		case *syntax.ParamExp:
			if !lateKnownParam(part) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func lateKnownWordPart(part syntax.WordPart) bool {
	switch part := part.(type) {
	case *syntax.Lit:
		return true
	case *syntax.ParamExp:
		return lateKnownParam(part)
	default:
		return false
	}
}

func latePlainParam(param *syntax.ParamExp) bool {
	if param.Param == nil || param.Excl || param.Length || param.Width || param.IsSet ||
		param.Index != nil || param.Slice != nil || param.Repl != nil || param.Names != 0 ||
		param.Exp != nil || param.Flags != nil || param.NestedParam != nil || len(param.Modifiers) != 0 {
		return false
	}
	return true
}

func lateKnownParam(param *syntax.ParamExp) bool {
	return latePlainParam(param) && (param.Param.Value == "HOME" || param.Param.Value == "PWD")
}
