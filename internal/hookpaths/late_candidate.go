// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// LateCallGrade combines every known word of a late shell call with the
// shared protected-reach reader. An unreadable shell shape remains Possible;
// it never clears a Named candidate found in another segment.
func LateCallGrade(command, cwd, home string) Grade {
	if !filepath.IsAbs(cwd) || !filepath.IsAbs(home) || len(command) > MaxPayloadBytes {
		return GradePossible
	}
	calls, known := LateKnownCalls(command, cwd, home)
	if !known {
		return GradePossible
	}
	memo := NewTargetMemo()
	grade := GradeNone
	wordGrade := func(word string) Grade {
		if word == "" {
			return GradeNone
		}
		return ProtectedReach(OperandPath(word, cwd), home, memo)
	}
	for _, words := range calls {
		if len(words) == 0 {
			return GradePossible
		}
		program := programBase(words[0])
		endOptions := false
		for i, word := range words {
			if i == 0 && !strings.ContainsAny(word, `/\`) {
				continue
			}
			if i > 0 && !endOptions && word == "--" {
				endOptions = true
				continue
			}
			if i > 0 && !endOptions && strings.HasPrefix(word, "-") {
				if strings.HasPrefix(word, "--") {
					if option, value, assigned := strings.Cut(word, "="); assigned &&
						!lateTextLongOption(program, option) {
						grade = grade.Max(wordGrade(value))
					}
				} else if value, known := lateAttachedFileOptionValue(program, word); known {
					grade = grade.Max(wordGrade(value))
				} else {
					for start := 2; start < len(word); start++ {
						grade = grade.Max(wordGrade(word[start:]))
					}
				}
			} else {
				grade = grade.Max(wordGrade(word))
			}
			if grade == GradeNamed {
				return grade
			}
		}
	}
	return grade
}

func lateTextLongOption(program, option string) bool {
	switch program {
	case "grep", "egrep", "fgrep":
		return option == "--regexp" || option == "--max-count" || option == "--after-context" ||
			option == "--before-context" || option == "--context"
	case "sed":
		return option == "--expression"
	case "awk", "gawk", "mawk", "nawk":
		return option == "--field-separator" || option == "--assign"
	}
	return false
}

// File-valued attached options are candidates; text-valued options are not.
// Unknown clusters are checked at every suffix by LateCallGrade.
func lateAttachedFileOptionValue(program, option string) (string, bool) {
	if len(option) < 3 || option[0] != '-' || option[1] == '-' {
		return "", false
	}
	var fileOptions, textOptions, switches string
	switch program {
	case "grep", "egrep", "fgrep":
		fileOptions, textOptions = "f", "eABCm"
		switches = "EFGivnHhroqwslLaxZzUuPp"
	case "sed":
		fileOptions, textOptions = "f", "ei"
		switches = "nErsuz"
	case "awk", "gawk", "mawk", "nawk":
		fileOptions, textOptions = "f", "FvW"
	default:
		fileOptions = "f"
	}
	for i := 1; i < len(option); i++ {
		if strings.IndexByte(fileOptions, option[i]) >= 0 {
			return option[i+1:], true
		}
		if strings.IndexByte(textOptions, option[i]) >= 0 || strings.IndexByte(switches, option[i]) < 0 {
			return "", strings.IndexByte(textOptions, option[i]) >= 0
		}
	}
	return "", true
}

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
		args, ok := lateUnwrapCall(cmd.Args, home)
		if !ok {
			return nil, false
		}
		program, fixed := StaticWord(args[0], home)
		if !fixed || compound && lateChangesShellContext(program) {
			return nil, false
		}
		if program == "bash" || program == "sh" || program == "zsh" || program == "eval" {
			if program == "eval" && len(args) != 2 || program != "eval" && len(args) != 3 {
				return nil, false
			}
			bodyIndex := 2
			if program == "eval" {
				bodyIndex = 1
			} else if option, known := StaticWord(args[1], home); !known || option != "-c" && option != "-lc" {
				return nil, false
			}
			body, bodyOK := lateKnownWord(args[bodyIndex], cwd, home)
			if !bodyOK {
				return nil, false
			}
			inner, ok := lateKnownCalls(body, cwd, home, depth+1)
			if !ok {
				return nil, false
			}
			calls = append(calls, inner...)
		} else {
			display := program == "echo" || program == "printf"
			words := make([]string, 0, len(args)+len(stmt.Redirs))
			for _, arg := range args {
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

// Prefix utilities execute their remaining words as a command. Keep that
// command's operands together so a quoted shell body is read as a body.
func lateUnwrapCall(args []*syntax.Word, home string) ([]*syntax.Word, bool) {
	for wraps := 0; wraps < 8 && len(args) > 0; wraps++ {
		program, known := StaticWord(args[0], home)
		if !known {
			return nil, false
		}
		prefix := args[:1]
		switch program {
		case "env", "/usr/bin/env", "/bin/env":
			i, options := 1, true
			for i < len(args) {
				word, fixed := StaticWord(args[i], home)
				if !fixed {
					return nil, false
				}
				if options && word == "--" {
					options = false
					i++
					continue
				}
				if options && (word == "-i" || word == "--ignore-environment") {
					i++
					continue
				}
				if options && (word == "-u" || word == "--unset") {
					if i+1 >= len(args) {
						return nil, false
					}
					name, fixed := StaticWord(args[i+1], home)
					if !fixed || name == "HOME" || name == "PWD" {
						return nil, false
					}
					i += 2
					continue
				}
				if options && strings.HasPrefix(word, "--unset=") {
					if name := strings.TrimPrefix(word, "--unset="); name == "HOME" || name == "PWD" || name == "" {
						return nil, false
					}
					i++
					continue
				}
				if name, _, assigned := strings.Cut(word, "="); assigned && lateEnvName(name) {
					if name == "HOME" || name == "PWD" {
						return nil, false
					}
					i++
					continue
				}
				if options && strings.HasPrefix(word, "-") {
					return nil, false
				}
				break
			}
			args = args[i:]
			if len(args) == 0 {
				return prefix, true
			}
		case "command", "exec":
			i := 1
			for i < len(args) {
				word, fixed := StaticWord(args[i], home)
				if !fixed {
					return nil, false
				}
				if word == "--" {
					i++
					break
				}
				if program == "command" && word == "-p" {
					i++
					continue
				}
				if strings.HasPrefix(word, "-") {
					return nil, false
				}
				break
			}
			args = args[i:]
			if len(args) == 0 {
				return prefix, true
			}
		default:
			return args, true
		}
	}
	return nil, false
}

func lateEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
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
					part.Param.Value != "USER" && part.Param.Value != "LOGNAME" &&
						part.Param.Value != "PATH" && part.Param.Value != "SHELL" {
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
	return name == "HOME" || name == "PWD" || name == "USER" || name == "LOGNAME" ||
		name == "PATH" || name == "SHELL"
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
