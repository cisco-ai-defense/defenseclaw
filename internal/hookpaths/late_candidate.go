// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// LateCallGrade combines every known word of a late shell call with the
// shared protected-reach reader. An unreadable shell shape remains Possible;
// it never clears a Named candidate found in another segment.
//
// On a Windows host the call is read twice, as the shell reads it and as the
// host reads its Windows spellings (late_windows_spelling.go): a backslash
// before a letter is an escape to the shell and a separator to Windows, and
// the grade is the higher of the two readings.
func LateCallGrade(command, cwd, home string) Grade {
	if !filepath.IsAbs(cwd) || !filepath.IsAbs(home) || len(command) > MaxPayloadBytes {
		return GradePossible
	}
	grade := lateCallGradeReading(command, cwd, home, false)
	if runtime.GOOS == "windows" && grade != GradeNamed {
		grade = grade.Max(lateCallGradeReading(command, cwd, home, true))
	}
	return grade
}

func lateCallGradeReading(command, cwd, home string, spelled bool) Grade {
	calls, known := lateKnownCalls(command, cwd, home, 0, spelled)
	if !known {
		return GradePossible
	}
	memo := NewTargetMemo()
	grade := GradeNone
	wordGrade := func(word string) Grade {
		if word == "" {
			return GradeNone
		}
		grade := ProtectedReach(OperandPath(word, cwd), home, memo)
		if runtime.GOOS == "windows" {
			if lateWindowsAlias(word) {
				return GradePossible
			}
			if drive := lateWindowsDrivePath(word); drive != word {
				grade = grade.Max(ProtectedReach(OperandPath(drive, cwd), home, memo))
			}
		}
		return grade
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
	return lateKnownCalls(command, cwd, home, 0, false)
}

func lateKnownCalls(command, cwd, home string, depth int, spelled bool) ([][]string, bool) {
	if depth > 2 {
		return nil, false
	}
	file, parsed := parseShell(command)
	if !parsed || len(file.Stmts) == 0 {
		return nil, false
	}
	var calls [][]string
	for _, stmt := range file.Stmts {
		part, ok := lateKnownStatement(stmt, cwd, home, depth, len(file.Stmts) > 1, spelled)
		if !ok {
			return nil, false
		}
		calls = append(calls, part...)
	}
	return calls, true
}

func lateKnownStatement(stmt *syntax.Stmt, cwd, home string, depth int, compound, spelled bool) ([][]string, bool) {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess {
		return nil, false
	}
	var calls [][]string
	switch cmd := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		left, ok := lateKnownStatement(cmd.X, cwd, home, depth, true, spelled)
		if !ok {
			return nil, false
		}
		right, ok := lateKnownStatement(cmd.Y, cwd, home, depth, true, spelled)
		if !ok {
			return nil, false
		}
		calls = append(left, right...)
	case *syntax.CallExpr:
		values, ok := lateAssignValues(cmd.Assigns, cwd, home, spelled)
		if !ok {
			return nil, false
		}
		calls = append(calls, values...)
		if len(cmd.Args) == 0 {
			if len(cmd.Assigns) == 0 {
				return nil, false
			}
			// An assignment-only statement runs nothing. A later word that
			// expands its variable is not a known word (lateKnownParam).
			break
		}
		args, wrappers, ok := lateUnwrapCall(cmd.Args, home)
		if !ok {
			return nil, false
		}
		for _, wrapper := range wrappers {
			value, known := lateKnownWord(wrapper, cwd, home, spelled)
			if !known {
				return nil, false
			}
			if name, assigned, ok := strings.Cut(value, "="); ok && lateEnvName(name) {
				value = assigned
			}
			calls = append(calls, []string{"", value})
		}
		program, fixed := StaticWord(args[0], home)
		displayCommand := false
		if program == "command" && len(args) > 1 {
			option, known := StaticWord(args[1], home)
			displayCommand = known && (option == "-v" || option == "-V")
		}
		if !fixed || compound && lateChangesShellContext(program) && !displayCommand {
			return nil, false
		}
		if len(args) == 1 && strings.ContainsAny(program, " \t") && lateHasSplitWrapper(wrappers, home) {
			inner, ok := lateKnownCalls(program, cwd, home, depth+1, spelled)
			if !ok {
				return nil, false
			}
			calls = append(calls, inner...)
			break
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
			body, bodyOK := lateKnownWord(args[bodyIndex], cwd, home, spelled)
			if !bodyOK {
				return nil, false
			}
			inner, ok := lateKnownCalls(body, cwd, home, depth+1, spelled)
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
				value, ok := lateKnownWord(arg, cwd, home, spelled)
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
		value, ok := lateKnownWord(redirect.Word, cwd, home, spelled)
		if !ok {
			return nil, false
		}
		calls = append(calls, []string{"", value})
	}
	return calls, true
}

// lateAssignValues reads the assignments of a simple command, before its
// words or alone, as candidate operands: each known value and each element
// of a colon list, as the shell expands an assignment. An assignment that
// changes how the reader expands later words (HOME, PWD, IFS), an array, an
// index or an unknown value keeps the statement unknown.
func lateAssignValues(assigns []*syntax.Assign, cwd, home string, spelled bool) ([][]string, bool) {
	var calls [][]string
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil || assign.Naked || assign.Index != nil || assign.Array != nil {
			return nil, false
		}
		switch name := assign.Name.Value; {
		case !lateEnvName(name), name == "HOME", name == "PWD", name == "IFS":
			return nil, false
		}
		if assign.Value == nil {
			continue
		}
		value, known := lateKnownWord(assign.Value, cwd, home, spelled)
		if !known {
			return nil, false
		}
		calls = append(calls, []string{"", value})
		if !strings.Contains(value, ":") {
			continue
		}
		for _, element := range strings.Split(value, ":") {
			if element == "~" || strings.HasPrefix(element, "~/") {
				element = home + element[1:]
			}
			calls = append(calls, []string{"", element})
		}
	}
	return calls, true
}

func lateHasSplitWrapper(wrappers []*syntax.Word, home string) bool {
	for _, wrapper := range wrappers {
		word, ok := StaticWord(wrapper, home)
		if ok && (word == "-S" || word == "--split-string") {
			return true
		}
	}
	return false
}

// Prefix utilities execute their remaining words as a command. Keep that
// command's operands together so a quoted shell body is read as a body.
func lateUnwrapCall(args []*syntax.Word, home string) ([]*syntax.Word, []*syntax.Word, bool) {
	homeChanged := false
	var wrappers []*syntax.Word
	for wraps := 0; wraps < 8 && len(args) > 0; wraps++ {
		program, known := StaticWord(args[0], home)
		if !known {
			return nil, nil, false
		}
		prefix := args[:1]
		switch program {
		case "env", "/usr/bin/env", "/bin/env":
			i, options := 1, true
			for i < len(args) {
				word, fixed := StaticWord(args[i], home)
				if !fixed {
					return nil, nil, false
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
				if options && (word == "-S" || word == "--split-string") {
					i++
					continue
				}
				if options && (word == "-u" || word == "--unset") {
					if i+1 >= len(args) {
						return nil, nil, false
					}
					name, fixed := StaticWord(args[i+1], home)
					if !fixed || name == "HOME" || name == "PWD" {
						return nil, nil, false
					}
					i += 2
					continue
				}
				if options && strings.HasPrefix(word, "--unset=") {
					if name := strings.TrimPrefix(word, "--unset="); name == "HOME" || name == "PWD" || name == "" {
						return nil, nil, false
					}
					i++
					continue
				}
				if name, _, assigned := strings.Cut(word, "="); assigned && lateEnvName(name) {
					if name == "PWD" {
						return nil, nil, false
					}
					if name == "HOME" {
						homeChanged = true
					}
					i++
					continue
				}
				if options && strings.HasPrefix(word, "-") {
					return nil, nil, false
				}
				break
			}
			wrappers = append(wrappers, args[1:i]...)
			args = args[i:]
			if len(args) == 0 {
				return prefix, wrappers, true
			}
		case "command", "exec":
			i := 1
			for i < len(args) {
				word, fixed := StaticWord(args[i], home)
				if !fixed {
					return nil, nil, false
				}
				if word == "--" {
					i++
					break
				}
				if program == "command" && word == "-p" {
					i++
					continue
				}
				if program == "command" && (word == "-v" || word == "-V") {
					return args, wrappers, true
				}
				if program == "exec" && word == "-a" && i+1 < len(args) {
					i += 2
					continue
				}
				if program == "exec" && (word == "-c" || word == "-l") {
					i++
					continue
				}
				if strings.HasPrefix(word, "-") {
					return nil, nil, false
				}
				break
			}
			wrappers = append(wrappers, args[1:i]...)
			args = args[i:]
			if len(args) == 0 {
				return prefix, wrappers, true
			}
		case "nice", "/usr/bin/nice", "/bin/nice":
			i := 1
			for i < len(args) {
				word, fixed := StaticWord(args[i], home)
				if !fixed {
					return nil, nil, false
				}
				if word == "--" {
					i++
					break
				}
				if word == "-n" || word == "--adjustment" {
					if i+1 >= len(args) {
						return nil, nil, false
					}
					i += 2
					continue
				}
				if strings.HasPrefix(word, "-n") && len(word) > 2 ||
					strings.HasPrefix(word, "--adjustment=") || lateSignedInteger(word) {
					i++
					continue
				}
				if strings.HasPrefix(word, "-") {
					return nil, nil, false
				}
				break
			}
			wrappers = append(wrappers, args[1:i]...)
			args = args[i:]
			if len(args) == 0 {
				return prefix, wrappers, true
			}
		case "timeout", "/usr/bin/timeout", "/bin/timeout":
			i := 1
			for i < len(args) {
				word, fixed := StaticWord(args[i], home)
				if !fixed {
					return nil, nil, false
				}
				if word == "--" {
					i++
					break
				}
				if word == "-k" || word == "--kill-after" || word == "-s" || word == "--signal" {
					if i+1 >= len(args) {
						return nil, nil, false
					}
					i += 2
					continue
				}
				if word == "--foreground" || word == "--preserve-status" ||
					strings.HasPrefix(word, "--kill-after=") || strings.HasPrefix(word, "--signal=") {
					i++
					continue
				}
				if strings.HasPrefix(word, "-") {
					return nil, nil, false
				}
				break
			}
			if i >= len(args) {
				return nil, nil, false
			}
			i++ // duration
			wrappers = append(wrappers, args[1:i]...)
			args = args[i:]
			if len(args) == 0 {
				return prefix, wrappers, true
			}
		case "nohup", "/usr/bin/nohup", "/bin/nohup":
			i := 1
			if i < len(args) {
				word, fixed := StaticWord(args[i], home)
				if !fixed {
					return nil, nil, false
				}
				if word == "--" {
					i++
				} else if strings.HasPrefix(word, "-") {
					return nil, nil, false
				}
			}
			wrappers = append(wrappers, args[1:i]...)
			args = args[i:]
			if len(args) == 0 {
				return prefix, wrappers, true
			}
		default:
			if homeChanged {
				body := program
				if (program == "bash" || program == "sh" || program == "zsh") && len(args) >= 3 {
					var fixed bool
					body, fixed = StaticWord(args[2], home)
					if !fixed {
						return nil, nil, false
					}
				}
				if strings.Contains(body, "$HOME") || strings.Contains(body, "${HOME") ||
					strings.Contains(body, "~") {
					return nil, nil, false
				}
			}
			return args, wrappers, true
		}
	}
	return nil, nil, false
}

func lateSignedInteger(word string) bool {
	if len(word) < 2 || word[0] != '-' && word[0] != '+' {
		return false
	}
	for _, r := range word[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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

func lateKnownWord(word *syntax.Word, cwd, home string, spelled bool) (string, bool) {
	if !lateKnownWordParts(word) {
		return "", false
	}
	if spelled {
		word = lateWindowsPathWord(word)
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
