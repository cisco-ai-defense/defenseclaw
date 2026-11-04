// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// StaticFunctionCallReadings returns the commands run by simple, statically
// called shell functions. The normal command splitter cannot reduce a body
// that forwards "$@". The projection retains only complete, bounded static
// readings. A command that may change a later shell binding ends the proof.
func StaticFunctionCallReadings(command, home string) []string {
	if len(command) > 64<<10 || !strings.Contains(command, ")") && !strings.Contains(command, "function") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	functions := make(map[string]*syntax.FuncDecl)
	bindings := make(map[string]string)
	var readings []string
	work := &staticFunctionWork{}
	for _, stmt := range file.Stmts {
		if stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
			break
		}
		switch node := stmt.Cmd.(type) {
		case *syntax.FuncDecl:
			if node.Name == nil || node.Body == nil {
				return readings
			}
			functions[node.Name.Value] = node
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				if len(node.Assigns) != 1 {
					return readings
				}
				name, value, known := boundedSimpleAssignment(stmt, home)
				if name == "HOME" || name == "PATH" || name == "IFS" {
					return readings
				}
				if known {
					bindings[name] = value
				} else if node.Assigns[0].Name != nil {
					delete(bindings, node.Assigns[0].Name.Value)
				}
				continue
			}
			if len(node.Assigns) != 0 {
				return readings
			}
			name, known := StaticWord(node.Args[0], home)
			if !known {
				name, known = bindings[simpleShellParameter(node.Args[0])]
				if !known {
					return readings
				}
			}
			if functions[name] == nil {
				// A proven read leaves the current function and variable
				// bindings intact. Other calls may change them.
				start, end := int(stmt.Pos().Offset()), int(stmt.End().Offset())
				if start >= 0 && end > start && end <= len(command) &&
					stateStatementReadOnlyWithBindings(command[start:end], home, functionNames(functions)) {
					continue
				}
				return readings
			}
			args, known := staticFunctionArgs(node.Args[1:], nil, home, work)
			if !known {
				return readings
			}
			if projected, ok := staticFunctionReading(functions, name, args, home, 0, work); ok {
				if len(readings)+len(projected) > 8 {
					return readings
				}
				readings = append(readings, projected...)
			}
		default:
			return readings
		}
	}
	return readings
}

type staticFunctionWork struct{ words, bytes, statements int }

const (
	staticFunctionMaxWords = 512
	staticFunctionMaxBytes = 64 << 10
)

func functionNames(functions map[string]*syntax.FuncDecl) map[string]bool {
	names := make(map[string]bool, len(functions))
	for name := range functions {
		names[name] = true
	}
	return names
}

func staticFunctionReading(functions map[string]*syntax.FuncDecl, name string, args []string, home string, depth int, work *staticFunctionWork) ([]string, bool) {
	if depth >= 8 {
		return nil, false
	}
	decl := functions[name]
	if decl == nil || decl.Body == nil || decl.Body.Background || decl.Body.Negated || len(decl.Body.Redirs) != 0 {
		return nil, false
	}
	body, ok := decl.Body.Cmd.(*syntax.Block)
	if !ok {
		return nil, false
	}
	return staticFunctionStatements(functions, body.Stmts, args, home, depth, work)
}

func staticFunctionStatements(functions map[string]*syntax.FuncDecl, statements []*syntax.Stmt, args []string, home string, depth int, work *staticFunctionWork) ([]string, bool) {
	if depth >= 8 || work.statements+len(statements) > 128 {
		return nil, false
	}
	var readings []string
	for _, stmt := range statements {
		work.statements++
		if stmt.Background || stmt.Negated {
			return nil, false
		}
		if clause, ok := stmt.Cmd.(*syntax.IfClause); ok {
			for current := clause; current != nil; current = current.Else {
				condition, complete := staticFunctionStatements(functions, current.Cond, args, home, depth+1, work)
				if !complete {
					return nil, false
				}
				readings = append(readings, condition...)
				truth := staticFunctionLiteralCondition(current.Cond, functions, home)
				if truth != 0 {
					branch, complete := staticFunctionStatements(functions, current.Then, args, home, depth+1, work)
					if !complete {
						return nil, false
					}
					readings = append(readings, branch...)
				}
				if truth == 1 {
					break
				}
			}
			if len(readings) > 8 {
				return nil, false
			}
			continue
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 || len(call.Assigns) != 0 {
			return nil, false
		}
		words, known := staticFunctionArgs(call.Args, args, home, work)
		if !known || len(words) == 0 {
			return nil, false
		}
		if staticFunctionInactiveShellCall(words, home) {
			continue
		}
		if child := functions[words[0]]; child != nil {
			if len(stmt.Redirs) != 0 {
				return nil, false
			}
			projected, complete := staticFunctionReading(functions, words[0], words[1:], home, depth+1, work)
			if !complete || len(readings)+len(projected) > 8 {
				return nil, false
			}
			readings = append(readings, projected...)
			continue
		}
		reading := make([]string, 0, len(words)+2*len(stmt.Redirs))
		for _, word := range words {
			reading = append(reading, staticFunctionQuote(word))
		}
		for _, redirect := range stmt.Redirs {
			if redirect.Word == nil || redirect.N != nil {
				return nil, false
			}
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrClob:
			default:
				return nil, false
			}
			target, ok := staticFunctionWord(redirect.Word, args, home)
			if !ok {
				return nil, false
			}
			reading = append(reading, redirect.Op.String(), staticFunctionQuote(target))
		}
		text := strings.Join(reading, " ")
		if len(text) > staticFunctionMaxBytes {
			return nil, false
		}
		if stateStatementReadOnly(text, home) {
			continue
		}
		readings = append(readings, text)
		if len(readings) > 8 {
			return nil, false
		}
	}
	return readings, true
}

// A literal shell condition selects a branch without widening a proven
// inactive body. Other conditions keep both possible branches.
func staticFunctionLiteralCondition(condition []*syntax.Stmt, functions map[string]*syntax.FuncDecl, home string) int {
	if len(condition) == 0 {
		return 1
	}
	if len(condition) != 1 || condition[0].Background || condition[0].Negated || len(condition[0].Redirs) != 0 {
		return -1
	}
	call, ok := condition[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 1 {
		return -1
	}
	name, known := StaticWord(call.Args[0], home)
	if !known || functions[name] != nil {
		return -1
	}
	switch name {
	case "true", ":":
		return 1
	case "false":
		return 0
	default:
		return -1
	}
}

// A literal false child script has no reachable writer. Restrict this
// reading to a plain noninteractive shell command string and statements
// whose condition and side effects are fully known.
func staticFunctionInactiveShellCall(words []string, home string) bool {
	if len(words) != 3 || words[1] != "-c" {
		return false
	}
	switch words[0] {
	case "sh", "dash", "bash":
	default:
		return false
	}
	script := words[2]
	file, ok := parseShell(script)
	if !ok || len(file.Stmts) == 0 {
		return false
	}
	inactive := false
	for _, stmt := range file.Stmts {
		if stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
			return false
		}
		if clause, ok := stmt.Cmd.(*syntax.IfClause); ok && clause.Else == nil &&
			staticFunctionLiteralCondition(clause.Cond, nil, home) == 0 {
			inactive = true
			continue
		}
		start, end := int(stmt.Pos().Offset()), int(stmt.End().Offset())
		if start < 0 || end <= start || end > len(script) || !stateStatementReadOnly(script[start:end], home) {
			return false
		}
	}
	return inactive
}

func staticFunctionArgs(words []*syntax.Word, args []string, home string, work *staticFunctionWork) ([]string, bool) {
	var values []string
	for _, word := range words {
		if staticFunctionQuotedParam(word) == "@" {
			if !work.add(args) {
				return nil, false
			}
			values = append(values, args...)
			continue
		}
		value, ok := staticFunctionWord(word, args, home)
		if !ok {
			return nil, false
		}
		if !work.add([]string{value}) {
			return nil, false
		}
		values = append(values, value)
	}
	return values, true
}

func (work *staticFunctionWork) add(values []string) bool {
	if work.words+len(values) > staticFunctionMaxWords {
		return false
	}
	bytes := 0
	for _, value := range values {
		bytes += len(value)
		if bytes > staticFunctionMaxBytes-work.bytes {
			return false
		}
	}
	work.words += len(values)
	work.bytes += bytes
	return true
}

func staticFunctionWord(word *syntax.Word, args []string, home string) (string, bool) {
	if parameter := staticFunctionQuotedParam(word); parameter != "" {
		index, err := strconv.Atoi(parameter)
		if err != nil || index < 1 || index > len(args) {
			return "", false
		}
		return args[index-1], true
	}
	if word != nil && len(word.Parts) == 1 {
		if _, plain := word.Parts[0].(*syntax.ParamExp); plain {
			index, err := strconv.Atoi(simpleShellParameter(word))
			if err == nil && index >= 1 && index <= len(args) && args[index-1] != "" &&
				!strings.ContainsAny(args[index-1], " \t\r\n*?[]") {
				return args[index-1], true
			}
		}
	}
	return StaticWord(word, home)
}

func staticFunctionQuotedParam(word *syntax.Word) string {
	if word == nil || len(word.Parts) != 1 {
		return ""
	}
	quoted, ok := word.Parts[0].(*syntax.DblQuoted)
	if !ok || len(quoted.Parts) != 1 {
		return ""
	}
	return simpleShellParameter(word)
}

func staticFunctionQuote(value string) string {
	if value != "" && !strings.Contains(" if then else elif fi do done for while case esac in function select time coproc ", " "+value+" ") {
		safe := true
		for _, c := range value {
			if c < 'a' || c > 'z' {
				if c < 'A' || c > 'Z' {
					if c < '0' || c > '9' {
						safe = safe && strings.ContainsRune("_./:=+-", c)
					}
				}
			}
		}
		if safe {
			return value
		}
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
