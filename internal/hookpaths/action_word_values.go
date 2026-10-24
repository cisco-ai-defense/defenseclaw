// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// actionValues holds only values established by a straight-line statement.
// A failed assignment removes the old value: it must never certify a later
// redirect after an unset, append, read or command substitution changed it.
type actionValues map[string]string

// A generated basename is bounded by its literal parent directory, but its
// exact spelling is not known until execution. Never replace it with a fake
// filename: that would miss an existing protected symlink with another name.
const actionGeneratedMarker = "\x1f"

// Assignments in a conditional, loop, function or pipeline may never execute
// or may execute more than once. They invalidate a prior straight-line value;
// their branch-local value cannot certify a later write target.
func actionForgetValues(stmt *syntax.Stmt, values actionValues, home string) {
	forget := func(assign *syntax.Assign) {
		if assign.Name != nil {
			delete(values, assign.Name.Value)
		}
	}
	if declaration, ok := stmt.Cmd.(*syntax.DeclClause); ok {
		for _, assign := range declaration.Args {
			forget(assign)
		}
		return
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return
	}
	for _, assign := range call.Assigns {
		forget(assign)
	}
	if len(call.Args) == 0 {
		return
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed {
		return
	}
	switch programBase(program) {
	case "read", "mapfile", "readarray", "export", "unset", "set", "declare", "local", "typeset":
		for name := range values {
			if name != "HOME" && name != "PWD" && name != "RANDOM" && name != "$" {
				delete(values, name)
			}
		}
	case "printf":
		if len(call.Args) >= 3 {
			if flag, ok := StaticWord(call.Args[1], home); ok && flag == "-v" {
				if name, ok := StaticWord(call.Args[2], home); ok {
					delete(values, name)
				}
			}
		}
	case "cd", "pushd", "popd":
		delete(values, "PWD")
	}
}

func actionWordValue(word *syntax.Word, values actionValues, cwd, home string) (string, bool) {
	if word == nil {
		return "", false
	}
	var out strings.Builder
	var parts func([]syntax.WordPart) bool
	parts = func(items []syntax.WordPart) bool {
		for _, item := range items {
			switch part := item.(type) {
			case *syntax.Lit:
				if strings.ContainsAny(part.Value, "*?[\x00\x1f") {
					return false
				}
				out.WriteString(part.Value)
			case *syntax.SglQuoted:
				if strings.Contains(part.Value, actionGeneratedMarker) {
					return false
				}
				out.WriteString(part.Value)
			case *syntax.DblQuoted:
				if !parts(part.Parts) {
					return false
				}
			case *syntax.ParamExp:
				if part.Param == nil || part.Excl || part.Length || part.Width || part.IsSet || part.Slice != nil ||
					part.Repl != nil || part.Exp != nil || part.NestedParam != nil || part.Flags != nil || len(part.Modifiers) != 0 {
					return false
				}
				name := part.Param.Value
				if part.Index != nil {
					var index strings.Builder
					if syntax.NewPrinter().Print(&index, part.Index) != nil || index.String() != "0" {
						return false
					}
					name += "[0]"
				}
				value, ok := values[name]
				if !ok {
					return false
				}
				out.WriteString(value)
			case *syntax.CmdSubst:
				value, ok := actionSubstitutionValue(part, values, cwd, home)
				if !ok {
					return false
				}
				out.WriteString(value)
			default:
				return false
			}
		}
		return true
	}
	if !parts(word.Parts) {
		return "", false
	}
	value := out.String()
	if strings.HasPrefix(value, "~/") {
		value = filepath.Join(home, value[2:])
	}
	return value, true
}

// actionBoundProgramWords accepts only a simple program parameter immediately
// after its one literal assignment. A computed assignment, intervening command
// or control flow can change the executable before the call runs.
func actionBoundProgramWords(file *syntax.File, home string) map[*syntax.CallExpr]string {
	bound := make(map[*syntax.CallExpr]string)
	for i := 1; i < len(file.Stmts); i++ {
		// The first command of a list (x=f; "$x" && echo done) runs right
		// after the assignment too.
		command := file.Stmts[i].Cmd
		for {
			list, ok := command.(*syntax.BinaryCmd)
			if !ok || list.Op != syntax.AndStmt && list.Op != syntax.OrStmt || list.X == nil ||
				list.X.Negated || list.X.Background || len(list.X.Redirs) != 0 {
				break
			}
			command = list.X.Cmd
		}
		call, ok := command.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			continue
		}
		name, ok := actionSimpleProgramParameter(call.Args[0])
		if !ok || len(file.Stmts[i-1].Redirs) != 0 {
			continue
		}
		previous, ok := file.Stmts[i-1].Cmd.(*syntax.CallExpr)
		if !ok || len(previous.Args) != 0 || len(previous.Assigns) != 1 {
			continue
		}
		assignment := previous.Assigns[0]
		if assignment.Name == nil || assignment.Name.Value != name || assignment.Append {
			continue
		}
		value, fixed := StaticWord(assignment.Value, home)
		if fixed && value != "" && !strings.ContainsAny(value, " \t\r\n*?[]\x00\x1f") {
			bound[call] = value
		}
	}
	return bound
}

func actionSimpleProgramParameter(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	part := word.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok {
		if len(quoted.Parts) != 1 {
			return "", false
		}
		part = quoted.Parts[0]
	}
	parameter, ok := part.(*syntax.ParamExp)
	if !ok || parameter.Param == nil || parameter.Excl || parameter.Length || parameter.Width ||
		parameter.IsSet || parameter.Slice != nil || parameter.Repl != nil || parameter.Exp != nil ||
		parameter.NestedParam != nil || parameter.Flags != nil || len(parameter.Modifiers) != 0 || parameter.Index != nil {
		return "", false
	}
	name := parameter.Param.Value
	return name, name != "" && name != "@" && name != "*" && name != "#"
}

func actionSubstitutionValue(sub *syntax.CmdSubst, values actionValues, cwd, home string) (string, bool) {
	if len(sub.Stmts) != 1 {
		return "", false
	}
	stmt := sub.Stmts[0]
	if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && binary.Op == syntax.OrStmt {
		left, leftOK := binary.X.Cmd.(*syntax.CallExpr)
		right, rightOK := binary.Y.Cmd.(*syntax.CallExpr)
		if leftOK && rightOK && len(left.Args) == 3 && len(right.Args) == 1 {
			git, g := StaticWord(left.Args[0], home)
			a, aOK := StaticWord(left.Args[1], home)
			b, bOK := StaticWord(left.Args[2], home)
			pwd, p := StaticWord(right.Args[0], home)
			if g && aOK && bOK && p && git == "git" && a == "rev-parse" && b == "--show-toplevel" && pwd == "pwd" {
				for dir := cwd; ; dir = filepath.Dir(dir) {
					if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
						return dir, true
					}
					if filepath.Dir(dir) == dir {
						break
					}
				}
				return cwd, true
			}
		}
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 || len(call.Assigns) != 0 || len(stmt.Redirs) != 0 {
		return "", false
	}
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		words[i], ok = actionWordValue(arg, values, cwd, home)
		if !ok {
			return "", false
		}
	}
	switch programBase(words[0]) {
	case "pwd":
		if len(words) == 1 {
			return cwd, true
		}
	case "printf":
		if len(words) == 2 && !strings.Contains(words[1], "%") {
			return words[1], true
		}
		if len(words) == 3 && words[1] == "%s" {
			return words[2], true
		}
	case "basename":
		if len(words) == 2 {
			return filepath.Base(words[1]), true
		}
	case "realpath":
		if len(words) == 2 {
			return ResolveWriteTarget(OperandPath(words[1], cwd))
		}
	case "date":
		if len(words) == 2 && (words[1] == "+%s" || words[1] == "+%Y%m%d") {
			return actionGeneratedMarker, true
		}
	case "mktemp":
		if len(words) <= 2 && (len(words) == 1 || words[1] == "-d") {
			root := os.TempDir()
			if filepath.IsAbs(root) && root != home && !strings.HasPrefix(root, filepath.Join(home, ".ssh")) {
				return filepath.Join(root, "defenseclaw-bounded-temp"), true
			}
		}
	}
	return "", false
}

func actionUpdateValues(stmt *syntax.Stmt, values actionValues, cwd, home string) {
	update := func(assign *syntax.Assign) {
		if assign.Name == nil {
			return
		}
		name := assign.Name.Value
		value, fixed := actionWordValue(assign.Value, values, cwd, home)
		if assign.Append {
			old, known := values[name]
			if known && fixed {
				value = old + value
			} else {
				fixed = false
			}
		}
		if fixed {
			values[name] = value
		} else {
			delete(values, name)
		}
	}
	if declaration, ok := stmt.Cmd.(*syntax.DeclClause); ok {
		for _, assign := range declaration.Args {
			update(assign)
		}
		return
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return
	}
	for _, assign := range call.Assigns {
		update(assign)
	}
	if len(call.Args) == 0 {
		return
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed {
		return
	}
	switch programBase(program) {
	case "unset":
		for _, arg := range call.Args[1:] {
			if name, ok := StaticWord(arg, home); ok {
				delete(values, name)
			}
		}
	case "export":
		for _, arg := range call.Args[1:] {
			assignment, ok := StaticWord(arg, home)
			if !ok {
				continue
			}
			if name, value, found := strings.Cut(assignment, "="); found && name != "" {
				values[name] = value
			}
		}
	case "printf":
		if len(call.Args) < 5 {
			return
		}
		flag, f := StaticWord(call.Args[1], home)
		name, n := StaticWord(call.Args[2], home)
		format, q := StaticWord(call.Args[3], home)
		if !f || !n || !q || flag != "-v" || name == "" {
			return
		}
		if strings.Count(format, "%s") == 0 || strings.Count(format, "%s") > 2 ||
			strings.Contains(strings.ReplaceAll(format, "%s", ""), "%") {
			delete(values, name)
			return
		}
		if len(call.Args)-4 != strings.Count(format, "%s") {
			delete(values, name)
			return
		}
		result := format
		for _, arg := range call.Args[4:] {
			value, ok := actionWordValue(arg, values, cwd, home)
			if !ok {
				delete(values, name)
				return
			}
			result = strings.Replace(result, "%s", value, 1)
		}
		values[name] = result
	case "read", "mapfile", "readarray":
		index := 1
		for index < len(call.Args) {
			word, ok := StaticWord(call.Args[index], home)
			if !ok {
				return
			}
			if !strings.HasPrefix(word, "-") {
				break
			}
			index++
		}
		if index >= len(call.Args) {
			return
		}
		name, ok := StaticWord(call.Args[index], home)
		if !ok || name == "" {
			return
		}
		var input string
		found := false
		for _, redir := range stmt.Redirs {
			if redir.Word == nil {
				continue
			}
			switch redir.Op {
			case syntax.RdrIn:
				path, ok := actionWordValue(redir.Word, values, cwd, home)
				if ok {
					input, found = readIndirectSource(path, cwd)
				}
			case syntax.WordHdoc:
				input, found = actionWordValue(redir.Word, values, cwd, home)
			}
		}
		if !found {
			delete(values, name)
			delete(values, name+"[0]")
			return
		}
		input = strings.TrimRight(input, "\r\n")
		if program == "read" {
			fields := strings.Fields(input)
			if len(fields) == 0 {
				delete(values, name)
			} else {
				values[name] = fields[0]
			}
		} else {
			values[name+"[0]"] = strings.Split(input, "\n")[0]
		}
	}
}
