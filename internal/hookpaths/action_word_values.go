// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// actionValues is one possible set of known values. The forgetting tracker
// removes a failed assignment so it cannot certify a later redirect after
// an unset, append, read or command substitution changed it.
type actionValues map[string]string

// AdjacentAssignedWriteOperands proves a redirect whose immediately preceding
// AND-list statement assigns its path. Earlier commands may create files, but
// cannot change the value between that assignment and the redirect.
func AdjacentAssignedWriteOperands(command, cwd, home string) []string {
	file, ok := parseShell(command)
	if !ok || !filepath.IsAbs(cwd) {
		return nil
	}
	var statements []*syntax.Stmt
	var collect func(*syntax.Stmt) bool
	collect = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Background || stmt.Negated || len(statements) > 512 {
			return false
		}
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
			return len(stmt.Redirs) == 0 && pair.Op == syntax.AndStmt && collect(pair.X) && collect(pair.Y)
		}
		if _, ok := stmt.Cmd.(*syntax.CallExpr); !ok {
			return false
		}
		statements = append(statements, stmt)
		return true
	}
	for _, stmt := range file.Stmts {
		if !collect(stmt) {
			return nil
		}
	}
	var paths []string
	for i := 1; i < len(statements); i++ {
		previous, ok := statements[i-1].Cmd.(*syntax.CallExpr)
		if !ok || len(previous.Args) != 0 || len(previous.Assigns) != 1 || len(statements[i-1].Redirs) != 0 {
			continue
		}
		assignment := previous.Assigns[0]
		if assignment.Name == nil || assignment.Value == nil || assignment.Append || assignment.Array != nil || assignment.Index != nil {
			continue
		}
		value, fixed := StaticWord(assignment.Value, home)
		if !fixed || value == "" {
			continue
		}
		values := actionValues{"HOME": home, assignment.Name.Value: value}
		for _, redirect := range statements[i].Redirs {
			if redirect.Word == nil {
				continue
			}
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			default:
				continue
			}
			if name, fixed := actionWordValue(redirect.Word, values, cwd, home); fixed && name != "" {
				paths = append(paths, OperandPath(name, cwd))
			}
		}
	}
	return paths
}

// A generated basename is bounded by its literal parent directory, but its
// exact spelling is not known until execution. Never replace it with a fake
// filename: that would miss an existing protected symlink with another name.
const actionGeneratedMarker = "\x1f"

// printf accepts both -v NAME and -vNAME. Return the position of the
// format word so both value trackers handle the same binding.
func actionPrintfBoundName(call *syntax.CallExpr, home string) (string, int, bool) {
	if call == nil || len(call.Args) < 2 {
		return "", 0, false
	}
	option, fixed := StaticWord(call.Args[1], home)
	if !fixed {
		return "", 0, false
	}
	if option == "-v" {
		if len(call.Args) < 3 {
			return "", 0, false
		}
		name, fixed := StaticWord(call.Args[2], home)
		return name, 3, fixed && actionEvalAssignmentName(name)
	}
	if strings.HasPrefix(option, "-v") {
		name := strings.TrimPrefix(option, "-v")
		return name, 2, actionEvalAssignmentName(name)
	}
	return "", 0, false
}

// actionPrintfLiteral expands the pathname-relevant escapes in a Bash printf
// format. An unfamiliar escape leaves the binding unknown rather than
// retaining a value from before printf -v.
func actionPrintfLiteral(format string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '\\' {
			out.WriteByte(format[i])
			continue
		}
		i++
		if i == len(format) {
			return "", false
		}
		switch format[i] {
		case '\\':
			out.WriteByte('\\')
		case 'a':
			out.WriteByte('\a')
		case 'b':
			out.WriteByte('\b')
		case 'e', 'E':
			out.WriteByte('\x1b')
		case 'f':
			out.WriteByte('\f')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'v':
			out.WriteByte('\v')
		case 'x', 'u', 'U':
			limit := 2
			switch format[i] {
			case 'u':
				limit = 4
			case 'U':
				limit = 8
			}
			start := i + 1
			for i+1 < len(format) && i+1-start < limit && strings.ContainsRune("0123456789abcdefABCDEF", rune(format[i+1])) {
				i++
			}
			if i < start {
				return "", false
			}
			value, err := strconv.ParseUint(format[start:i+1], 16, 32)
			if err != nil || value == 0 {
				return "", false
			}
			if limit == 2 {
				out.WriteByte(byte(value))
			} else if utf8.ValidRune(rune(value)) {
				out.WriteRune(rune(value))
			} else {
				return "", false
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			start := i
			for i+1 < len(format) && i+1-start < 3 && format[i+1] >= '0' && format[i+1] <= '7' {
				i++
			}
			value, err := strconv.ParseUint(format[start:i+1], 8, 8)
			if err != nil || value == 0 {
				return "", false
			}
			out.WriteByte(byte(value))
		default:
			return "", false
		}
	}
	return out.String(), true
}

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
		if name, _, ok := actionPrintfBoundName(call, home); ok {
			delete(values, name)
		}
	case "cd", "pushd", "popd":
		delete(values, "PWD")
	}
}

func actionWordValue(word *syntax.Word, values actionValues, cwd, home string) (string, bool) {
	return actionWordValueWithGlob(word, values, cwd, home, false)
}

func actionWordValueWithGlob(word *syntax.Word, values actionValues, cwd, home string, allowGlob bool) (string, bool) {
	if word == nil {
		return "", false
	}
	var out strings.Builder
	var parts func([]syntax.WordPart) bool
	parts = func(items []syntax.WordPart) bool {
		for _, item := range items {
			switch part := item.(type) {
			case *syntax.Lit:
				if strings.ContainsAny(part.Value, "\x00\x1f") || !allowGlob && strings.ContainsAny(part.Value, "*?[") {
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
					part.Repl != nil || part.NestedParam != nil || part.Flags != nil || len(part.Modifiers) != 0 {
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
				if part.Exp != nil {
					if part.Exp.Op != syntax.DefaultUnset && part.Exp.Op != syntax.DefaultUnsetOrNull {
						return false
					}
					if !ok || part.Exp.Op == syntax.DefaultUnsetOrNull && value == "" {
						value, ok = actionWordValueWithGlob(part.Exp.Word, values, cwd, home, allowGlob)
					}
				}
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
	if actionWordTildePrefix(word) {
		// A preceding HOME assignment changes how the shell expands ~/.
		// The active user's home remains the protection root, but the
		// operand is resolved from the current shell value.
		currentHome, known := values["HOME"]
		if !known || currentHome == "" {
			return "", false
		}
		if actionPosixWindowsHome(home) {
			value = path.Join(currentHome, value[1:])
		} else {
			value = filepath.Join(currentHome, value[1:])
		}
	}
	return value, true
}

// The shell expands a leading tilde only when it is unquoted and unescaped
// and ends at an unquoted slash or the end of the word. A quoted, escaped or
// parameter-derived tilde stays a literal directory name below the cwd.
func actionWordTildePrefix(word *syntax.Word) bool {
	if len(word.Parts) == 0 {
		return false
	}
	lit, ok := word.Parts[0].(*syntax.Lit)
	return ok && (strings.HasPrefix(lit.Value, "~/") || lit.Value == "~" && len(word.Parts) == 1)
}

// actionBoundProgramWords accepts only a simple program parameter immediately
// after its one literal assignment. A computed assignment, intervening command
// or control flow can change the executable before the call runs.
func actionBoundProgramWords(file *syntax.File, home string) map[*syntax.CallExpr]string {
	bound := make(map[*syntax.CallExpr]string)
	for i := 1; i < len(file.Stmts); i++ {
		call, ok := file.Stmts[i].Cmd.(*syntax.CallExpr)
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
					if _, err := pathLstat(filepath.Join(dir, ".git")); err == nil {
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
	case "cat":
		if len(words) == 2 {
			if content, ok := readIndirectSource(words[1], cwd); ok {
				value := strings.TrimSuffix(content, "\n")
				if value != "" && !strings.ContainsAny(value, "\x00\r\n\t ") {
					return value, true
				}
			}
		}
	case "pwd":
		if len(words) == 1 {
			return cwd, true
		}
	case "echo":
		// echo [-n] word...: the words joined by one blank; the shell drops
		// the trailing newline. -e and a backslash change what is printed,
		// so they stay unknown (rel-1-0-2:GAP-0409, f=$(echo <link>)). A
		// brace word is several words in bash ({keylink,} is keylink), so it
		// stays unknown too (review should-fix).
		for _, arg := range call.Args[1:] {
			if actionWordHasBraceText(arg) {
				return "", false
			}
		}
		args := words[1:]
		if len(args) > 0 && args[0] == "-n" {
			args = args[1:]
		}
		if len(args) == 0 {
			return "", false
		}
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") || strings.ContainsAny(arg, "\\\x00\n") {
				return "", false
			}
		}
		return strings.Join(args, " "), true
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
	actionUpdateValuesAs(stmt, values, cwd, home, true)
}

// actionUpdateValuesKept retains each possible straight-line value after a
// compound statement. A skipped branch keeps the earlier value; an executed
// branch contributes its assignments. A brace group runs in this shell, so
// its assignments replace the earlier value. The forgetting tracker still
// supplies unset/default readings of a later word (rel-1-0-2:GAP-0409).
func actionUpdateValuesKept(stmt *syntax.Stmt, candidates []actionValues, cwd, home string, steps *int) []actionValues {
	if actionKeptSaturated(candidates) {
		return actionUpdateSaturatedValues(stmt, candidates[0], cwd, home)
	}
	var next []actionValues
	for _, values := range candidates {
		*steps += 1
		if *steps > actionMaxValueSteps {
			return actionSaturateValues(stmt, candidates, home)
		}
		next = actionAppendValueCandidates(next, actionKeptStatement(stmt, values, cwd, home, steps))
		if actionKeptSaturated(next) {
			return actionSaturateValues(stmt, candidates, home)
		}
	}
	return next
}

// The marker is distinct from every shell variable name. Values retained
// with it are the same in every candidate; a name absent from the map is
// unknown to a later redirect or writer.
const (
	actionMaxValueCandidates = 32
	actionMaxValueSteps      = 512
	actionKeptSaturatedKey   = "\x00kept-saturated"
	actionKeptAlternatesKey  = "\x00kept-alternates:"
)

var actionSaturatedCandidates = []actionValues{{actionKeptSaturatedKey: "1"}}

func actionKeptSaturated(candidates []actionValues) bool {
	return len(candidates) == 1 && candidates[0][actionKeptSaturatedKey] == "1"
}

// On a candidate or step cap, keep only values shared by every input path.
// The current statement may be only partly explored, so its assignments
// cannot certify a value even when the paths explored so far agree.
func actionSaturateValues(stmt *syntax.Stmt, candidates []actionValues, home string) []actionValues {
	stable := actionValues{actionKeptSaturatedKey: "1"}
	if len(candidates) > 0 {
		for name, value := range candidates[0] {
			shared := true
			for _, candidate := range candidates[1:] {
				if other, ok := candidate[name]; !ok || other != value {
					shared = false
					break
				}
			}
			if shared {
				stable[name] = value
			}
		}
	}
	actionInvalidateSaturatedValues(stmt, stable, home)
	return []actionValues{stable}
}

// Straight-line assignments after saturation can establish a fresh value.
// Compound statements can take several paths, so their writes invalidate
// the affected names without expanding the candidate product again.
func actionUpdateSaturatedValues(stmt *syntax.Stmt, stable actionValues, cwd, home string) []actionValues {
	next := maps.Clone(stable)
	switch stmt.Cmd.(type) {
	case *syntax.CallExpr:
		call := stmt.Cmd.(*syntax.CallExpr)
		if len(call.Args) == 0 {
			for _, assign := range call.Assigns {
				if assign.Name != nil {
					delete(next, actionKeptAlternatesKey+assign.Name.Value)
				}
			}
			actionUpdateValuesAs(stmt, next, cwd, home, false)
			return []actionValues{next}
		}
		if len(call.Args) > 0 {
			program, fixed := staticProgramWord(call.Args[0], home)
			switch programBase(program) {
			case "eval", "source", ".", "unset", "export", "printf", "read", "mapfile", "readarray", "set", "declare", "local", "typeset":
				fixed = false
			}
			if !fixed {
				actionInvalidateSaturatedValues(stmt, next, home)
				return []actionValues{next}
			}
		}
		actionUpdateValuesAs(stmt, next, cwd, home, false)
	case *syntax.DeclClause:
		for _, assign := range stmt.Cmd.(*syntax.DeclClause).Args {
			if assign.Name != nil {
				delete(next, actionKeptAlternatesKey+assign.Name.Value)
			}
		}
		actionUpdateValuesAs(stmt, next, cwd, home, false)
	default:
		if !actionSaturatedIfAlternates(stmt, next, cwd, home) {
			actionInvalidateSaturatedValues(stmt, next, home)
		}
	}
	return []actionValues{next}
}

// An if with one plain assignment either keeps the prior value or uses the
// new one. Store both without resuming the full candidate product.
func actionSaturatedIfAlternates(stmt *syntax.Stmt, stable actionValues, cwd, home string) bool {
	clause, ok := stmt.Cmd.(*syntax.IfClause)
	if !ok || len(clause.Cond) != 1 || len(clause.Then) != 1 || clause.Else != nil {
		return false
	}
	condition, ok := clause.Cond[0].Cmd.(*syntax.CallExpr)
	if !ok || len(condition.Args) == 0 || len(condition.Assigns) != 0 || len(clause.Cond[0].Redirs) != 0 {
		return false
	}
	program, fixed := staticProgramWord(condition.Args[0], home)
	if !fixed {
		return false
	}
	switch program {
	case "true", "false":
		if len(condition.Args) != 1 {
			return false
		}
	case "[", "test":
		want := 3
		if program == "[" {
			want = 4
		}
		if len(condition.Args) != want {
			return false
		}
		if program == "[" {
			if closing, fixed := StaticWord(condition.Args[3], home); !fixed || closing != "]" {
				return false
			}
		}
		flag, fixed := StaticWord(condition.Args[1], home)
		if !fixed || flag != "-n" && flag != "-z" && flag != "-f" && flag != "-d" {
			return false
		}
		if _, fixed := StaticWord(condition.Args[2], home); !fixed {
			if _, simple := actionSimpleProgramParameter(condition.Args[2]); !simple {
				return false
			}
		}
	default:
		return false
	}
	branch := clause.Then[0]
	call, ok := branch.Cmd.(*syntax.CallExpr)
	if !ok || branch.Background || branch.Negated || len(branch.Redirs) != 0 || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return false
	}
	assign := call.Assigns[0]
	if assign.Name == nil || assign.Value == nil || assign.Append || assign.Array != nil || assign.Index != nil {
		return false
	}
	name := assign.Name.Value
	value, fixed := actionWordValue(assign.Value, stable, cwd, home)
	if !fixed || strings.ContainsAny(value, "\x00\x1f") {
		return false
	}
	key := actionKeptAlternatesKey + name
	var options []string
	if previous, ok := stable[key]; ok {
		options = strings.Split(previous, "\x00")
	} else if previous, ok := stable[name]; ok {
		if strings.ContainsAny(previous, "\x00\x1f") {
			return false
		}
		options = []string{previous}
	} else {
		return false
	}
	if !slices.Contains(options, value) {
		if len(options) >= actionMaxValueCandidates {
			return false
		}
		options = append(options, value)
	}
	delete(stable, name)
	stable[key] = strings.Join(options, "\x00")
	return true
}

func actionSaturatedWordValues(word *syntax.Word, stable actionValues, cwd, home string) ([]string, bool) {
	states := []actionValues{stable}
	for key, encoded := range stable {
		if !strings.HasPrefix(key, actionKeptAlternatesKey) {
			continue
		}
		options := strings.Split(encoded, "\x00")
		if len(states)*len(options) > actionMaxValueCandidates {
			return nil, false
		}
		var next []actionValues
		for _, state := range states {
			for _, option := range options {
				candidate := maps.Clone(state)
				candidate[strings.TrimPrefix(key, actionKeptAlternatesKey)] = option
				next = append(next, candidate)
			}
		}
		states = next
	}
	var values []string
	for _, state := range states {
		value, fixed := actionWordValue(word, state, cwd, home)
		if !fixed {
			return nil, false
		}
		if !slices.Contains(values, value) {
			values = append(values, value)
		}
	}
	return values, true
}

func actionInvalidateSaturatedValues(stmt *syntax.Stmt, stable actionValues, home string) {
	for name := range stable {
		if strings.HasPrefix(name, actionKeptAlternatesKey) {
			delete(stable, name)
		}
	}
	clear := func() {
		for name := range stable {
			if name != actionKeptSaturatedKey {
				delete(stable, name)
			}
		}
	}
	syntax.Walk(stmt, func(node syntax.Node) bool {
		nested, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		actionForgetValues(nested, stable, home)
		if call, ok := nested.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			program, fixed := staticProgramWord(call.Args[0], home)
			if !fixed || programBase(program) == "eval" || programBase(program) == "source" || program == "." {
				clear()
			}
		}
		if _, ok := nested.Cmd.(*syntax.ArithmCmd); ok {
			clear()
		}
		return true
	})
}

func actionAppendValueCandidates(candidates, more []actionValues) []actionValues {
	if actionKeptSaturated(candidates) {
		return candidates
	}
	if actionKeptSaturated(more) {
		return more
	}
	for _, values := range more {
		seen := false
		for _, prior := range candidates {
			if maps.Equal(prior, values) {
				seen = true
				break
			}
		}
		if !seen {
			if len(candidates) == actionMaxValueCandidates {
				return actionSaturatedCandidates
			}
			candidates = append(candidates, values)
		}
	}
	return candidates
}

func actionKeptStatements(statements []*syntax.Stmt, candidates []actionValues, cwd, home string, steps *int) []actionValues {
	for _, stmt := range statements {
		candidates = actionUpdateValuesKept(stmt, candidates, cwd, home, steps)
	}
	return candidates
}

func actionKeptStatement(stmt *syntax.Stmt, values actionValues, cwd, home string, steps *int) []actionValues {
	if stmt == nil || stmt.Background {
		return []actionValues{values}
	}
	switch command := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(command.Assigns) == 0 {
			if len(command.Args) == 0 {
				return []actionValues{values}
			}
			program, fixed := StaticWord(command.Args[0], home)
			if !fixed {
				return []actionValues{values}
			}
			switch programBase(program) {
			case "eval", "unset", "export", "printf", "read", "mapfile", "readarray":
			default:
				return []actionValues{values}
			}
		}
		next := maps.Clone(values)
		actionUpdateValuesAs(stmt, next, cwd, home, false)
		return []actionValues{next}
	case *syntax.DeclClause:
		if len(command.Args) == 0 {
			return []actionValues{values}
		}
		next := maps.Clone(values)
		actionUpdateValuesAs(stmt, next, cwd, home, false)
		return []actionValues{next}
	case *syntax.Block:
		return actionKeptStatements(command.Stmts, []actionValues{values}, cwd, home, steps)
	case *syntax.IfClause:
		return actionKeptIf(command, values, cwd, home, steps)
	case *syntax.BinaryCmd:
		if command.Op == syntax.Pipe || command.Op == syntax.PipeAll {
			return []actionValues{values}
		}
		left := actionKeptStatement(command.X, values, cwd, home, steps)
		if actionKeptSaturated(left) {
			return left
		}
		var next []actionValues
		truth := actionStaticCondition(command.X, home)
		for _, candidate := range left {
			if truth == 0 || command.Op == syntax.AndStmt && truth < 0 || command.Op == syntax.OrStmt && truth > 0 {
				next = actionAppendValueCandidates(next, []actionValues{candidate})
			}
			if truth == 0 || command.Op == syntax.AndStmt && truth > 0 || command.Op == syntax.OrStmt && truth < 0 {
				next = actionAppendValueCandidates(next, actionKeptStatement(command.Y, candidate, cwd, home, steps))
			}
			if actionKeptSaturated(next) {
				return next
			}
		}
		return next
	case *syntax.WhileClause:
		condition := actionKeptStatements(command.Cond, []actionValues{values}, cwd, home, steps)
		if actionKeptSaturated(condition) {
			return condition
		}
		if len(command.Cond) > 0 && actionStaticCondition(command.Cond[len(command.Cond)-1], home) == -1 && !command.Until {
			return condition
		}
		return actionAppendValueCandidates(condition, actionKeptStatements(command.Do, condition, cwd, home, steps))
	case *syntax.ForClause:
		return actionAppendValueCandidates([]actionValues{values}, actionKeptStatements(command.Do, []actionValues{values}, cwd, home, steps))
	case *syntax.CaseClause:
		next := []actionValues{values}
		for _, item := range command.Items {
			next = actionAppendValueCandidates(next, actionKeptStatements(item.Stmts, []actionValues{values}, cwd, home, steps))
			if actionKeptSaturated(next) {
				return next
			}
		}
		return next
	default:
		// Other command forms do not prove an assignment in this shell.
		return []actionValues{values}
	}
}

// 1 is true, -1 false, and 0 unknown. Only shell builtins whose result is
// fixed without inspecting the environment narrow a branch here.
func actionStaticCondition(stmt *syntax.Stmt, home string) int {
	if stmt == nil {
		return 0
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 1 || len(call.Assigns) != 0 || len(stmt.Redirs) != 0 {
		return 0
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed {
		return 0
	}
	result := 0
	switch program {
	case "true", ":":
		result = 1
	case "false":
		result = -1
	}
	if stmt.Negated {
		result = -result
	}
	return result
}

func actionKeptIf(clause *syntax.IfClause, values actionValues, cwd, home string, steps *int) []actionValues {
	if len(clause.Cond) == 0 { // else
		return actionKeptStatements(clause.Then, []actionValues{values}, cwd, home, steps)
	}
	condition := actionKeptStatements(clause.Cond, []actionValues{values}, cwd, home, steps)
	if actionKeptSaturated(condition) {
		return condition
	}
	truth := actionStaticCondition(clause.Cond[len(clause.Cond)-1], home)
	var next []actionValues
	for _, candidate := range condition {
		if truth >= 0 {
			next = actionAppendValueCandidates(next, actionKeptStatements(clause.Then, []actionValues{candidate}, cwd, home, steps))
		}
		if truth <= 0 {
			if clause.Else == nil {
				next = actionAppendValueCandidates(next, []actionValues{candidate})
			} else {
				next = actionAppendValueCandidates(next, actionKeptIf(clause.Else, candidate, cwd, home, steps))
			}
		}
		if actionKeptSaturated(next) {
			return next
		}
	}
	return next
}

func actionUpdateValuesAs(stmt *syntax.Stmt, values actionValues, cwd, home string, forget bool) {
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
	if !ok && !forget {
		return
	}
	if !ok {
		// A conditional, loop, group or subshell may run its statements
		// once, never or many times: a name one of them assigns or unsets
		// no longer has a known value after it, so a later ${f:-default}
		// reads its default (rel-1-0-2:GAP-0409, unset inside an if).
		syntax.Walk(stmt, func(node syntax.Node) bool {
			if nested, ok := node.(*syntax.Stmt); ok && nested != stmt {
				actionForgetValues(nested, values, home)
			}
			return true
		})
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
	case "eval":
		// eval of static name=value words assigns them; any other eval
		// may change every name (rel-1-0-2:GAP-0409, eval f=<link>).
		assigned := map[string]string{}
		for _, arg := range call.Args[1:] {
			text, ok := StaticWord(arg, home)
			name, value, found := strings.Cut(text, "=")
			if !ok || !found || !actionEvalAssignmentName(name) ||
				strings.ContainsAny(value, " \t\n;&|<>()$`'\"\\*?[]{}~#") {
				if !forget {
					return
				}
				for name := range values {
					if name != "HOME" && name != "PWD" {
						delete(values, name)
					}
				}
				return
			}
			assigned[name] = value
		}
		for name, value := range assigned {
			values[name] = value
		}
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
		name, formatIndex, ok := actionPrintfBoundName(call, home)
		if !ok {
			return
		}
		if len(call.Args) <= formatIndex {
			delete(values, name)
			return
		}
		format, fixed := StaticWord(call.Args[formatIndex], home)
		if !fixed {
			delete(values, name)
			return
		}
		if strings.Count(format, "%s") > 2 ||
			strings.Contains(strings.ReplaceAll(format, "%s", ""), "%") {
			delete(values, name)
			return
		}
		parts := strings.Split(format, "%s")
		literals := make([]string, len(parts))
		for i, part := range parts {
			literal, ok := actionPrintfLiteral(part)
			if !ok {
				delete(values, name)
				return
			}
			literals[i] = literal
		}
		var result strings.Builder
		argIndex, argCount := formatIndex+1, len(call.Args)
		for {
			for i, literal := range literals {
				result.WriteString(literal)
				if i == len(literals)-1 {
					break
				}
				if argIndex < argCount {
					value, ok := actionWordValue(call.Args[argIndex], values, cwd, home)
					if !ok {
						delete(values, name)
						return
					}
					result.WriteString(value)
					argIndex++
				}
			}
			if result.Len() > MaxWriteTargetPathBytes {
				delete(values, name)
				return
			}
			if len(literals) == 1 || argIndex == argCount {
				break
			}
		}
		values[name] = result.String()
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

// actionEvalAssignmentName reports a shell variable name: a letter or _,
// then letters, digits and _.
func actionEvalAssignmentName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}
