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

// DeclaredRedirectWriteOperands lists a variable redirect whose pathname was
// established by an earlier assignment on the same execution path. The
// client resolves these paths through links before a managed gateway loses
// access to the caller's home.
func DeclaredRedirectWriteOperands(command, cwd, home string) []string {
	if !strings.Contains(command, "$") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok || !filepath.IsAbs(cwd) {
		return nil
	}
	walker := newDeclaredRedirectWalker(file, cwd, home)
	walker.walkList(file.Stmts, []actionValues{{"HOME": home, "PWD": cwd}}, 0)
	if walker.exhausted {
		walker.anyAssignedValue(file)
	}
	return walker.paths
}

const actionReadonlyValuePrefix = "\x00readonly:"

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
// format word so both value trackers handle the same binding. An indexed
// destination may replace element zero of an existing scalar; only a bounded
// numeric index has an effect the tracker can recover.
func actionPrintfBoundName(call *syntax.CallExpr, values actionValues, cwd, home string) (string, int, bool) {
	if call == nil || len(call.Args) < 2 {
		return "", 0, false
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed {
		return "", 0, false
	}
	optionIndex := 1
	if program == "builtin" || program == "command" {
		if _, defined := values[actionFunctionValuePrefix+program]; defined || len(call.Args) < 3 {
			return "", 0, false
		}
		wrapped, known := StaticWord(call.Args[1], home)
		if !known || wrapped != "printf" {
			return "", 0, false
		}
		optionIndex = 2
	} else if program != "printf" {
		return "", 0, false
	} else if _, defined := values[actionFunctionValuePrefix+program]; defined {
		return "", 0, false
	}
	option, fixed := actionWordValue(call.Args[optionIndex], values, cwd, home)
	if !fixed {
		return "", 0, false
	}
	if option == "-v" {
		if len(call.Args) <= optionIndex+1 {
			return "", 0, false
		}
		name, fixed := actionWordValue(call.Args[optionIndex+1], values, cwd, home)
		if !fixed {
			return "", 0, false
		}
		return actionPrintfScalarName(name, optionIndex+2)
	}
	if strings.HasPrefix(option, "-v") {
		name := strings.TrimPrefix(option, "-v")
		return actionPrintfScalarName(name, optionIndex+1)
	}
	return "", 0, false
}

func actionPrintfScalarName(destination string, formatIndex int) (string, int, bool) {
	if actionEvalAssignmentName(destination) {
		return destination, formatIndex, true
	}
	name, index, indexed := strings.Cut(destination, "[")
	if !indexed || !actionEvalAssignmentName(name) {
		return "", formatIndex, false
	}
	if strings.HasSuffix(index, "]") {
		if number, known := actionPrintfStaticIndex(index[:len(index)-1]); known {
			if number == 0 {
				return name, formatIndex, true
			}
			if number > 0 {
				return "", formatIndex, true
			}
		}
	}
	// Other index expressions may evaluate to zero or change another binding.
	return name, formatIndex, false
}

func actionPrintfStaticIndex(index string) (int64, bool) {
	parse := func(term string) (int64, bool) {
		if term == "" || len(term) > 1 && term[0] == '0' || strings.Trim(term, "0123456789") != "" {
			return 0, false
		}
		number, err := strconv.ParseInt(term, 10, 64)
		return number, err == nil
	}
	position := strings.IndexAny(index, "+-")
	if position < 0 {
		return parse(index)
	}
	left, leftOK := parse(index[:position])
	right, rightOK := parse(index[position+1:])
	if !leftOK || !rightOK {
		return 0, false
	}
	if index[position] == '+' {
		const maxInt64 int64 = 1<<63 - 1
		if right > maxInt64-left {
			return 0, false
		}
		return left + right, true
	}
	return left - right, true
}

// printf's %n conversion assigns through an argument as well as -v's
// destination. Forget those names before a later redirect uses their values.
func actionPrintfFormatBindings(call *syntax.CallExpr, values actionValues, cwd, home string) ([]string, string, bool) {
	if call == nil || len(call.Args) < 2 {
		return nil, "", false
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed {
		return nil, "", false
	}
	index := 1
	if program == "builtin" || program == "command" {
		if _, defined := values[actionFunctionValuePrefix+program]; defined || len(call.Args) < 3 {
			return nil, "", false
		}
		wrapped, known := StaticWord(call.Args[1], home)
		if !known || wrapped != "printf" {
			return nil, "", false
		}
		index = 2
	} else if program != "printf" {
		return nil, "", false
	} else if _, defined := values[actionFunctionValuePrefix+program]; defined {
		return nil, "", false
	}
	option, known := actionWordValue(call.Args[index], values, cwd, home)
	if !known {
		return nil, "", true
	}
	if option == "-v" {
		index += 2
	} else if strings.HasPrefix(option, "-v") {
		index++
	} else if option == "--" {
		index++
	}
	if index >= len(call.Args) {
		return nil, "", false
	}
	format, known := actionWordValue(call.Args[index], values, cwd, home)
	if known && !actionPrintfHasNameConversion(format) {
		return nil, "", false
	}
	if known {
		if format == "%n" && index+2 == len(call.Args) {
			if split, exact := actionPrintfSplitNames(call.Args[index+1], values, cwd, home); exact {
				if len(split) == 0 {
					return nil, "", false
				}
				return split, "0", false
			}
		}
		if name, count, exact := actionPrintfExactNameBinding(format, call.Args[index+1:], values, cwd, home); exact {
			return []string{name}, count, false
		}
	}
	var names []string
	for _, arg := range call.Args[index+1:] {
		value, fixed := actionPrintfNameValue(arg, values, cwd, home)
		if !fixed {
			return nil, "", true
		}
		if actionEvalAssignmentName(value) {
			names = append(names, value)
		} else if actionPrintfNameMaySplit(arg) {
			return nil, "", true
		}
	}
	return names, "", false
}

// With the default IFS, one unquoted scalar may supply several %n names.
// Each repetition of a bare %n format writes the same zero count.
func actionPrintfSplitNames(word *syntax.Word, values actionValues, cwd, home string) ([]string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return nil, false
	}
	if _, changedIFS := values["IFS"]; changedIFS {
		return nil, false
	}
	param, ok := word.Parts[0].(*syntax.ParamExp)
	if !ok || param.Param == nil || param.Excl || param.Length || param.Width || param.IsSet ||
		param.Index != nil || param.Slice != nil || param.Repl != nil || param.NestedParam != nil ||
		param.Flags != nil || len(param.Modifiers) != 0 ||
		param.Exp != nil && param.Exp.Op != syntax.RemSmallSuffix && param.Exp.Op != syntax.RemLargeSuffix {
		return nil, false
	}
	value, known := actionPrintfNameValue(word, values, cwd, home)
	if !known || len(value) > 256 || strings.ContainsAny(value, "*?[]\\") {
		return nil, false
	}
	names := strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' })
	if len(names) > 16 {
		return nil, false
	}
	for _, name := range names {
		if !actionEvalAssignmentName(name) || values[actionReadonlyValuePrefix+name] != "" {
			return nil, false
		}
	}
	return names, true
}

func actionPrintfNameMaySplit(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	for _, part := range word.Parts {
		switch part.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp:
			return true
		}
	}
	return false
}

// A literal prefix and plain %s operands make %n's count exact. Other
// conversions leave the target unknown to the value tracker.
func actionPrintfExactNameBinding(format string, args []*syntax.Word, values actionValues, cwd, home string) (string, string, bool) {
	count, argIndex := 0, 0
	for i := 0; i < len(format); {
		if format[i] != '%' {
			end := strings.IndexByte(format[i:], '%')
			if end < 0 {
				return "", "", false
			}
			literal, ok := actionPrintfLiteral(format[i : i+end])
			if !ok || !actionPrintfASCII(literal) {
				return "", "", false
			}
			count += len(literal)
			i += end
			continue
		}
		if i+1 == len(format) {
			return "", "", false
		}
		switch format[i+1] {
		case '%':
			count++
			i += 2
		case 's':
			if argIndex >= len(args) {
				return "", "", false
			}
			value, fixed := StaticWord(args[argIndex], home)
			if !fixed || !actionPrintfASCII(value) {
				return "", "", false
			}
			count += len(value)
			argIndex++
			i += 2
		case 'n':
			if i+2 != len(format) || argIndex+1 != len(args) {
				return "", "", false
			}
			destination, fixed := actionPrintfNameValue(args[argIndex], values, cwd, home)
			if !fixed {
				return "", "", false
			}
			if !actionEvalAssignmentName(destination) {
				return "", "", false
			}
			return destination, strconv.Itoa(count), true
		default:
			return "", "", false
		}
	}
	return "", "", false
}

// Bash %n accepts a scalar identifier. Resolve a literal suffix removal on
// a known scalar so the resulting identifier can be checked before binding.
func actionPrintfNameValue(word *syntax.Word, values actionValues, cwd, home string) (string, bool) {
	if value, known := actionWordValue(word, values, cwd, home); known {
		return value, true
	}
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
	param, ok := part.(*syntax.ParamExp)
	if !ok || param.Param == nil || param.Excl || param.Length || param.Width || param.IsSet ||
		param.Index != nil || param.Slice != nil || param.Repl != nil || param.NestedParam != nil ||
		param.Flags != nil || len(param.Modifiers) != 0 || param.Exp == nil ||
		param.Exp.Op != syntax.RemSmallSuffix && param.Exp.Op != syntax.RemLargeSuffix {
		return "", false
	}
	value, known := values[param.Param.Value]
	if !known || param.Exp.Word == nil || len(param.Exp.Word.Parts) != 1 {
		return "", false
	}
	literal, ok := param.Exp.Word.Parts[0].(*syntax.Lit)
	if !ok || literal.Value == "" || strings.ContainsAny(literal.Value, "*?[]\\()@+!|") {
		return "", false
	}
	return strings.TrimSuffix(value, literal.Value), true
}

func actionPrintfASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func actionPrintfHasNameConversion(format string) bool {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 == len(format) {
			continue
		}
		i++
		if format[i] == '%' {
			continue
		}
		for i < len(format) && (format[i] < 'a' || format[i] > 'z') &&
			(format[i] < 'A' || format[i] > 'Z') && format[i] != '%' {
			i++
		}
		if i < len(format) && format[i] == 'n' {
			return true
		}
	}
	return false
}

func actionForgetPrintfFormatBindings(values actionValues, names []string, unknown bool) {
	if unknown {
		for name := range values {
			if !strings.HasPrefix(name, "\x00") {
				delete(values, name)
			}
		}
		return
	}
	for _, name := range names {
		delete(values, name)
		delete(values, name+"[0]")
	}
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
func actionForgetValues(stmt *syntax.Stmt, values actionValues, cwd, home string) {
	forget := func(assign *syntax.Assign) {
		if assign.Name != nil {
			delete(values, assign.Name.Value)
		}
	}
	if declaration, ok := stmt.Cmd.(*syntax.DeclClause); ok {
		if declaration.Variant != nil && declaration.Variant.Value == "readonly" {
			for _, assign := range declaration.Args {
				if assign.Name != nil {
					values[actionReadonlyValuePrefix+assign.Name.Value] = "?"
				}
			}
		}
		for _, assign := range declaration.Args {
			forget(assign)
		}
		return
	}
	if function, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
		if function.Name != nil {
			values[actionFunctionValuePrefix+function.Name.Value] = actionFunctionUnknownValue
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
	if _, defined := values[actionFunctionValuePrefix+program]; defined {
		next := maps.Clone(values)
		if _, known := actionApplyFunctionValue(program, next, 0); !known {
			actionClearFunctionValues(values)
			return
		}
		for name, value := range values {
			if !strings.HasPrefix(name, "\x00") && next[name] != value {
				delete(values, name)
			}
		}
		return
	}
	switch programBase(program) {
	case "read", "mapfile", "readarray", "export", "unset", "set", "declare", "local", "typeset":
		for name := range values {
			if name != "HOME" && name != "PWD" && name != "RANDOM" && name != "$" &&
				!strings.HasPrefix(name, actionFunctionValuePrefix) && !strings.HasPrefix(name, actionReadonlyValuePrefix) {
				delete(values, name)
			}
		}
	case "readonly":
		for _, arg := range call.Args[1:] {
			if name, ok := StaticWord(arg, home); ok && actionEvalAssignmentName(name) {
				values[actionReadonlyValuePrefix+name] = "?"
				delete(values, name)
			}
		}
	case "printf", "builtin", "command":
		names, _, unknown := actionPrintfFormatBindings(call, values, cwd, home)
		if name, _, _ := actionPrintfBoundName(call, values, cwd, home); name != "" {
			delete(values, name)
			delete(values, name+"[0]")
		}
		actionForgetPrintfFormatBindings(values, names, unknown)
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
	if !strings.Contains(words[0], "/") {
		if _, defined := values[actionFunctionValuePrefix+words[0]]; defined {
			return actionFunctionSubstitutionValue(words[0], values)
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
			return actionSaturateValues(stmt, candidates, cwd, home)
		}
		next = actionAppendValueCandidates(next, actionKeptStatement(stmt, values, cwd, home, steps))
		if actionKeptSaturated(next) {
			return actionSaturateValues(stmt, candidates, cwd, home)
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
func actionSaturateValues(stmt *syntax.Stmt, candidates []actionValues, cwd, home string) []actionValues {
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
		for _, candidate := range candidates {
			for name := range candidate {
				if strings.HasPrefix(name, actionReadonlyValuePrefix) {
					if _, certain := stable[name]; !certain {
						stable[name] = "?"
					}
				}
			}
		}
	}
	if _, function := stmt.Cmd.(*syntax.FuncDecl); function {
		actionUpdateValuesAs(stmt, stable, cwd, home, false)
	} else {
		actionInvalidateSaturatedValues(stmt, stable, cwd, home)
	}
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
			if fixed {
				if _, defined := next[actionFunctionValuePrefix+program]; defined {
					actionUpdateValuesAs(stmt, next, cwd, home, false)
					return []actionValues{next}
				}
			}
			switch programBase(program) {
			case "eval", "source", ".", "unset", "export", "printf", "builtin", "command", "read", "mapfile", "readarray", "set", "declare", "local", "typeset":
				fixed = false
			}
			if !fixed {
				actionInvalidateSaturatedValues(stmt, next, cwd, home)
				return []actionValues{next}
			}
		}
		actionUpdateValuesAs(stmt, next, cwd, home, false)
	case *syntax.FuncDecl:
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
			actionInvalidateSaturatedValues(stmt, next, cwd, home)
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

func actionInvalidateSaturatedValues(stmt *syntax.Stmt, stable actionValues, cwd, home string) {
	for name := range stable {
		if strings.HasPrefix(name, actionKeptAlternatesKey) {
			delete(stable, name)
		}
	}
	clear := func() {
		for name := range stable {
			if strings.HasPrefix(name, actionFunctionValuePrefix) {
				stable[name] = actionFunctionUnknownValue
			} else if strings.HasPrefix(name, actionReadonlyValuePrefix) {
				stable[name] = "?"
			} else if name != actionKeptSaturatedKey {
				delete(stable, name)
			}
		}
	}
	syntax.Walk(stmt, func(node syntax.Node) bool {
		nested, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		actionForgetValues(nested, stable, cwd, home)
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
		temporaryAssignments := false
		if len(command.Assigns) > 0 && len(command.Args) > 0 {
			if program, fixed := StaticWord(command.Args[0], home); fixed {
				switch programBase(program) {
				case "eval", "source", ".", "export", "readonly", "set", "unset", "declare", "local", "typeset":
				default:
					temporaryAssignments = true
				}
			}
		}
		if len(command.Assigns) == 0 {
			if len(command.Args) == 0 {
				return []actionValues{values}
			}
			program, fixed := StaticWord(command.Args[0], home)
			if !fixed {
				return []actionValues{values}
			}
			if _, defined := values[actionFunctionValuePrefix+program]; !defined {
				switch programBase(program) {
				case "eval", "unset", "export", "printf", "builtin", "command", "readonly", "read", "mapfile", "readarray":
				default:
					return []actionValues{values}
				}
			}
		}
		next := maps.Clone(values)
		actionUpdateValuesAs(stmt, next, cwd, home, false)
		if temporaryAssignments {
			for _, assignment := range command.Assigns {
				if assignment.Name == nil {
					continue
				}
				name := assignment.Name.Value
				if before, known := values[name]; known {
					next[name] = before
				} else {
					delete(next, name)
				}
			}
		}
		return []actionValues{next}
	case *syntax.FuncDecl:
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
		if next, known := actionKeptWhileControl(command, values, cwd, home, steps); known {
			return next
		}
		condition := actionKeptStatements(command.Cond, []actionValues{values}, cwd, home, steps)
		if actionKeptSaturated(condition) {
			return condition
		}
		if len(command.Cond) > 0 && actionStaticCondition(command.Cond[len(command.Cond)-1], home) == -1 && !command.Until {
			return condition
		}
		return actionAppendValueCandidates(condition, actionKeptStatements(command.Do, condition, cwd, home, steps))
	case *syntax.ForClause:
		if next, known := actionKeptFixedFor(command, values, cwd, home, steps); known {
			return next
		}
		return actionAppendValueCandidates([]actionValues{values}, actionKeptStatements(command.Do, []actionValues{values}, cwd, home, steps))
	case *syntax.CaseClause:
		if next, known := actionKeptFixedCase(command, values, cwd, home, steps); known {
			return next
		}
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

// A fixed, non-globbing for-list runs once per item. The shared value
// tracker can then keep assignments made by that loop without retaining a
// path that was overwritten before the next command.
func actionKeptFixedFor(clause *syntax.ForClause, values actionValues, cwd, home string, steps *int) ([]actionValues, bool) {
	exit, beyond, ok := actionKeptFixedForFlow(clause, values, cwd, home, steps)
	if !ok {
		return nil, false
	}
	// No enclosing loop is read here, so a counted break leaves this one.
	for _, states := range beyond {
		exit = actionAppendValueCandidates(exit, states)
	}
	return exit, true
}

// actionKeptFixedForFlow returns the states that leave a fixed for list and,
// in beyond, those a counted break carries past it: beyond[i] also leaves
// i more enclosing loops.
func actionKeptFixedForFlow(clause *syntax.ForClause, values actionValues, cwd, home string, steps *int) ([]actionValues, [][]actionValues, bool) {
	name, items, ok := actionFixedForItems(clause, values, cwd, home)
	if !ok {
		return nil, nil, false
	}
	if len(items) == 0 {
		return []actionValues{values}, nil, true
	}
	current := []actionValues{values}
	var left []actionValues
	var beyond [][]actionValues
	for _, item := range items {
		var next []actionValues
		for _, candidate := range current {
			bound := maps.Clone(candidate)
			bound[name] = item
			flow := actionKeptLoopBody(clause.Do, []actionValues{bound}, cwd, home, steps)
			if states, saturated := flow.saturatedStates(); saturated {
				return states, nil, true
			}
			next = actionAppendValueCandidates(next, flow.ended)
			next = actionAppendValueCandidates(next, flow.continued)
			left = actionAppendValueCandidates(left, flow.broken)
			for level, states := range flow.beyond {
				for len(beyond) <= level {
					beyond = append(beyond, nil)
				}
				beyond[level] = actionAppendValueCandidates(beyond[level], states)
			}
			if actionKeptSaturated(next) {
				return next, nil, true
			}
			if actionKeptSaturated(left) {
				return left, nil, true
			}
		}
		current = next
		if len(current) == 0 {
			break
		}
	}
	return actionAppendValueCandidates(left, current), beyond, true
}

// actionFixedForItems returns the variable and the fixed items of a
// non-globbing for list.
func actionFixedForItems(clause *syntax.ForClause, values actionValues, cwd, home string) (string, []string, bool) {
	loop, ok := clause.Loop.(*syntax.WordIter)
	if !ok || clause.Select || loop.Name == nil || len(loop.Items) > 16 {
		return "", nil, false
	}
	items := make([]string, 0, len(loop.Items))
	for _, word := range loop.Items {
		item, known := actionWordValue(word, values, cwd, home)
		if !known {
			return "", nil, false
		}
		switch {
		case actionWordOneField(word):
			// Every expansion is quoted: the word is one item, and its
			// expanded text is not a pattern.
		case !wordExpandsParameter(word) && !strings.ContainsAny(item, "*?["):
		case simpleShellParameter(word) != "" && !strings.ContainsAny(item, "*?["):
			// An unquoted expansion splits at the field separators the
			// shell has: the default ones, or the IFS the command set.
			separators := " \t\n"
			if set, changed := values["IFS"]; changed {
				separators = set
			}
			fields := shellFields(item, separators)
			if len(items)+len(fields) > 16 {
				return "", nil, false
			}
			items = append(items, fields...)
			continue
		default:
			return "", nil, false
		}
		items = append(items, item)
	}
	return loop.Name.Value, items, true
}

// shellFields splits the text of an unquoted expansion as the shell does at
// the characters of ifs. A white space separator is dropped at the ends and
// merged with its neighbours; any other separator ends a field, empty or not.
func shellFields(text, ifs string) []string {
	if ifs == "" {
		if text == "" {
			return nil
		}
		return []string{text}
	}
	runes := []rune(text)
	separator := func(r rune) bool { return strings.ContainsRune(ifs, r) }
	space := func(r rune) bool { return (r == ' ' || r == '\t' || r == '\n') && separator(r) }
	var fields []string
	i := 0
	skipSpace := func() {
		for i < len(runes) && space(runes[i]) {
			i++
		}
	}
	skipSpace()
	for i < len(runes) {
		start := i
		for i < len(runes) && !separator(runes[i]) {
			i++
		}
		fields = append(fields, string(runes[start:i]))
		if i >= len(runes) {
			break
		}
		if space(runes[i]) {
			skipSpace()
			if i < len(runes) && separator(runes[i]) {
				i++
				skipSpace()
			}
		} else {
			i++
			skipSpace()
		}
	}
	return fields
}

// actionWordOneField reports a word whose expansions are all quoted and
// whose unquoted text has no pattern character, so the shell makes exactly
// one field of it.
func actionWordOneField(word *syntax.Word) bool {
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				return false
			}
		default:
			return false
		}
	}
	return len(word.Parts) > 0
}

// actionKeptWhileControl reads a while or until loop whose body runs break
// or continue. The loop leaves when its condition fails or a break runs;
// passes repeat until they reach no new state.
func actionKeptWhileControl(clause *syntax.WhileClause, values actionValues, cwd, home string, steps *int) ([]actionValues, bool) {
	if len(clause.Cond) == 0 || len(clause.Do) == 0 {
		return nil, false
	}
	for _, condition := range clause.Cond {
		if actionNodeRunsLoopControl(condition, home, false) {
			return nil, false
		}
	}
	controlled := false
	for _, stmt := range clause.Do {
		if actionNodeRunsLoopControl(stmt, home, false) {
			controlled = true
			break
		}
	}
	if !controlled {
		return nil, false
	}
	truth := actionStaticCondition(clause.Cond[len(clause.Cond)-1], home)
	if clause.Until {
		truth = -truth
	}
	states := []actionValues{values}
	seen := []actionValues{values}
	var left []actionValues
	for pass := 0; pass < 8 && len(states) > 0; pass++ {
		condition := actionKeptStatements(clause.Cond, states, cwd, home, steps)
		if actionKeptSaturated(condition) {
			return condition, true
		}
		if truth <= 0 {
			left = actionAppendValueCandidates(left, condition)
		}
		if truth < 0 {
			return left, true
		}
		flow := actionKeptLoopBody(clause.Do, condition, cwd, home, steps)
		if saturated, ok := flow.saturatedStates(); ok {
			return saturated, true
		}
		left = actionAppendValueCandidates(left, flow.broken)
		if actionKeptSaturated(left) {
			return left, true
		}
		var next []actionValues
		for _, state := range actionAppendValueCandidates(actionAppendValueCandidates(nil, flow.ended), flow.continued) {
			if !slices.ContainsFunc(seen, func(prior actionValues) bool { return maps.Equal(prior, state) }) {
				next = append(next, state)
				seen = append(seen, state)
			}
		}
		states = next
	}
	// A pass cap with states still running keeps them as candidates.
	left = actionAppendValueCandidates(left, states)
	if len(left) == 0 {
		// The loop never leaves; keep the entry state for what follows.
		return []actionValues{values}, true
	}
	return left, true
}

// actionLoopFlow holds the value states that leave part of a loop body:
// ended runs the following statement, continued starts the next item and
// broken leaves the loop.
type actionLoopFlow struct {
	ended, continued, broken []actionValues
	// beyond[i] leaves this loop and i+1 enclosing loops (break N, N > 1).
	beyond [][]actionValues
}

func (flow *actionLoopFlow) addBeyond(level int, states []actionValues) {
	for len(flow.beyond) <= level {
		flow.beyond = append(flow.beyond, nil)
	}
	flow.beyond[level] = actionAppendValueCandidates(flow.beyond[level], states)
}

func (flow *actionLoopFlow) add(other actionLoopFlow) {
	flow.ended = actionAppendValueCandidates(flow.ended, other.ended)
	flow.continued = actionAppendValueCandidates(flow.continued, other.continued)
	flow.broken = actionAppendValueCandidates(flow.broken, other.broken)
	for level, states := range other.beyond {
		flow.addBeyond(level, states)
	}
}

func (flow actionLoopFlow) saturatedStates() ([]actionValues, bool) {
	for _, states := range append([][]actionValues{flow.ended, flow.continued, flow.broken}, flow.beyond...) {
		if actionKeptSaturated(states) {
			return states, true
		}
	}
	return nil, false
}

// actionKeptLoopBody runs a loop body over states. It follows break and
// continue through blocks, if clauses and && or || lists with the static
// conditions the value tracker already uses.
func actionKeptLoopBody(statements []*syntax.Stmt, states []actionValues, cwd, home string, steps *int) actionLoopFlow {
	var flow actionLoopFlow
	for _, stmt := range statements {
		if len(states) == 0 {
			break
		}
		part := actionKeptLoopStatement(stmt, states, cwd, home, steps)
		if _, saturated := part.saturatedStates(); saturated {
			return part
		}
		flow.continued = actionAppendValueCandidates(flow.continued, part.continued)
		flow.broken = actionAppendValueCandidates(flow.broken, part.broken)
		for level, beyond := range part.beyond {
			flow.addBeyond(level, beyond)
		}
		states = part.ended
		if _, saturated := flow.saturatedStates(); saturated {
			return flow
		}
	}
	flow.ended = actionAppendValueCandidates(nil, states)
	return flow
}

func actionKeptLoopStatement(stmt *syntax.Stmt, states []actionValues, cwd, home string, steps *int) actionLoopFlow {
	if !actionNodeRunsLoopControl(stmt, home, false) {
		return actionLoopFlow{ended: actionUpdateValuesKept(stmt, states, cwd, home, steps)}
	}
	if !stmt.Background && !stmt.Negated && len(stmt.Redirs) == 0 {
		switch command := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			switch control, count := actionLoopControlCall(command, home); {
			case control == "break" && count == 1:
				return actionLoopFlow{broken: actionAppendValueCandidates(nil, states)}
			case control == "break":
				var flow actionLoopFlow
				flow.addBeyond(count-2, states)
				return flow
			case control == "continue" && count == 1:
				return actionLoopFlow{continued: actionAppendValueCandidates(nil, states)}
			}
		case *syntax.ForClause:
			// A nested fixed loop keeps its own controls; a counted break
			// in it leaves this loop as well.
			if !actionNestedLoopEscapesKnown(command, home) {
				break
			}
			var flow actionLoopFlow
			for _, state := range states {
				exit, beyond, fixed := actionKeptFixedForFlow(command, state, cwd, home, steps)
				if !fixed {
					return actionUnknownLoopFlow(stmt, states, cwd, home, steps)
				}
				if actionKeptSaturated(exit) {
					return actionLoopFlow{ended: exit}
				}
				flow.ended = actionAppendValueCandidates(flow.ended, exit)
				for level, escaped := range beyond {
					if level == 0 {
						flow.broken = actionAppendValueCandidates(flow.broken, escaped)
					} else {
						flow.addBeyond(level-1, escaped)
					}
				}
			}
			return flow
		case *syntax.Block:
			return actionKeptLoopBody(command.Stmts, states, cwd, home, steps)
		case *syntax.IfClause:
			return actionKeptLoopIf(stmt, command, states, cwd, home, steps)
		case *syntax.CaseClause:
			// The selected items of a fixed case run in order, as one list.
			var flow actionLoopFlow
			for _, state := range states {
				items, fixed := actionFixedCaseItems(command, state, cwd, home)
				if !fixed {
					return actionUnknownLoopFlow(stmt, states, cwd, home, steps)
				}
				var selected []*syntax.Stmt
				for _, item := range items {
					selected = append(selected, item.Stmts...)
				}
				flow.add(actionKeptLoopBody(selected, []actionValues{state}, cwd, home, steps))
				if _, saturated := flow.saturatedStates(); saturated {
					return flow
				}
			}
			return flow
		case *syntax.BinaryCmd:
			if (command.Op == syntax.AndStmt || command.Op == syntax.OrStmt) && !actionNodeRunsLoopControl(command.X, home, false) {
				left := actionUpdateValuesKept(command.X, states, cwd, home, steps)
				if actionKeptSaturated(left) {
					return actionLoopFlow{ended: left}
				}
				truth := actionStaticCondition(command.X, home)
				var flow actionLoopFlow
				if truth == 0 || command.Op == syntax.AndStmt && truth < 0 || command.Op == syntax.OrStmt && truth > 0 {
					flow.ended = actionAppendValueCandidates(nil, left)
				}
				if truth == 0 || command.Op == syntax.AndStmt && truth > 0 || command.Op == syntax.OrStmt && truth < 0 {
					flow.add(actionKeptLoopStatement(command.Y, left, cwd, home, steps))
				}
				return flow
			}
		}
	}
	return actionUnknownLoopFlow(stmt, states, cwd, home, steps)
}

func actionKeptLoopIf(whole *syntax.Stmt, clause *syntax.IfClause, states []actionValues, cwd, home string, steps *int) actionLoopFlow {
	if len(clause.Cond) == 0 { // else
		return actionKeptLoopBody(clause.Then, states, cwd, home, steps)
	}
	for _, condition := range clause.Cond {
		if actionNodeRunsLoopControl(condition, home, false) {
			return actionUnknownLoopFlow(whole, states, cwd, home, steps)
		}
	}
	condition := actionKeptStatements(clause.Cond, states, cwd, home, steps)
	if actionKeptSaturated(condition) {
		return actionLoopFlow{ended: condition}
	}
	truth := actionStaticCondition(clause.Cond[len(clause.Cond)-1], home)
	var flow actionLoopFlow
	if truth >= 0 {
		flow.add(actionKeptLoopBody(clause.Then, condition, cwd, home, steps))
	}
	if truth <= 0 {
		if clause.Else == nil {
			flow.ended = actionAppendValueCandidates(flow.ended, condition)
		} else {
			flow.add(actionKeptLoopIf(whole, clause.Else, condition, cwd, home, steps))
		}
	}
	return flow
}

// A statement that may run a loop control in a form this reader does not
// follow may leave the loop, start the next item or finish, so each value
// it can reach stays a candidate on every outcome.
func actionUnknownLoopFlow(stmt *syntax.Stmt, states []actionValues, cwd, home string, steps *int) actionLoopFlow {
	ended := actionUpdateValuesKept(stmt, states, cwd, home, steps)
	if actionKeptSaturated(ended) {
		return actionLoopFlow{ended: ended}
	}
	reach := actionAppendValueCandidates(actionAppendValueCandidates(nil, states), ended)
	flow := actionLoopFlow{ended: reach, continued: reach, broken: reach}
	// A counted break in it may also leave enclosing loops.
	syntax.Walk(stmt, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
			return false
		case *syntax.CallExpr:
			if control, count := actionLoopControlCall(node, home); control == "break" && count > 1 {
				for level := 0; level <= count-2; level++ {
					flow.addBeyond(level, reach)
				}
			}
		}
		return true
	})
	return flow
}

// actionLoopControlCall names a plain break or continue with its loop
// count: one when absent, or a fixed positive count.
func actionLoopControlCall(call *syntax.CallExpr, home string) (string, int) {
	if len(call.Assigns) != 0 || len(call.Args) == 0 || len(call.Args) > 2 {
		return "", 0
	}
	name, known := StaticWord(call.Args[0], home)
	if !known || name != "break" && name != "continue" {
		return "", 0
	}
	count := 1
	if len(call.Args) == 2 {
		word, fixed := StaticWord(call.Args[1], home)
		number, err := strconv.Atoi(word)
		if !fixed || err != nil || number < 1 || number > 16 {
			return "", 0
		}
		count = number
	}
	return name, count
}

// actionNestedLoopEscapesKnown reports that every control in a nested loop
// that may reach past it is a counted break this reader carries out. A
// counted continue or another form keeps the conservative reading.
func actionNestedLoopEscapesKnown(clause *syntax.ForClause, home string) bool {
	known := true
	syntax.Walk(clause, func(node syntax.Node) bool {
		if !known {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
			return false
		case *syntax.WhileClause:
			known = !actionNodeRunsLoopControl(node, home, true)
			return false
		case *syntax.CallExpr:
			if actionLoopControlWord(node, home, true) {
				if control, count := actionLoopControlCall(node, home); control != "break" || count < 2 {
					known = false
				}
			}
		}
		return known
	})
	return known
}

// actionNodeRunsLoopControl reports a break or continue in root that can
// leave the loop running root. A subshell, substitution or function body
// runs its own controls; a nested loop keeps its own unless a count other
// than one may reach past it (nested).
func actionNodeRunsLoopControl(root syntax.Node, home string, nested bool) bool {
	found := false
	syntax.Walk(root, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
			return false
		case *syntax.ForClause, *syntax.WhileClause:
			if node != root {
				found = actionNodeRunsLoopControl(node, home, true)
				return false
			}
		case *syntax.CallExpr:
			found = actionLoopControlWord(node, home, nested)
		}
		return !found
	})
	return found
}

func actionLoopControlWord(call *syntax.CallExpr, home string, nested bool) bool {
	if len(call.Args) == 0 {
		return false
	}
	name, known := StaticWord(call.Args[0], home)
	if !known {
		return false
	}
	switch name {
	case "break", "continue":
		if !nested {
			return true
		}
		if len(call.Args) == 1 {
			return false
		}
		count, fixed := StaticWord(call.Args[1], home)
		return !fixed || count != "1"
	case "eval", "builtin", "command":
		for _, arg := range call.Args[1:] {
			if word, fixed := StaticWord(arg, home); fixed && (strings.Contains(word, "break") || strings.Contains(word, "continue")) {
				return true
			}
		}
	}
	return false
}

// Resolve only simple, fixed case patterns. Other pattern forms retain the
// existing conservative candidate reading.
func actionKeptFixedCase(clause *syntax.CaseClause, values actionValues, cwd, home string, steps *int) ([]actionValues, bool) {
	items, known := actionFixedCaseItems(clause, values, cwd, home)
	if !known {
		return nil, false
	}
	current := []actionValues{values}
	for _, item := range items {
		current = actionKeptStatements(item.Stmts, current, cwd, home, steps)
		if actionKeptSaturated(current) {
			return current, true
		}
	}
	return current, true
}

func actionFixedCaseItems(clause *syntax.CaseClause, values actionValues, cwd, home string) ([]*syntax.CaseItem, bool) {
	word, known := actionWordValue(clause.Word, values, cwd, home)
	if !known || len(clause.Items) > 16 {
		return nil, false
	}
	var selected []*syntax.CaseItem
	falling := false
	for _, item := range clause.Items {
		if item.Op != syntax.Break && item.Op != syntax.Fallthrough && item.Op != syntax.Resume {
			return nil, false
		}
		itemMatches := falling
		if !falling {
			for _, patternWord := range item.Patterns {
				if len(patternWord.Parts) != 1 {
					return nil, false
				}
				literal, ok := patternWord.Parts[0].(*syntax.Lit)
				if !ok || !actionSimpleCasePattern(literal.Value) {
					return nil, false
				}
				pattern := literal.Value
				if pattern == "*" || strings.HasSuffix(pattern, "*") && strings.HasPrefix(word, strings.TrimSuffix(pattern, "*")) || pattern == word {
					itemMatches = true
				}
			}
		}
		if !itemMatches {
			continue
		}
		selected = append(selected, item)
		falling = item.Op == syntax.Fallthrough
		if item.Op == syntax.Break {
			break
		}
	}
	return selected, true
}

func actionSimpleCasePattern(pattern string) bool {
	if pattern == "" {
		return false
	}
	for i := 0; i < len(pattern); i++ {
		char := pattern[i]
		if char == '*' && (i == len(pattern)-1 || pattern == "*") {
			continue
		}
		if !strings.ContainsRune("_-./+:@%,", rune(char)) && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

// 1 is true, -1 false, and 0 unknown. Only shell builtins whose result is
// fixed without inspecting the environment narrow a branch here.
func actionStaticCondition(stmt *syntax.Stmt, home string) int {
	if stmt == nil {
		return 0
	}
	if block, ok := stmt.Cmd.(*syntax.Block); ok && len(block.Stmts) == 1 && len(stmt.Redirs) == 0 && !stmt.Background && !stmt.Negated {
		return actionStaticCondition(block.Stmts[0], home)
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(stmt.Redirs) != 0 {
		return 0
	}
	if len(call.Args) == 0 && len(call.Assigns) > 0 {
		for _, assignment := range call.Assigns {
			if assignment.Value == nil {
				continue
			}
			commandSubstitution := false
			syntax.Walk(assignment.Value, func(node syntax.Node) bool {
				switch node.(type) {
				case *syntax.CmdSubst, *syntax.ProcSubst:
					commandSubstitution = true
				}
				return !commandSubstitution
			})
			if commandSubstitution {
				return 0
			}
		}
		return 1
	}
	if len(call.Args) != 1 || len(call.Assigns) != 0 {
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
		if readonly := values[actionReadonlyValuePrefix+name]; readonly != "" {
			if readonly == "?" {
				delete(values, name)
			}
			return
		}
		value, fixed := actionWordValue(assign.Value, values, cwd, home)
		if assign.Value == nil && !assign.Naked && assign.Array == nil && assign.Index == nil {
			// name= holds the empty string.
			value, fixed = "", true
		}
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
			if declaration.Variant != nil && declaration.Variant.Value == "readonly" && assign.Name != nil {
				if assign.Value != nil {
					update(assign)
				}
				values[actionReadonlyValuePrefix+assign.Name.Value] = "1"
			} else if declaration.Variant != nil && declaration.Variant.Value == "export" && assign.Naked && assign.Value == nil {
				// export NAME keeps the value NAME already has.
				continue
			} else {
				update(assign)
			}
		}
		return
	}
	if function, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
		if function.Name != nil {
			values[actionFunctionValuePrefix+function.Name.Value] = actionFunctionValue(function, home)
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
				actionForgetValues(nested, values, cwd, home)
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
	if _, defined := values[actionFunctionValuePrefix+program]; defined {
		if _, known := actionApplyFunctionValue(program, values, 0); !known {
			actionClearFunctionValues(values)
		}
		return
	}
	if program == "builtin" || program == "command" {
		if len(call.Args) < 2 {
			return
		}
		wrapped, known := StaticWord(call.Args[1], home)
		if !known || wrapped != "printf" {
			return
		}
		program = "printf"
	}
	if program != "printf" && programBase(program) == "printf" {
		return
	}
	switch programBase(program) {
	case "readonly":
		for _, arg := range call.Args[1:] {
			word, known := StaticWord(arg, home)
			if !known {
				continue
			}
			name, value, assigned := strings.Cut(word, "=")
			if !actionEvalAssignmentName(name) {
				continue
			}
			if assigned && values[actionReadonlyValuePrefix+name] == "" {
				values[name] = value
			}
			values[actionReadonlyValuePrefix+name] = "1"
		}
	case "eval":
		if len(call.Args) == 2 {
			if body, fixed := actionWordValue(call.Args[1], values, cwd, home); fixed && len(body) <= 4096 {
				if parsed, ok := parseShell(body); ok && len(parsed.Stmts) > 0 && len(parsed.Stmts) <= 8 {
					var assignments []*syntax.Assign
					for _, nested := range parsed.Stmts {
						plain, direct := nested.Cmd.(*syntax.CallExpr)
						if !direct || nested.Background || nested.Negated || len(nested.Redirs) != 0 ||
							len(plain.Args) != 0 || len(plain.Assigns) != 1 || plain.Assigns[0].Name == nil ||
							!actionEvalAssignmentName(plain.Assigns[0].Name.Value) {
							assignments = nil
							break
						}
						assignments = append(assignments, plain.Assigns[0])
					}
					if len(assignments) == len(parsed.Stmts) {
						for _, assignment := range assignments {
							update(assignment)
						}
						return
					}
				}
			}
		}
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
		functionOnly := false
		for _, arg := range call.Args[1:] {
			if flag, ok := StaticWord(arg, home); ok && flag == "-f" {
				functionOnly = true
			}
		}
		for _, arg := range call.Args[1:] {
			if name, ok := StaticWord(arg, home); ok {
				if functionOnly {
					delete(values, actionFunctionValuePrefix+name)
				} else if values[actionReadonlyValuePrefix+name] == "" {
					delete(values, name)
				}
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
		name, formatIndex, ok := actionPrintfBoundName(call, values, cwd, home)
		names, count, unknown := actionPrintfFormatBindings(call, values, cwd, home)
		defer func() {
			actionForgetPrintfFormatBindings(values, names, unknown)
			for _, target := range names {
				if count != "" && name != target && values[actionReadonlyValuePrefix+target] == "" && target != "HOME" && target != "PWD" {
					values[target] = count
				}
			}
		}()
		if !ok {
			if name != "" {
				delete(values, name)
				delete(values, name+"[0]")
			}
			return
		}
		if name == "" {
			return
		}
		delete(values, name+"[0]")
		if readonly := values[actionReadonlyValuePrefix+name]; readonly != "" {
			if readonly == "?" {
				delete(values, name)
			}
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
		if format == "%b" {
			if len(call.Args) == formatIndex+2 {
				if argument, known := actionWordValue(call.Args[formatIndex+1], values, cwd, home); known {
					if decoded, plain := actionPrintfLiteral(argument); plain {
						values[name] = decoded
						return
					}
				}
			}
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
