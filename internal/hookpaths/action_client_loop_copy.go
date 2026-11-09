// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A fixed for-word list gives each copy destination one concrete value.
// This positive client fact lets a managed gateway judge a link it cannot
// follow through ProtectHome. Earlier statements and other body calls must
// leave the current directory, iterator and link unchanged.
func actionClientLoopCopyDestinationProtected(command, cwd, home string) bool {
	return loopCopyDestinationProtected(command, cwd, home, false)
}

// LoopCopyDestinationProtected checks fixed loop destinations of copy calls
// in the gateway's own filesystem view. Move and install calls have different
// destination-link behavior and are left to their existing readers.
func LoopCopyDestinationProtected(command, cwd, home string) bool {
	return loopCopyDestinationProtected(command, cwd, home, true)
}

func loopCopyDestinationProtected(command, cwd, home string, copyOnly bool) bool {
	if !filepath.IsAbs(cwd) || home == "" || !strings.Contains(command, "for") {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	assignments := actionValues{"HOME": home, "PWD": cwd}
	for _, top := range file.Stmts {
		loop, ok := actionClientLoopCopyTop(top, cwd, home)
		if !ok {
			if name, value, assigned := actionClientLoopCopyAssignment(top, home); assigned {
				assignments[name] = value
			} else if !actionClientLoopCopyNoop(top, cwd, home) {
				return false
			}
			continue
		}
		iter, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iter.Name == nil || len(iter.Items) == 0 {
			return false
		}
		loopAssignments := maps.Clone(assignments)
		delete(loopAssignments, iter.Name.Value)
		var destination *syntax.Word
		for _, stmt := range loop.Do {
			call, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) == 0 {
				return false
			}
			if candidate, ok := actionClientLoopCopyDestination(call, loopAssignments, cwd, home, copyOnly); ok {
				if destination != nil {
					return false
				}
				destination = candidate
			} else if !actionClientLoopCopyNoop(stmt, cwd, home) {
				return false
			}
		}
		if destination == nil {
			return false
		}
		usesLoopName := false
		syntax.Walk(destination, func(part syntax.Node) bool {
			if param, ok := part.(*syntax.ParamExp); ok && param.Param != nil && param.Param.Value == iter.Name.Value {
				usesLoopName = true
			}
			return true
		})
		if !usesLoopName {
			return false
		}
		for _, item := range iter.Items {
			value, fixed := StaticWord(item, home)
			if !fixed || value == "" || strings.ContainsAny(value, "*?[]\x00\x1f") {
				return false
			}
			loopValues := actionValues{"HOME": home, "PWD": cwd, iter.Name.Value: value}
			if target, known := actionWordValue(destination, loopValues, cwd, home); known &&
				actionClientProtectedPath(target, cwd, protected, ssh) {
				return true
			}
		}
		// A preceding copy loop does not replace a destination link. Keep
		// checking later loops, and forget the iterator's final value.
		delete(assignments, iter.Name.Value)
	}
	return false
}

func actionClientLoopCopyAssignment(stmt *syntax.Stmt, home string) (string, string, bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return "", "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return "", "", false
	}
	assign := call.Assigns[0]
	if assign.Name == nil || assign.Append || assign.Array != nil || assign.Index != nil ||
		assign.Name.Value == "HOME" || assign.Name.Value == "PWD" {
		return "", "", false
	}
	if assign.Value == nil {
		return assign.Name.Value, "", true
	}
	value, fixed := StaticWord(assign.Value, home)
	return assign.Name.Value, value, fixed && !strings.ContainsAny(value, "*?[]\x00\x1f")
}

func actionClientLoopCopyTop(stmt *syntax.Stmt, cwd, home string) (*syntax.ForClause, bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return nil, false
	}
	if loop, ok := stmt.Cmd.(*syntax.ForClause); ok {
		return loop, true
	}
	if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt &&
		actionClientLoopCopyNoop(pair.X, cwd, home) {
		return actionClientLoopCopyTop(pair.Y, cwd, home)
	}
	return nil, false
}

func actionClientLoopCopyNoop(stmt *syntax.Stmt, cwd, home string) bool {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed {
		return false
	}
	switch program {
	case "true", ":":
		return len(call.Args) == 1
	case "cd":
		if len(call.Args) != 2 {
			return false
		}
		value, fixed := StaticWord(call.Args[1], home)
		return fixed && samePathName(OperandPath(value, cwd), cwd)
	case "echo":
		for _, arg := range call.Args[1:] {
			if _, fixed := StaticWord(arg, home); !fixed {
				return false
			}
		}
		return true
	}
	return false
}

func actionClientLoopCopyDestination(call *syntax.CallExpr, assignments actionValues, cwd, home string, copyOnly bool) (*syntax.Word, bool) {
	if len(call.Args) < 3 {
		return nil, false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed {
		return nil, false
	}
	base := programBase(program)
	if base != "cp" && base != "gcp" && base != "mv" && base != "install" {
		return nil, false
	}
	if copyOnly && base != "cp" && base != "gcp" {
		return nil, false
	}
	if !copyOnly && len(assignments) > 2 && base != "cp" && base != "gcp" {
		// Earlier assignments are only tracked for copy sources. Keep move
		// and install on their existing entry semantics.
		return nil, false
	}
	for i := 1; i < len(call.Args)-2; i++ {
		option, fixed := StaticWord(call.Args[i], home)
		if !fixed {
			return nil, false
		}
		if base == "install" && option == "-m" && i+1 < len(call.Args)-2 {
			i++
			mode, fixed := StaticWord(call.Args[i], home)
			if !fixed || mode == "" || strings.Trim(mode, "01234567") != "" {
				return nil, false
			}
			continue
		}
		switch option {
		case "--":
			if i != len(call.Args)-3 {
				return nil, false
			}
		case "-f", "-i", "--force", "--interactive":
			if base == "install" {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	sourceWord := call.Args[len(call.Args)-2]
	source, fixed := StaticWord(sourceWord, home)
	endOfOptions := false
	if len(call.Args) > 3 {
		option, fixed := StaticWord(call.Args[len(call.Args)-3], home)
		endOfOptions = fixed && option == "--"
	}
	if !fixed {
		if base != "cp" && base != "gcp" || len(sourceWord.Parts) != 1 {
			return nil, false
		}
		if _, quoted := sourceWord.Parts[0].(*syntax.DblQuoted); !quoted {
			return nil, false
		}
		if !actionClientLoopCopySourceVariableMayChange(sourceWord) && !actionClientLoopCopySourceStartupUnknown() {
			value, known := actionWordValue(sourceWord, assignments, cwd, home)
			if !known && actionClientLoopCopyKnownEmptySource(sourceWord, assignments) {
				value, known = "", true
			}
			if known && (value == "" || strings.HasPrefix(value, "-") && !endOfOptions) {
				return nil, false
			}
		}
		return call.Args[len(call.Args)-1], true
	}
	if source == "" || strings.HasPrefix(source, "-") && !endOfOptions || strings.ContainsAny(source, "*?[]\x00\x1f") {
		return nil, false
	}
	return call.Args[len(call.Args)-1], true
}

// Only a quoted expansion of an assigned empty scalar can establish a
// source that cp will not open. Keep this narrower than the general word
// evaluator: other expansion operators can supply a source or run a command.
func actionClientLoopCopyKnownEmptySource(word *syntax.Word, assignments actionValues) bool {
	if len(word.Parts) != 1 {
		return false
	}
	quoted, ok := word.Parts[0].(*syntax.DblQuoted)
	if !ok || len(quoted.Parts) != 1 {
		return false
	}
	param, ok := quoted.Parts[0].(*syntax.ParamExp)
	if !ok || param.Param == nil || param.Excl || param.Length || param.Width || param.IsSet ||
		param.Index != nil || param.Repl != nil || param.NestedParam != nil || param.Flags != nil ||
		len(param.Modifiers) != 0 {
		return false
	}
	value, assigned := assignments[param.Param.Value]
	if !assigned || value != "" {
		return false
	}
	if param.Slice != nil {
		if param.Exp != nil {
			return false
		}
		if !actionClientPlainSliceIndex(param.Slice.Offset) {
			return false
		}
		return param.Slice.Length == nil || actionClientPlainSliceIndex(param.Slice.Length)
	}
	if param.Exp == nil {
		return true
	}
	switch param.Exp.Op {
	case syntax.AlternateUnsetOrNull, syntax.ErrorUnset, syntax.DefaultUnset:
		return true
	case syntax.AlternateUnset:
		return actionClientPlainEmptyWord(param.Exp.Word)
	case syntax.RemSmallPrefix, syntax.RemLargePrefix, syntax.RemSmallSuffix, syntax.RemLargeSuffix:
		return actionClientPlainPatternWord(param.Exp.Word)
	default:
		return false
	}
}

func actionClientPlainSliceIndex(expr syntax.ArithmExpr) bool {
	if expr == nil {
		return false
	}
	var printed strings.Builder
	if syntax.NewPrinter().Print(&printed, expr) != nil {
		return false
	}
	value := printed.String()
	if value == "" || strings.Trim(value, "0123456789") != "" {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 32)
	return err == nil
}

func actionClientPlainEmptyWord(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return true
	}
	if len(word.Parts) != 1 {
		return false
	}
	switch part := word.Parts[0].(type) {
	case *syntax.Lit:
		return part.Value == ""
	case *syntax.SglQuoted:
		return part.Value == ""
	case *syntax.DblQuoted:
		for _, inner := range part.Parts {
			literal, ok := inner.(*syntax.Lit)
			if !ok || literal.Value != "" {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func actionClientPlainPatternWord(word *syntax.Word) bool {
	if word == nil {
		return true
	}
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				if _, ok := inner.(*syntax.Lit); !ok {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// A plain copy in a fixed loop with one assigned empty source cannot open a
// source file. The literal operand reader uses this narrow proof before it
// lists the destination; other statements keep their usual write readings.
func actionClientLoopCopyNoEffectCalls(file *syntax.File, cwd, home string) map[*syntax.CallExpr]bool {
	if file == nil || !filepath.IsAbs(cwd) || home == "" || actionClientLoopCopySourceStartupUnknown() {
		return nil
	}
	assignments := actionValues{"HOME": home, "PWD": cwd}
	noEffect := map[*syntax.CallExpr]bool{}
	for _, top := range file.Stmts {
		loop, ok := actionClientLoopCopyTop(top, cwd, home)
		if !ok {
			if name, value, assigned := actionClientLoopCopyAssignment(top, home); assigned {
				assignments[name] = value
			} else if !actionClientLoopCopyNoop(top, cwd, home) {
				break
			}
			continue
		}
		iter, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iter.Name == nil || len(iter.Items) == 0 || len(loop.Do) != 1 {
			break
		}
		stmt := loop.Do[0]
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 ||
			len(call.Assigns) != 0 || len(call.Args) != 3 {
			break
		}
		program, fixed := staticProgramWord(call.Args[0], home)
		if !fixed || programBase(program) != "cp" && programBase(program) != "gcp" {
			break
		}
		loopAssignments := maps.Clone(assignments)
		delete(loopAssignments, iter.Name.Value)
		if actionClientLoopCopyKnownEmptySource(call.Args[1], loopAssignments) &&
			!actionClientLoopCopySourceVariableMayChange(call.Args[1]) {
			noEffect[call] = true
		}
		break
	}
	return noEffect
}

func actionClientLoopCopySourceVariableMayChange(word *syntax.Word) bool {
	mayChange := false
	syntax.Walk(word, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok && param.Param != nil {
			// These values can be refreshed by Bash after a plain assignment.
			// Other assigned shell variables keep their known empty value
			// throughout the admitted straight-line loop.
			switch param.Param.Value {
			case "_", "BASHPID", "BASH_ARGC", "BASH_COMMAND", "BASH_SUBSHELL", "COLUMNS", "DIRSTACK",
				"EPOCHREALTIME", "EPOCHSECONDS", "EUID", "GROUPS", "HISTCMD", "LINENO", "LINES",
				"OPTIND", "PIPESTATUS", "PPID", "RANDOM", "SECONDS", "SHELLOPTS", "SRANDOM", "UID":
				mayChange = true
			}
		}
		return !mayChange
	})
	return mayChange
}

func actionClientLoopCopySourceStartupUnknown() bool {
	if os.Getenv("BASH_ENV") != "" || os.Getenv("ENV") != "" {
		return true
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "BASH_FUNC_") {
			return true
		}
	}
	return false
}

// copyOpensNoSource reports a reading that is one plain copy whose source
// operand is the empty string. cp stats its source first and fails, so the
// call writes nothing wherever the destination lies; the loop proof above
// reaches the same answer for a loop whose source variable is empty. A
// reading the straight-line walk gives for such a call (IFS=; cp "$IFS" d,
// src=; cp "$src" d) names the destination only because the walk
// substituted the value, so it is not described as a write.
func copyOpensNoSource(reading, home string) bool {
	if actionClientLoopCopySourceStartupUnknown() {
		return false
	}
	file, parsed := parseShell(reading)
	if !parsed || len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) < 3 {
		return false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed || programBase(program) != "cp" && programBase(program) != "gcp" {
		return false
	}
	// Only options that take no value: -t, -S and their long forms name a
	// directory or a suffix and change which words are the sources.
	for _, word := range call.Args[1 : len(call.Args)-2] {
		option, fixed := StaticWord(word, home)
		if !fixed || option != "--" && !plainCopyFlags.MatchString(option) {
			return false
		}
	}
	source, fixed := StaticWord(call.Args[len(call.Args)-2], home)
	return fixed && source == ""
}

var plainCopyFlags = regexp.MustCompile(`^-[fipnrRavdPLHux]+$`)
