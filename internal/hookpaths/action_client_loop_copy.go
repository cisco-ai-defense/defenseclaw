// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
// The proof needs the copy that runs to be the system one: nothing before the
// loop may assign PATH or a name the environment already carries (a loader
// variable reaches cp), and the cp that PATH finds must not lie in the
// project. whole reports that the loop is the last statement, so every
// reading of the command comes from the proved call.
func actionClientLoopCopyNoEffectCalls(file *syntax.File, cwd, home string) (calls map[*syntax.CallExpr]bool, whole bool) {
	if file == nil || !filepath.IsAbs(cwd) || home == "" || actionClientLoopCopySourceStartupUnknown() {
		return nil, false
	}
	assignments := actionValues{"HOME": home, "PWD": cwd}
	for i, top := range file.Stmts {
		loop, ok := actionClientLoopCopyTop(top, cwd, home)
		if !ok {
			name, value, assigned := actionClientLoopCopyAssignment(top, home)
			switch {
			case assigned && actionClientLoopCopyAssignmentReachesChild(name):
				return nil, false
			case assigned:
				assignments[name] = value
			case !actionClientLoopCopyNoop(top, cwd, home):
				return nil, false
			}
			continue
		}
		iter, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iter.Name == nil || len(iter.Items) == 0 || len(loop.Do) != 1 {
			return nil, false
		}
		stmt := loop.Do[0]
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 ||
			len(call.Assigns) != 0 || len(call.Args) < 3 {
			return nil, false
		}
		program, fixed := staticProgramWord(call.Args[0], home)
		if !fixed || programBase(program) != "cp" && programBase(program) != "gcp" ||
			!plainCopyOptions(call.Args[1:len(call.Args)-2], home) {
			return nil, false
		}
		source := call.Args[len(call.Args)-2]
		loopAssignments := maps.Clone(assignments)
		delete(loopAssignments, iter.Name.Value)
		if actionClientLoopCopyKnownEmptySource(source, loopAssignments) &&
			!actionClientLoopCopySourceVariableMayChange(source) &&
			actionClientCopyProgramIsSystem(program, cwd) {
			return map[*syntax.CallExpr]bool{call: true}, i == len(file.Stmts)-1
		}
		return nil, false
	}
	return nil, false
}

// A plain assignment reaches the programs the command starts when the name
// is PATH or a loader variable, or when the environment already exports it.
// IFS is never read by cp.
func actionClientLoopCopyAssignmentReachesChild(name string) bool {
	if name == "PATH" || strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") {
		return true
	}
	if name == "IFS" {
		return false
	}
	_, exported := os.LookupEnv(name)
	return exported
}

// actionClientCopyProgramIsSystem reports whether the program word names the
// system copy: the file the shell starts (the word itself when it holds a
// path, otherwise the first directory of PATH that holds the name) is
// followed through its links, and the file reached must be a regular file
// that other users cannot write, in a system program directory, and named
// for a copy (cp, gcp, or the multi-call binary that provides it). A project
// link to the system cp is therefore the system cp, while a script or binary
// named cp that sits anywhere else, in the project or in a temporary
// directory, is not. The name alone never decides: a program that only
// carries the name cp may write anything (rel-1-0-6:GAP-0880).
func actionClientCopyProgramIsSystem(program, cwd string) bool {
	candidate := ""
	if strings.ContainsAny(program, `/\`) {
		candidate = program
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cwd, candidate)
		}
	} else {
	search:
		for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
			if dir == "" {
				dir = "."
			}
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(cwd, dir)
			}
			for _, name := range []string{program, program + ".exe"} {
				if _, err := pathLstat(filepath.Join(dir, name)); err == nil {
					candidate = filepath.Join(dir, name)
					break search
				}
			}
		}
	}
	if candidate == "" {
		return false
	}
	resolved, err := pathEvalSymlinks(candidate)
	if err != nil {
		return false
	}
	info, err := pathLstat(resolved)
	if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return false
	}
	switch strings.TrimSuffix(strings.ToLower(filepath.Base(resolved)), ".exe") {
	case "cp", "gcp", "coreutils", "busybox":
	default:
		return false
	}
	resolved = filepath.ToSlash(resolved)
	for _, root := range actionClientSystemProgramRoots {
		if strings.HasPrefix(resolved, root) {
			return true
		}
	}
	return false
}

// The program directories the system or the package manager of the platform
// installs a copy in. The match is on a whole directory name.
var actionClientSystemProgramRoots = []string{
	"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/libexec/",
	"/opt/homebrew/", "/usr/local/Cellar/",
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

// copyOpensNoSource reports a reading of command that is one plain copy
// whose source operand is the empty string, in a command whose every
// reading comes from a copy the loop proof above shows opens no source: cp
// stats its source first and fails, so the call writes nothing wherever the
// destination lies. A reading the straight-line walk gives for such a call
// (IFS=; cp "$IFS" d) names the destination only because the walk
// substituted the value, so it is not described as a write. The reading
// alone proves neither the value the source has when the copy runs nor
// which cp runs, so the command must be the proved loop (rel-1-0-6:GAP-0880,
// GAP-0885).
func copyOpensNoSource(reading, command, cwd, home string) bool {
	if !plainEmptySourceCopy(reading, home) {
		return false
	}
	file, parsed := parseShell(command)
	if !parsed {
		return false
	}
	calls, whole := actionClientLoopCopyNoEffectCalls(file, cwd, home)
	return whole && len(calls) != 0
}

// describedCopyReading is the text the hook client lists for a reading, and
// whether it lists it. A plain copy with an empty source whose command is not
// proved is described under the name of the program: the gateway reads an
// explicit program path outside the system directories as an unknown program,
// so a program that carries only the name cp (anywhere but the system copy)
// would otherwise hide the write it can make to the link
// (rel-1-0-6:GAP-0880).
func describedCopyReading(reading, command, cwd, home string) (string, bool) {
	if !plainEmptySourceCopy(reading, home) {
		return reading, true
	}
	if copyOpensNoSource(reading, command, cwd, home) {
		return "", false
	}
	file, parsed := parseShell(reading)
	if !parsed {
		return reading, true
	}
	word := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[0]
	program, _ := staticProgramWord(word, home)
	start, end := int(word.Pos().Offset()), int(word.End().Offset())
	if !strings.ContainsAny(program, `/\`) || start < 0 || end > len(reading) || start >= end {
		return reading, true
	}
	return reading[:start] + programBase(program) + reading[end:], true
}

func plainEmptySourceCopy(reading, home string) bool {
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
	if !plainCopyOptions(call.Args[1:len(call.Args)-2], home) {
		return false
	}
	source, fixed := StaticWord(call.Args[len(call.Args)-2], home)
	return fixed && source == ""
}

// Only options that take no value: -t, -S and their long forms name a
// directory or a suffix and change which words are the sources.
func plainCopyOptions(words []*syntax.Word, home string) bool {
	for _, word := range words {
		option, fixed := StaticWord(word, home)
		if !fixed || option != "--" && !plainCopyFlags.MatchString(option) {
			return false
		}
	}
	return true
}

var plainCopyFlags = regexp.MustCompile(`^-[fipnrRavdPLHux]+$`)
