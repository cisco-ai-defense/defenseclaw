// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// PossibleTargetDecision is a path mention that may reach an SSH key file,
// without a named target in the reader's current view.
const PossibleTargetDecision = "possible-target"

// SSHKeyMentionGrade separates a named path from a pattern or unresolved
// path. It uses the same Windows words and bounded assignment substitutions
// as the target reader. A named path wins even if an earlier word was only
// possible. The caller applies the policy tier to a possible answer.
func SSHKeyMentionGrade(command, cwd, home string) string {
	context := actionSSHGradeContext{memo: NewTargetMemo(), grades: make(map[actionSSHGradeKey]string)}
	return sshKeyMentionGrade(command, cwd, home, 0, &context)
}

type actionSSHGradeKey struct {
	command, cwd string
	depth        int
}

type actionSSHGradeContext struct {
	memo   *TargetMemo
	grades map[actionSSHGradeKey]string
}

func sshKeyMentionGrade(command, cwd, home string, depth int, context *actionSSHGradeContext) string {
	if command == "" || !actionWindowsHome(home) || len(command) > MaxPayloadBytes || depth >= 8 {
		return ""
	}
	key := actionSSHGradeKey{command: command, cwd: cwd, depth: depth}
	if grade, ok := context.grades[key]; ok {
		return grade
	}
	grade := sshKeyMentionGradeUncached(command, cwd, home, depth, context)
	context.grades[key] = grade
	return grade
}

func sshKeyMentionGradeUncached(command, cwd, home string, depth int, context *actionSSHGradeContext) string {
	possible := actionPOSIXCopyMayVary(command, home)
	displayOnly := ProvedDisplayOnlyHereString(command) || actionReadOnlyNestedShellPattern(command, home) ||
		ProvedReadOnlyPOSIXCommand(command, home) || actionGradeReadOnlyPOSIXCommand(command, home)
	memo := context.memo
	if actionNamedPOSIXWrite(command, cwd, home, depth, context) {
		return ProtectedTargetDecision
	}
	for _, target := range actionKnownPOSIXCopyTargets(command, cwd, home) {
		resolved, ok := actionWindowsPath(target, cwd, home)
		root, rootOK := actionWindowsPath(home, cwd, home)
		if ok && rootOK && resolved == root+"/.ssh" {
			return ProtectedTargetDecision
		}
		if protected, _ := actionWindowsProtected(target, cwd, home, false); protected {
			return ProtectedTargetDecision
		}
		if ok && actionWindowsLinkReachesKeyFile(resolved, home, memo) {
			return ProtectedTargetDecision
		}
	}
	for _, grammar := range []actionWindowsGrammar{0, actionWindowsPlainGrammar, actionWindowsPlainGrammar | actionWindowsBackslashEscapes} {
		scan := actionWindowsScan(actionWindowsBlankPatchText(command), grammar)
		if !scan.ok {
			continue
		}
		readOnly := displayOnly || actionKnownReadOnlyWindows(scan.words)
		spans := actionWindowsResolvedSpans(scan.words, cwd, home)
		spanReadOnly := make([]bool, len(spans))
		var rawReadOnly []bool
		if runtime.GOOS == "windows" {
			rawReadOnly = make([]bool, len(scan.words))
		}
		for i, span := range spans {
			spanReadOnly[i] = readOnly || actionKnownReadOnlyWindowsStatement(span.words) ||
				actionReadOnlyFixedPOSIXShellBody(span.words, home)
			if spanReadOnly[i] {
				for j := span.start; j < span.end && j < len(rawReadOnly); j++ {
					rawReadOnly[j] = true
				}
			}
			if len(span.words) > 1 && (programBase(span.words[0]) == "copy-item" || programBase(span.words[0]) == "cpi") {
				for _, word := range span.words[1:] {
					if strings.HasPrefix(word, "-") {
						possible = true
					}
				}
			}
		}
		if !displayOnly && actionWindowsInvokedTextMention(scan.words, cwd, home, 0, false, memo) {
			return ProtectedTargetDecision
		}
		check := func(word, dir string, consumed, readOnly bool) bool {
			for _, candidate := range strings.FieldsFunc(word, func(r rune) bool {
				return strings.ContainsRune(" \t\r\n'\"(),;|&<>{}=", r)
			}) {
				candidate = strings.ReplaceAll(candidate, "`", "")
				if candidate == "" {
					continue
				}
				if strings.ContainsAny(candidate, "*?[") {
					if actionWindowsProtectedGlobReach(candidate, dir, home) || actionWindowsDynamicKeyPath(candidate) {
						possible = true
						if consumed && !readOnly {
							return true
						}
						if !readOnly && runtime.GOOS == "windows" && actionWindowsGlobNamesKeyFile(candidate, dir, home, memo) {
							return true
						}
					}
					continue
				}
				if protected, _ := actionWindowsProtected(candidate, dir, home, false); protected {
					return true
				}
				if resolved, ok := actionWindowsPath(candidate, dir, home); ok {
					if actionWindowsLinkReachesKeyFile(resolved, home, memo) {
						return true
					}
				} else if actionWindowsUnresolvedUnderSSH(candidate, dir, home) || actionWindowsDynamicKeyPath(candidate) {
					possible = true
				}
			}
			return false
		}
		for i, word := range scan.words {
			wordReadOnly := readOnly
			if len(rawReadOnly) != 0 {
				wordReadOnly = wordReadOnly || rawReadOnly[i]
			}
			if check(word, cwd, false, wordReadOnly) {
				return ProtectedTargetDecision
			}
		}
		effectiveCWD := cwd
		var directoryStack []string
		for i, span := range spans {
			if body, ok := actionFixedPOSIXShellBody(span.words); ok &&
				sshKeyMentionGrade(body, effectiveCWD, home, depth+1, context) == ProtectedTargetDecision {
				return ProtectedTargetDecision
			}
			consumed := len(span.words) > 0 && !actionWindowsTextStatement(span.words) &&
				!spanReadOnly[i]
			if len(span.words) > 0 && actionWindowsTextStatement(span.words) &&
				!actionWindowsPrintOnlyDisplays(scan, span.start, span.end) {
				consumed = true
			}
			for _, word := range span.words {
				if check(word, effectiveCWD, consumed, spanReadOnly[i]) {
					return ProtectedTargetDecision
				}
			}
			actionWindowsAdvanceDirectory(span.words, home, &effectiveCWD, &directoryStack)
		}
	}
	if possible {
		return PossibleTargetDecision
	}
	return ""
}

// Follow a fixed shell body with the same bounded grade reader. The Windows
// word scanner keeps the body as one word, including its own separators.
func actionFixedPOSIXShellBody(words []string) (string, bool) {
	if len(words) > 0 && programBase(words[0]) == "env" {
		index := 1
		for index < len(words) && (words[index] == "-i" || words[index] == "--ignore-environment" || words[index] == "--") {
			index++
		}
		words = words[index:]
	}
	if len(words) != 3 || !posixShellProgram(programBase(words[0])) ||
		words[1] != "-c" && words[1] != "-lc" ||
		strings.ContainsAny(words[2], "\x00\r\n") {
		return "", false
	}
	return words[2], true
}

// A child shell whose fixed body is entirely read-only contributes only a
// possible path mention. Each surrounding statement is graded separately.
func actionReadOnlyFixedPOSIXShellBody(words []string, home string) bool {
	return actionReadOnlyFixedPOSIXShellBodyAtDepth(words, home, 0)
}

func actionReadOnlyFixedPOSIXShellBodyAtDepth(words []string, home string, depth int) bool {
	if os.Getenv("BASH_ENV") != "" {
		return false
	}
	body, ok := actionFixedPOSIXShellBody(words)
	if len(words) > 0 && programBase(words[0]) == "env" {
		index := 1
		for index < len(words) && (words[index] == "-i" || words[index] == "--ignore-environment" || words[index] == "--") {
			index++
		}
		words = words[index:]
	}
	if !ok || programBase(words[0]) != "bash" || words[1] != "-c" || body == "" ||
		strings.ContainsAny(body, "$`\\%!^'\r\n") {
		return false
	}
	child, parsed := parseShell(body)
	return parsed && actionGradeReadOnlyPOSIXFile(child, home, depth+1)
}

// Keep the display proof bounded and structural. A fixed child body may be
// surrounded by shell control statements, but every reached command must
// still be a known reader before the whole command is display-only.
func actionGradeReadOnlyPOSIXCommand(command, home string) bool {
	if os.Getenv("BASH_ENV") != "" || !strings.Contains(command, "*/*") {
		return false
	}
	file, parsed := parseShell(command)
	return parsed && actionGradeReadOnlyPOSIXFile(file, home, 0)
}

func actionGradeReadOnlyPOSIXFile(file *syntax.File, home string, depth int) bool {
	if depth >= 8 || len(file.Stmts) == 0 || len(file.Stmts) > 128 {
		return false
	}
	var walk func(*syntax.Stmt, int) bool
	var walkList func([]*syntax.Stmt, int) bool
	walkList = func(stmts []*syntax.Stmt, level int) bool {
		for _, stmt := range stmts {
			if !walk(stmt, level) {
				return false
			}
		}
		return true
	}
	walk = func(stmt *syntax.Stmt, level int) bool {
		if stmt == nil || level >= 8 || stmt.Background || stmt.Coprocess || stmt.Negated {
			return false
		}
		for _, redirect := range stmt.Redirs {
			if !actionDiscardRedirect(redirect, home) {
				return false
			}
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(cmd.Assigns) != 0 || len(cmd.Args) == 0 {
				return false
			}
			if actionKnownReadOnlyShell(&syntax.File{Stmts: []*syntax.Stmt{stmt}}, home) {
				return true
			}
			program, known := StaticWord(cmd.Args[0], home)
			if !known {
				return false
			}
			if programBase(program) == "bash" || programBase(program) == "env" {
				words := make([]string, 0, len(cmd.Args))
				for _, arg := range cmd.Args {
					word, fixed := StaticWord(arg, home)
					if !fixed {
						return false
					}
					words = append(words, word)
				}
				return actionReadOnlyFixedPOSIXShellBodyAtDepth(words, home, level)
			}
			switch programBase(program) {
			case "pwd", "true", ":":
				return len(cmd.Args) == 1
			case "cd":
				if len(cmd.Args) == 2 {
					destination, fixed := StaticWord(cmd.Args[1], home)
					return fixed && destination == "."
				}
			}
		case *syntax.BinaryCmd:
			return walk(cmd.X, level+1) && walk(cmd.Y, level+1)
		case *syntax.Subshell:
			return walkList(cmd.Stmts, level+1)
		case *syntax.Block:
			return walkList(cmd.Stmts, level+1)
		case *syntax.IfClause:
			if !walkList(cmd.Cond, level+1) || !walkList(cmd.Then, level+1) {
				return false
			}
			for next := cmd.Else; next != nil; next = next.Else {
				if !walkList(next.Cond, level+1) || !walkList(next.Then, level+1) {
					return false
				}
			}
			return true
		}
		return false
	}
	return walkList(file.Stmts, depth)
}

// Resolve fixed write targets across POSIX statement bodies while retaining
// scalar and directory state. Uncertain operands keep the possible grade.
func actionNamedPOSIXWrite(command, cwd, home string, depth int, context *actionSSHGradeContext) bool {
	if !strings.Contains(command, ">") && !strings.Contains(command, "-c") &&
		!strings.Contains(strings.ToLower(command), "cp") {
		return false
	}
	file, parsed := parseShell(command)
	if !parsed {
		return false
	}
	state := actionGradePOSIXState{values: actionValues{"HOME": home, "PWD": cwd}, cwd: cwd}
	seen := 0
	var walk func(*syntax.Stmt, *actionGradePOSIXState, int) bool
	var walkList func([]*syntax.Stmt, *actionGradePOSIXState, int) bool
	walkList = func(stmts []*syntax.Stmt, current *actionGradePOSIXState, level int) bool {
		for _, stmt := range stmts {
			if walk(stmt, current, level) {
				return true
			}
		}
		return false
	}
	walk = func(stmt *syntax.Stmt, current *actionGradePOSIXState, level int) bool {
		if stmt == nil || level >= 8 || seen >= 128 {
			return false
		}
		seen++
		if stmt.Background || stmt.Coprocess {
			child := current.clone()
			copyStmt := *stmt
			copyStmt.Background, copyStmt.Coprocess = false, false
			return walk(&copyStmt, &child, level+1)
		}
		for _, redirect := range stmt.Redirs {
			if redirect.Word == nil || !actionOutputRedirect(redirect.Op) {
				continue
			}
			target, known := actionWordValue(redirect.Word, current.values, current.cwd, home)
			if known && actionNamedSSHKeyPath(target, current.cwd, home, context.memo) {
				return true
			}
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			current.values["PWD"] = current.cwd
			actionUpdateValues(stmt, current.values, current.cwd, home)
			if target, known := actionKnownPOSIXCopyCallTarget(cmd, current.values, current.cwd, home); known &&
				actionNamedSSHKeyPath(target, current.cwd, home, context.memo) {
				return true
			}
			if body, ok := actionPOSIXShellCallBody(cmd, current.values, current.cwd, home); ok &&
				sshKeyMentionGrade(body, current.cwd, home, depth+1, context) == ProtectedTargetDecision {
				return true
			}
			actionGradePOSIXAdvanceDirectory(cmd, current.values, home, &current.cwd, &current.stack)
		case *syntax.BinaryCmd:
			if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
				left, right := current.clone(), current.clone()
				return walk(cmd.X, &left, level+1) || walk(cmd.Y, &right, level+1)
			}
			return walk(cmd.X, current, level+1) || walk(cmd.Y, current, level+1)
		case *syntax.Subshell:
			child := current.clone()
			return walkList(cmd.Stmts, &child, level+1)
		case *syntax.Block:
			return walkList(cmd.Stmts, current, level+1)
		case *syntax.IfClause:
			if walkList(cmd.Cond, current, level+1) || walkList(cmd.Then, current, level+1) {
				return true
			}
			for next := cmd.Else; next != nil; next = next.Else {
				if walkList(next.Cond, current, level+1) || walkList(next.Then, current, level+1) {
					return true
				}
			}
		}
		return false
	}
	return walkList(file.Stmts, &state, 0)
}

type actionGradePOSIXState struct {
	values actionValues
	cwd    string
	stack  []string
}

func (s actionGradePOSIXState) clone() actionGradePOSIXState {
	values := make(actionValues, len(s.values))
	for name, value := range s.values {
		values[name] = value
	}
	s.values = values
	s.stack = append([]string(nil), s.stack...)
	return s
}

func actionNamedSSHKeyPath(target, cwd, home string, memo *TargetMemo) bool {
	if protected, _ := actionWindowsProtected(target, cwd, home, false); protected {
		return true
	}
	resolved, known := actionWindowsPath(target, cwd, home)
	return known && actionWindowsLinkReachesKeyFile(resolved, home, memo)
}

func actionPOSIXShellCallBody(call *syntax.CallExpr, values actionValues, cwd, home string) (string, bool) {
	args := call.Args
	if len(args) > 0 {
		program, known := actionWordValue(args[0], values, cwd, home)
		if known && programBase(program) == "env" {
			index := 1
			for index < len(args) {
				option, fixed := StaticWord(args[index], home)
				if !fixed || option != "-i" && option != "--ignore-environment" && option != "--" {
					break
				}
				index++
			}
			args = args[index:]
		}
	}
	if len(args) != 3 {
		return "", false
	}
	program, known := actionWordValue(args[0], values, cwd, home)
	if !known || !posixShellProgram(programBase(program)) {
		return "", false
	}
	option, known := StaticWord(args[1], home)
	if !known || option != "-c" && option != "-lc" {
		return "", false
	}
	return actionWordValue(args[2], values, cwd, home)
}

func actionKnownPOSIXCopyCallTarget(call *syntax.CallExpr, values actionValues, cwd, home string) (string, bool) {
	if len(call.Args) < 2 || len(call.Assigns) != 0 {
		return "", false
	}
	program, known := StaticWord(call.Args[0], home)
	if !known || programBase(program) != "cp" && programBase(program) != "gcp" {
		return "", false
	}
	if target, known := actionPosixCopyVariableTarget(call, values, cwd, home); known {
		return target, true
	}
	args := make([]string, 0, len(call.Args)-1)
	for _, word := range call.Args[1:] {
		value, known := actionWordValue(word, values, cwd, home)
		if !known || strings.ContainsAny(value, "\x00 \t\n") {
			return "", false
		}
		args = append(args, value)
	}
	parsed := cpOperands(args, makeStatic(len(args)))
	return parsed.destination, parsed.ok
}

// The grade reader uses Windows lexical paths even when its POSIX reading
// runs on a Linux gateway. The ordinary directory reader uses host paths.
func actionGradePOSIXAdvanceDirectory(call *syntax.CallExpr, values actionValues, home string, cwd *string, stack *[]string) {
	if len(call.Args) == 0 {
		return
	}
	program, known := actionWordValue(call.Args[0], values, *cwd, home)
	if !known {
		return
	}
	switch programBase(program) {
	case "popd":
		if len(*stack) != 0 {
			*cwd = (*stack)[len(*stack)-1]
			*stack = (*stack)[:len(*stack)-1]
		}
		return
	case "cd", "pushd":
	default:
		return
	}
	index := 1
	if index < len(call.Args) {
		if option, fixed := StaticWord(call.Args[index], home); fixed && option == "--" {
			index++
		}
	}
	if len(call.Args)-index > 1 {
		return
	}
	destination := home
	if index < len(call.Args) {
		destination, known = actionWordValue(call.Args[index], values, *cwd, home)
		if !known {
			return
		}
	}
	resolved, known := actionWindowsPath(destination, *cwd, home)
	if !known {
		return
	}
	if programBase(program) == "pushd" {
		*stack = append(*stack, *cwd)
	}
	*cwd = resolved
}

// A runtime-expanded copy operand or source pattern leaves the target set
// uncertain until the connector's shell has supplied its values.
func actionPOSIXCopyMayVary(command, home string) bool {
	if !strings.Contains(strings.ToLower(command), "cp") {
		return false
	}
	file, parsed := parseShell(command)
	if !parsed {
		return false
	}
	for _, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			continue
		}
		program, fixed := StaticWord(call.Args[0], home)
		if !fixed || programBase(program) != "cp" && programBase(program) != "gcp" {
			continue
		}
		for _, word := range call.Args[1:] {
			uncertain := false
			syntax.Walk(word, func(node syntax.Node) bool {
				if parameter, ok := node.(*syntax.ParamExp); ok &&
					(parameter.Param == nil || parameter.Param.Value != "HOME") {
					uncertain = true
				}
				return !uncertain
			})
			if uncertain || strings.ContainsAny(actionWordLiteralText(word), "*?[") {
				return true
			}
		}
	}
	return false
}

// Existing copy operand and scalar-value readers decide which word is the
// destination after an ordinary assignment and shell field splitting.
func actionKnownPOSIXCopyTargets(command, cwd, home string) []string {
	if !strings.Contains(strings.ToLower(command), "cp") {
		return nil
	}
	file, parsed := parseShell(command)
	if !parsed {
		return nil
	}
	values := actionValues{"HOME": home, "PWD": cwd}
	effectiveCWD := cwd
	var directoryStack []string
	var targets []string
	for _, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(stmt.Redirs) != 0 || stmt.Background || stmt.Negated {
			clear(values)
			values["HOME"] = home
			continue
		}
		values["PWD"] = effectiveCWD
		actionUpdateValues(stmt, values, effectiveCWD, home)
		if len(call.Args) > 1 {
			if target, known := actionPosixCopyVariableTarget(call, values, effectiveCWD, home); known {
				if resolved, ok := actionWindowsPath(target, effectiveCWD, home); ok {
					targets = append(targets, resolved)
				}
			} else if program, fixed := StaticWord(call.Args[0], home); fixed &&
				(programBase(program) == "cp" || programBase(program) == "gcp") {
				args := make([]string, 0, len(call.Args)-1)
				for _, word := range call.Args[1:] {
					value, known := actionWordValue(word, values, effectiveCWD, home)
					if !known || strings.ContainsAny(value, "*?[]\x00 \t\n") {
						args = nil
						break
					}
					args = append(args, value)
				}
				if len(args) > 0 {
					if parsed := cpOperands(args, makeStatic(len(args))); parsed.ok {
						if resolved, ok := actionWindowsPath(parsed.destination, effectiveCWD, home); ok {
							targets = append(targets, resolved)
						}
					}
				}
			}
		}
		actionGradePOSIXAdvanceDirectory(call, values, home, &effectiveCWD, &directoryStack)
	}
	return targets
}

// The body is read by the existing POSIX shell reader after a fixed shell
// launch. A startup script may add work, so it is never a display proof.
func actionReadOnlyNestedShellPattern(command, home string) bool {
	if os.Getenv("BASH_ENV") != "" || !strings.Contains(strings.ToLower(command), "bash") {
		return false
	}
	file, parsed := parseShell(command)
	if !parsed || len(file.Stmts) == 0 || len(file.Stmts) > 128 {
		return false
	}
	seenChild := false
	for _, stmt := range file.Stmts {
		if len(stmt.Redirs) != 0 || stmt.Background || stmt.Negated || stmt.Coprocess {
			return false
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
			return false
		}
		args := call.Args
		program, fixed := StaticWord(args[0], home)
		if !fixed {
			return false
		}
		if programBase(program) == "env" {
			args = args[1:]
		}
		if len(args) == 3 {
			program, fixed = StaticWord(args[0], home)
			option, known := StaticWord(args[1], home)
			if fixed && known && programBase(program) == "bash" && option == "-c" {
				// StaticWord returns the body after the outer shell has
				// processed its quotes, including escaped inner quotes.
				body, known := StaticWord(args[2], home)
				if !known || body == "" || strings.ContainsAny(body, "$`\\%!^'\r\n") {
					return false
				}
				child, parsed := parseShell(body)
				if !parsed || !actionKnownReadOnlyShell(child, home) {
					return false
				}
				seenChild = true
				continue
			}
		}
		if actionKnownReadOnlyShell(&syntax.File{Stmts: []*syntax.Stmt{stmt}}, home) ||
			actionFixedTextEcho(call) {
			continue
		}
		switch programBase(program) {
		case "pwd", "true", ":":
			if len(call.Args) == 1 {
				continue
			}
		}
		return false
	}
	return seenChild
}

// A complete native expansion can turn a pattern into a named disk target.
// An incomplete walk remains possible and is left to the strict policy tier.
func actionWindowsGlobNamesKeyFile(pattern, cwd, home string, memo *TargetMemo) bool {
	pattern = strings.ReplaceAll(pattern, `\`, "/")
	for _, prefix := range []string{"~", "$HOME", "${HOME}", "$env:USERPROFILE", "${env:USERPROFILE}", "%USERPROFILE%"} {
		if strings.HasPrefix(strings.ToLower(pattern), strings.ToLower(prefix)+"/") {
			pattern = filepath.ToSlash(home) + pattern[len(prefix):]
			break
		}
	}
	if !filepath.IsAbs(filepath.FromSlash(pattern)) {
		pattern = filepath.ToSlash(filepath.Join(cwd, filepath.FromSlash(pattern)))
	}
	paths, complete, _ := actionExpandGlob(filepath.FromSlash(pattern), "", false, true, func() bool { return true })
	if !complete {
		return false
	}
	keys := memo.ProtectedAuthorizedKeysPaths(home)
	for _, candidate := range paths {
		resolved, ok := memo.resolveWriteTarget(candidate)
		if !ok {
			continue
		}
		for _, key := range keys {
			if samePathName(resolved, key) {
				return true
			}
		}
	}
	return false
}
