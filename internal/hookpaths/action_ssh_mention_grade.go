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
	if command == "" || !actionWindowsHome(home) || len(command) > MaxPayloadBytes {
		return ""
	}
	possible := actionPOSIXCopyMayVary(command, home)
	displayOnly := ProvedDisplayOnlyHereString(command) || actionReadOnlyNestedShellPattern(command, home) ||
		ProvedReadOnlyPOSIXCommand(command, home)
	memo := NewTargetMemo()
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
		for _, span := range actionWindowsResolvedSpans(scan.words, cwd, home) {
			if len(span.words) > 1 && (programBase(span.words[0]) == "copy-item" || programBase(span.words[0]) == "cpi") {
				for _, word := range span.words[1:] {
					if strings.HasPrefix(word, "-") {
						possible = true
					}
				}
			}
		}
		if actionWindowsInvokedTextMention(scan.words, cwd, home, 0, false, memo) {
			return ProtectedTargetDecision
		}
		check := func(word string, consumed bool) bool {
			for _, candidate := range strings.FieldsFunc(word, func(r rune) bool {
				return strings.ContainsRune(" \t\r\n'\"(),;|&<>{}=", r)
			}) {
				candidate = strings.ReplaceAll(candidate, "`", "")
				if candidate == "" {
					continue
				}
				if strings.ContainsAny(candidate, "*?[") {
					if actionWindowsProtectedGlobReach(candidate, cwd, home) || actionWindowsDynamicKeyPath(candidate) {
						possible = true
						if consumed && !readOnly {
							return true
						}
						if !readOnly && runtime.GOOS == "windows" && actionWindowsGlobNamesKeyFile(candidate, cwd, home, memo) {
							return true
						}
					}
					continue
				}
				if protected, _ := actionWindowsProtected(candidate, cwd, home, false); protected {
					return true
				}
				if resolved, ok := actionWindowsPath(candidate, cwd, home); ok {
					if actionWindowsLinkReachesKeyFile(resolved, home, memo) {
						return true
					}
				} else if actionWindowsUnresolvedUnderSSH(candidate, cwd, home) || actionWindowsDynamicKeyPath(candidate) {
					possible = true
				}
			}
			return false
		}
		for _, word := range scan.words {
			if check(word, false) {
				return ProtectedTargetDecision
			}
		}
		for _, span := range actionWindowsResolvedSpans(scan.words, cwd, home) {
			consumed := len(span.words) > 0 && !actionWindowsTextStatement(span.words) &&
				!actionKnownReadOnlyWindowsStatement(span.words)
			if len(span.words) > 0 && actionWindowsTextStatement(span.words) &&
				!actionWindowsPrintOnlyDisplays(scan, span.start, span.end) {
				consumed = true
			}
			for _, word := range span.words {
				if check(word, consumed) {
					return ProtectedTargetDecision
				}
			}
		}
	}
	if possible {
		return PossibleTargetDecision
	}
	return ""
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
	values := actionValues{"HOME": home}
	var targets []string
	for _, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(stmt.Redirs) != 0 || stmt.Background || stmt.Negated {
			clear(values)
			values["HOME"] = home
			continue
		}
		if len(call.Args) == 0 && len(call.Assigns) == 1 {
			assignment := call.Assigns[0]
			if assignment.Name != nil && assignment.Value != nil && !assignment.Append {
				if value, known := actionWordValue(assignment.Value, values, cwd, home); known {
					values[assignment.Name.Value] = value
					continue
				}
			}
		}
		if len(call.Args) > 1 {
			if target, known := actionPosixCopyVariableTarget(call, values, cwd, home); known {
				targets = append(targets, target)
			} else if program, fixed := StaticWord(call.Args[0], home); fixed &&
				(programBase(program) == "cp" || programBase(program) == "gcp") {
				args := make([]string, 0, len(call.Args)-1)
				for _, word := range call.Args[1:] {
					value, known := actionWordValue(word, values, cwd, home)
					if !known || strings.ContainsAny(value, "*?[]\x00 \t\n") {
						args = nil
						break
					}
					args = append(args, value)
				}
				if len(args) > 0 {
					if parsed := cpOperands(args, makeStatic(len(args))); parsed.ok {
						targets = append(targets, parsed.destination)
					}
				}
			}
		}
		clear(values)
		values["HOME"] = home
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
	if !parsed || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) < 3 {
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
	if len(args) != 3 {
		return false
	}
	program, fixed = StaticWord(args[0], home)
	option, known := StaticWord(args[1], home)
	if !fixed || !known || programBase(program) != "bash" || option != "-c" {
		return false
	}
	body := actionWordLiteralText(args[2])
	if body == "" || strings.ContainsAny(body, "$`\\%!^\"'\r\n") {
		return false
	}
	child, parsed := parseShell(body)
	return parsed && actionKnownReadOnlyShell(child, home)
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
