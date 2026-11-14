// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// NoDereferenceTouchShape reports the bounded touch form whose -h option
// changes link entries. Its operands must have one fixed expansion, or one
// fixed pattern supplied by a preceding assignment.
func NoDereferenceTouchShape(command, cwd, home string) bool {
	_, ok := noDereferenceTouchOperands(command, cwd, home, false)
	return ok
}

// NoDereferenceTouchSafe checks that every entry changed by that form is
// ordinary in the hook's filesystem view. Links are checked at their own
// entry, while regular files are checked by identity as usual.
func NoDereferenceTouchSafe(command, cwd, home string) bool {
	safe, _ := noDereferenceTouchStatus(command, cwd, home)
	return safe
}

// noDereferenceTouchStatus reads the entries touch changes. A regular file
// is checked by identity; -h changes a symbolic link's entry instead.
//
// A shell startup that can change what the statement runs only withholds the
// safe proof. The entries the command names are still read, so a protected
// file reached through another name (a hard link) is reported whatever the
// account's environment holds. Before GAP-0293, any exported bash function
// (RHEL's which, a host profile's helpers) dropped the protected reading
// too, and the quoted hard link reached the protected file.
func noDereferenceTouchStatus(command, cwd, home string) (safe, protectedTarget bool) {
	if !strings.Contains(command, "touch") ||
		!strings.Contains(command, "-h") && !strings.Contains(command, "--no-dereference") {
		return false, false
	}
	operands, ok := noDereferenceTouchOperands(command, cwd, home, true)
	if !ok {
		return false, false
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	memo := NewTargetMemo()
	unknown := false
	for _, operand := range operands {
		path := OperandPath(operand, cwd)
		parent, known := memo.resolveWriteTarget(filepath.Dir(path))
		if !known {
			unknown = true
			continue
		}
		entry := filepath.Join(parent, filepath.Base(path))
		if protected.has(entry) || samePathName(entry, ssh) ||
			samePathName(parent, ssh) || strings.HasPrefix(parent, ssh+string(filepath.Separator)) {
			protectedTarget = true
			continue
		}
		info, err := pathLstat(entry)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			unknown = true
			continue
		}
		if protectedReachPathWith(entry, protected, ssh, memo) {
			protectedTarget = true
		}
	}
	return !unknown && !protectedTarget && !noDereferenceTouchStartupUnknown(), protectedTarget
}

// noDereferenceTouchStartupUnknown reports a shell startup that can change
// what the touch statement runs: a startup file (BASH_ENV, ENV), or an
// exported function that bash calls instead of touch or gtouch (bash accepts
// slashes in a function name, so /usr/bin/touch can be one) or for a missing
// program (command_not_found_handle). The statement calls no other function,
// so an exported function of another name leaves the proof intact. An export
// spelled neither name%% (bash 4.3+) nor name() (older patched bash) is
// unknown.
func noDereferenceTouchStartupUnknown() bool {
	if os.Getenv("BASH_ENV") != "" || os.Getenv("ENV") != "" {
		return true
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		function, exported := strings.CutPrefix(name, "BASH_FUNC_")
		if !exported {
			continue
		}
		function, modern := strings.CutSuffix(function, "%%")
		if !modern {
			var patched bool
			if function, patched = strings.CutSuffix(function, "()"); !patched {
				return true
			}
		}
		base := function[strings.LastIndexByte(function, '/')+1:]
		if base == "touch" || base == "gtouch" || function == "command_not_found_handle" {
			return true
		}
	}
	return false
}

func noDereferenceTouchOperands(command, cwd, home string, expandPatterns bool) ([]string, bool) {
	if !filepath.IsAbs(cwd) || home == "" ||
		!strings.Contains(command, "touch") ||
		!strings.Contains(command, "-h") && !strings.Contains(command, "--no-dereference") {
		return nil, false
	}
	file, parsed := parseShell(command)
	if !parsed || len(file.Stmts) == 0 || len(file.Stmts) > 2 {
		return nil, false
	}
	values := actionValues{"HOME": home, "PWD": cwd}
	if len(file.Stmts) == 2 {
		stmt := file.Stmts[0]
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 ||
			len(call.Args) != 0 || len(call.Assigns) != 1 {
			return nil, false
		}
		assign := call.Assigns[0]
		if assign.Name == nil || assign.Name.Value == "HOME" || assign.Name.Value == "PWD" ||
			assign.Value == nil || assign.Append || assign.Array != nil || assign.Index != nil {
			return nil, false
		}
		if !noDereferenceTouchLiteralWord(assign.Value) {
			return nil, false
		}
		value, fixed := actionWordValueWithGlob(assign.Value, values, cwd, home, true)
		if strings.Contains(value, "\\") {
			if actionWordHasBraceText(assign.Value) {
				return nil, false
			}
			fields, err := shellparse.Fields(&expand.Config{Env: expand.ListEnviron("HOME=" + home)}, assign.Value)
			if err != nil || len(fields) != 1 {
				return nil, false
			}
			value = fields[0]
		}
		if !fixed || value == "" || strings.ContainsAny(value, " \t\r\n\x00\x1f") {
			return nil, false
		}
		values[assign.Name.Value] = value
	}
	stmt := file.Stmts[len(file.Stmts)-1]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 ||
		len(call.Assigns) != 0 || len(call.Args) < 3 {
		return nil, false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed || programBase(program) != "touch" && programBase(program) != "gtouch" {
		return nil, false
	}
	options, noDeref := true, false
	var operands []string
	for _, word := range call.Args[1:] {
		if options {
			if option, fixed := StaticWord(word, home); fixed && strings.HasPrefix(option, "-") && option != "-" {
				switch option {
				case "-h", "--no-dereference":
					noDeref = true
					continue
				case "--":
					options = false
					continue
				default:
					return nil, false
				}
			}
		}
		fields := actionMentionBraceFields(word, home)
		if len(fields) == 0 {
			fields = actionExactOversizedTouchFields(word, home)
		}
		if len(fields) == 0 {
			if !noDereferenceTouchLiteralWord(word) {
				if len(word.Parts) != 1 || actionSoleParameter(word) == "" {
					return nil, false
				}
			}
			value, known := actionWordValueWithGlob(word, values, cwd, home, true)
			if noDereferenceTouchLiteralWord(word) && !actionWordHasUnquotedGlob(word, command) && strings.Contains(value, "\\") {
				expanded, err := shellparse.Fields(&expand.Config{Env: expand.ListEnviron("HOME=" + home)}, word)
				if err != nil || len(expanded) != 1 {
					return nil, false
				}
				value = expanded[0]
			}
			if !known || value == "" || strings.ContainsAny(value, " \t\r\n\x00\x1f") {
				return nil, false
			}
			fields = []string{value}
		}
		activePattern := actionWordHasUnquotedGlob(word, command)
		if len(word.Parts) == 1 {
			_, unquotedParameter := word.Parts[0].(*syntax.ParamExp)
			activePattern = activePattern || unquotedParameter
		}
		for _, field := range fields {
			if activePattern && strings.ContainsAny(field, "*?[") {
				if !expandPatterns {
					operands = append(operands, field)
					continue
				}
				patternField := field
				if len(fields) == 1 && noDereferenceTouchLiteralWord(word) && !actionWordHasBraceText(word) {
					var known bool
					patternField, known = noDereferenceTouchPattern(word, home)
					if !known {
						return nil, false
					}
				}
				pattern := OperandPath(patternField, cwd)
				matches, complete, unseen := actionExpandGlob(pattern, cwd, false, true,
					func() bool { return actionShellProfileMayDotglob(home) })
				if !complete || unseen {
					return nil, false
				}
				operands = append(operands, matches...)
			} else {
				operands = append(operands, field)
			}
			if len(operands) > 1024 {
				return nil, false
			}
		}
	}
	return operands, noDeref && len(operands) > 0
}

func noDereferenceTouchLiteralWord(word *syntax.Word) bool {
	if word == nil {
		return false
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

// noDereferenceTouchPattern keeps quoted pattern characters literal while
// retaining the active glob characters in an unquoted part of the same word.
func noDereferenceTouchPattern(word *syntax.Word, home string) (string, bool) {
	var out strings.Builder
	quoted := func(value string) bool {
		if runtime.GOOS == "windows" && strings.ContainsAny(value, "*?[]") {
			return false
		}
		for _, r := range value {
			if strings.ContainsRune("\\*?[]", r) {
				out.WriteByte('\\')
			}
			out.WriteRune(r)
		}
		return true
	}
	for _, item := range word.Parts {
		switch part := item.(type) {
		case *syntax.Lit:
			out.WriteString(part.Value)
		case *syntax.SglQuoted:
			if !quoted(part.Value) {
				return "", false
			}
		case *syntax.DblQuoted:
			fields, err := shellparse.Fields(&expand.Config{Env: expand.ListEnviron("HOME=" + home)},
				&syntax.Word{Parts: []syntax.WordPart{part}})
			if err != nil || len(fields) != 1 || !quoted(fields[0]) {
				return "", false
			}
		default:
			return "", false
		}
	}
	pattern := out.String()
	if actionWordTildePrefix(word) {
		pattern = strings.TrimRight(home, "/") + pattern[1:]
	}
	return pattern, true
}
