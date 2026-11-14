// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// NoDereferenceTouchShape reports the bounded touch form whose -h option
// changes link entries. Its operands must have one fixed expansion, or one
// fixed pattern supplied by a preceding assignment.
func NoDereferenceTouchShape(command, cwd, home string) bool {
	_, ok := noDereferenceTouchOperands(command, cwd, home, false, ShellStartup{})
	return ok
}

// NoDereferenceTouchSafe checks that every entry changed by that form is
// ordinary in the hook's filesystem view. Links are checked at their own
// entry, while regular files are checked by identity as usual.
func NoDereferenceTouchSafe(command, cwd, home string) bool {
	safe, _ := noDereferenceTouchStatus(command, cwd, home)
	return safe
}

// NoDereferenceTouchSafeIn is NoDereferenceTouchSafe judged against the
// agent's shell startup (nil: this process's own).
func NoDereferenceTouchSafeIn(command, cwd, home string, startup *ShellStartup) bool {
	if startup == nil {
		return NoDereferenceTouchSafe(command, cwd, home)
	}
	safe, _ := noDereferenceTouchStatusIn(command, cwd, home, *startup)
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
	return noDereferenceTouchStatusIn(command, cwd, home, CurrentShellStartup())
}

// noDereferenceTouchStatusIn is noDereferenceTouchStatus with the agent's
// shell startup (a per-user gateway reads it from the client's header).
func noDereferenceTouchStatusIn(command, cwd, home string, startup ShellStartup) (safe, protectedTarget bool) {
	if !strings.Contains(command, "touch") ||
		!strings.Contains(command, "-h") && !strings.Contains(command, "--no-dereference") {
		return false, false
	}
	operands, ok := noDereferenceTouchOperands(command, cwd, home, true, startup)
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
	return !unknown && !protectedTarget && !startup.mayChange("touch", "gtouch"), protectedTarget
}

// entryOnlyStatement reads the bounded statement the entry-only proofs
// (touch -h, the replace verbs) accept: one simple command, optionally after
// one plain assignment of a fixed value, with no redirect, no background and
// no prefix assignment. It returns the command call and the values known
// before it.
func entryOnlyStatement(command, cwd, home string) (*syntax.CallExpr, actionValues, bool) {
	file, parsed := parseShell(command)
	if !parsed || len(file.Stmts) == 0 || len(file.Stmts) > 2 {
		return nil, nil, false
	}
	values := actionValues{"HOME": home, "PWD": cwd}
	if len(file.Stmts) == 2 {
		stmt := file.Stmts[0]
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 ||
			len(call.Args) != 0 || len(call.Assigns) != 1 {
			return nil, nil, false
		}
		assign := call.Assigns[0]
		if assign.Name == nil || assign.Name.Value == "HOME" || assign.Name.Value == "PWD" ||
			assign.Value == nil || assign.Append || assign.Array != nil || assign.Index != nil {
			return nil, nil, false
		}
		if !noDereferenceTouchLiteralWord(assign.Value) {
			return nil, nil, false
		}
		value, fixed := actionWordValueWithGlob(assign.Value, values, cwd, home, true)
		if strings.Contains(value, "\\") {
			if actionWordHasBraceText(assign.Value) {
				return nil, nil, false
			}
			fields, err := shellparse.Fields(&expand.Config{Env: expand.ListEnviron("HOME=" + home)}, assign.Value)
			if err != nil || len(fields) != 1 {
				return nil, nil, false
			}
			value = fields[0]
		}
		if !fixed || value == "" || strings.ContainsAny(value, " \t\r\n\x00\x1f") {
			return nil, nil, false
		}
		values[assign.Name.Value] = value
	}
	stmt := file.Stmts[len(file.Stmts)-1]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 {
		return nil, nil, false
	}
	return call, values, true
}

func noDereferenceTouchOperands(command, cwd, home string, expandPatterns bool, startup ShellStartup) ([]string, bool) {
	if !filepath.IsAbs(cwd) || home == "" ||
		!strings.Contains(command, "touch") ||
		!strings.Contains(command, "-h") && !strings.Contains(command, "--no-dereference") {
		return nil, false
	}
	call, values, ok := entryOnlyStatement(command, cwd, home)
	if !ok || len(call.Args) < 3 {
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
			if expandPatterns {
				// The one resolver: quote removal (ANSI-C included), bash's
				// glob rules and the literal fallback of an unmatched
				// pattern. Every candidate it names is an operand
				// (GAP-0293, GAP-0324, GAP-0325). A Windows home reads
				// these characters as wildcards: no proof there.
				if actionWindowsHome(home) && shellWordNeedsResolver(word) {
					return nil, false
				}
				resolved := resolveShellWord(word, values, cwd, shellGlobOptionsForCall(command, startup), nil)
				if resolved.uncertain != "" {
					return nil, false
				}
				operands = append(operands, resolved.candidates...)
				if len(operands) > 1024 {
					return nil, false
				}
				continue
			}
			value, known := actionWordValueWithGlob(word, values, cwd, home, true)
			if !known || value == "" || strings.ContainsAny(value, " \t\r\n\x00\x1f") {
				return nil, false
			}
			operands = append(operands, value)
			continue
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
				pattern := OperandPath(field, cwd)
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
