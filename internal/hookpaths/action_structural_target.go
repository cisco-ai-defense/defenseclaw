// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The mention scan follows the same effective working directory the shell
// uses for later words. A physical directory is retained so a symlink into
// .ssh cannot hide a relative protected name.
func actionPosixAdvanceDirectory(call *syntax.CallExpr, values actionValues, home string, cwd *string, stack *[]string) {
	if len(call.Args) == 0 {
		return
	}
	program, known := actionWordValue(call.Args[0], values, *cwd, home)
	if !known {
		return
	}
	switch programBase(program) {
	case "popd":
		if len(*stack) == 0 {
			return
		}
		*cwd = (*stack)[len(*stack)-1]
		*stack = (*stack)[:len(*stack)-1]
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
		var fixed bool
		destination, fixed = actionWordValue(call.Args[index], values, *cwd, home)
		if !fixed || destination == "" {
			return
		}
	}
	if programBase(program) == "pushd" {
		*stack = append(*stack, *cwd)
	}
	if actionPosixWindowsHome(home) {
		*cwd = actionPosixWindowsPath(destination, *cwd, home)
		return
	}
	if resolved, ok := ResolveWriteTarget(OperandPath(destination, *cwd)); ok {
		*cwd = resolved
	} else {
		*cwd = filepath.Clean(OperandPath(destination, *cwd))
	}
}

// An unresolved fragment is target-bearing only when the surrounding syntax
// or current directory puts its possible expansion in the protected class.
// This keeps ordinary project variables out of the protected-target rule.
func actionUnknownWordMayNameKey(word *syntax.Word, cwd, home string) bool {
	if word == nil {
		return false
	}
	var raw strings.Builder
	if syntax.NewPrinter().Print(&raw, word) != nil {
		return false
	}
	value := raw.String()
	for _, name := range AuthorizedKeysFiles {
		if strings.Contains(value, name) {
			return true
		}
	}
	if !strings.ContainsAny(value, "$`*?[") {
		return false
	}
	if actionPosixWindowsHome(home) {
		return path.Clean(cwd) == path.Join(home, ".ssh")
	}
	ssh, sshKnown := ResolveWriteTarget(filepath.Join(home, ".ssh"))
	current, cwdKnown := ResolveWriteTarget(cwd)
	return sshKnown && cwdKnown && samePathName(current, ssh) &&
		strings.ContainsAny(value, "$`*?[")
}

func actionWindowsAdvanceDirectory(words []string, home string, cwd *string, stack *[]string) {
	if len(words) == 0 {
		return
	}
	program := strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(words[0], `\`, "/"))), ".exe")
	switch program {
	case "popd", "pop-location":
		if len(*stack) != 0 {
			*cwd = (*stack)[len(*stack)-1]
			*stack = (*stack)[:len(*stack)-1]
		}
		return
	case "cd", "pushd", "set-location", "push-location":
	default:
		return
	}
	index := 1
	if index < len(words) {
		option := strings.ToLower(words[index])
		if option == "--" || option == "-path" || option == "-literalpath" {
			index++
		}
	}
	if len(words)-index > 1 {
		return
	}
	destination := home
	if index < len(words) {
		destination = words[index]
	}
	resolved, known := actionWindowsPath(destination, *cwd, home)
	if !known {
		return
	}
	if program == "pushd" || program == "push-location" {
		*stack = append(*stack, *cwd)
	}
	*cwd = resolved
}

func actionReadOptionMayWrite(option string) bool {
	option = strings.ToLower(option)
	for _, prefix := range []string{"--output", "--out-file", "--outfile", "--log-file", "--in-place", "-output", "-outfile", "-filepath", "-logfile", "-inplace"} {
		if strings.HasPrefix(option, prefix) {
			return true
		}
	}
	return false
}
