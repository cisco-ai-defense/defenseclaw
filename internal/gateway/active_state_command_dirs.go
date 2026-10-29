// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// posixCommandDirectories is the working directory each POSIX command of
// facts runs in: the call cwd, moved by every earlier static cd, pushd and
// popd of the same action. Pod check26 (GAP-2485): with the session cwd at
// the home, `cd ~/proj2 && git clean -fdx` cleans the project, not the home
// work tree, and `cd ~/.defenseclaw/hooks && sort -o a.txt x` writes the
// hooks tree; judging both against the call cwd blocked the first and
// missed the second. A change the action cannot prove (a dynamic or `-`
// target, an unknown option, a conditional cd, popd with an empty stack)
// leaves "" from there on, so a relative operand proves nothing.
func posixCommandDirectories(facts actionfacts.Facts, home string) []string {
	dirs := make([]string, len(facts.Commands))
	cwd := facts.CWD
	if !strings.HasPrefix(cwd, "/") {
		cwd = ""
	}
	var stack []string
	for index, command := range facts.Commands {
		dirs[index] = cwd
		program := command.Program
		if command.Dialect != actionfacts.DialectPOSIX ||
			program != "cd" && program != "pushd" && program != "popd" {
			continue
		}
		words, ok := stateOperandWords(command)
		if !ok || command.ControlFlowUncertain {
			cwd, stack = "", nil
			continue
		}
		if program == "popd" {
			if len(words) != 0 || len(stack) == 0 {
				cwd, stack = "", nil
				continue
			}
			cwd, stack = stack[len(stack)-1], stack[:len(stack)-1]
			continue
		}
		for len(words) > 0 && program == "cd" && (words[0] == "-P" || words[0] == "-L") {
			words = words[1:]
		}
		if len(words) > 0 && words[0] == "--" {
			words = words[1:]
		}
		next := ""
		switch {
		case len(words) == 0 && program == "cd":
			next = home
		case len(words) == 1 && words[0] != "-" && !stateWordExpands(words[0]):
			if target, known := stateHomePath(words[0], home, cwd); known {
				next = path.Clean(target)
			}
		}
		if next == "" {
			cwd, stack = "", nil
			continue
		}
		if program == "pushd" {
			stack = append(stack, cwd)
		}
		cwd = next
	}
	return dirs
}
