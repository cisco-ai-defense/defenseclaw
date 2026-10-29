// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// posixCommandDirectories is every working directory each POSIX command
// of facts may run in: the call cwd, moved by the earlier static cd, pushd
// and popd of the same action. Pod check26 (GAP-2485): with the session cwd
// at the home, `cd ~/proj2 && git clean -fdx` cleans the project, not the
// home work tree, and `cd ~/.defenseclaw/hooks && sort -o a.txt x` writes
// the hooks tree.
//
// Pod check27: a cd moves the shell only when it runs in that shell and
// succeeds. A backgrounded cd or one in a pipeline moves nothing. A command
// that follows a cd only through && in the same list runs in the new
// directory alone; any other later command (after ;, ||, an if or a
// subshell, or after the && list ends) may run where the shell was before
// the cd, so it is judged in both. A target the action cannot prove (a
// dynamic or `-` target, an unknown option, popd with an empty stack) adds
// no directory. An empty set is returned as [""]: a relative operand then
// proves nothing, an absolute one still counts.
func posixCommandDirectories(facts actionfacts.Facts, home string) [][]string {
	dirs := make([][]string, len(facts.Commands))
	var current []string
	if strings.HasPrefix(facts.CWD, "/") {
		current = []string{path.Clean(facts.CWD)}
	}
	var stack [][]string
	var listID int64
	var listDirs []string
	indexOfID := make(map[int64]int, len(facts.Commands))
	for index, command := range facts.Commands {
		indexOfID[command.ID] = index
		here := current
		if listID != 0 && command.ShortCircuitListID == listID &&
			command.ControlFlowOperator == actionfacts.ControlFlowOperatorAnd {
			here = listDirs
		} else {
			listID, listDirs = 0, nil
		}
		if parent, ok := indexOfID[command.ParentCommandID]; ok && command.ParentCommandID != 0 && parent < index {
			// A wrapped or nested command runs where its parent runs.
			dirs[index] = dirs[parent]
			continue
		}
		dirs[index] = commandDirectoryCandidates(here)
		program := command.Program
		if command.Dialect != actionfacts.DialectPOSIX ||
			program != "cd" && program != "pushd" && program != "popd" {
			continue
		}
		if command.Background || command.PipelineID != 0 {
			continue
		}
		var next []string
		words, ok := stateOperandWords(command)
		switch {
		case !ok:
		case program == "popd":
			if len(words) == 0 && len(stack) != 0 {
				next, stack = stack[len(stack)-1], stack[:len(stack)-1]
			}
		default:
			next = cdTargets(program, words, home, here)
			if program == "pushd" && len(next) != 0 {
				stack = append(stack, here)
			}
		}
		if command.ShortCircuitListID != 0 &&
			command.ControlFlowOperator == actionfacts.ControlFlowOperatorAnd {
			listID, listDirs = command.ShortCircuitListID, next
		}
		current = unionDirectories(current, here, next)
	}
	return dirs
}

// cdTargets is every directory a cd or pushd with words leads to from the
// directories in from.
func cdTargets(program string, words []string, home string, from []string) []string {
	for len(words) > 0 && program == "cd" && (words[0] == "-P" || words[0] == "-L") {
		words = words[1:]
	}
	if len(words) > 0 && words[0] == "--" {
		words = words[1:]
	}
	switch {
	case len(words) == 0 && program == "cd":
		return []string{home}
	case len(words) != 1 || words[0] == "-" || stateWordExpands(words[0]):
		return nil
	}
	var targets []string
	bases := from
	if len(bases) == 0 {
		bases = []string{""}
	}
	for _, base := range bases {
		if target, known := stateHomePath(words[0], home, base); known {
			targets = unionDirectories(targets, []string{path.Clean(target)})
		}
	}
	return targets
}

func unionDirectories(sets ...[]string) []string {
	var out []string
	for _, set := range sets {
		for _, dir := range set {
			if !slices.Contains(out, dir) {
				out = append(out, dir)
			}
		}
	}
	return out
}

func commandDirectoryCandidates(dirs []string) []string {
	if len(dirs) == 0 {
		return []string{""}
	}
	return dirs
}
