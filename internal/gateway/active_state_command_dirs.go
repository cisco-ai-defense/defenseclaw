// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// maxCommandDirectories bounds the directories one command is judged in.
// Pod check28: each relative cd after ; may or may not hold, so n of them
// give 2^n candidate directories; unbounded, 14 of them took 93 s per hook
// call (the hook gives the gateway 4 s).
const maxCommandDirectories = 8

// commandDirectoryScope is the directory walk of one shell: the call shell,
// or the script of a nested `sh -c` / wrapper, which starts where its parent
// command runs.
type commandDirectoryScope struct {
	start    []string
	current  []string
	stack    [][]string
	listID   int64
	listDirs []string
	// held is where the shell is when every earlier cd of the scope held
	// (the answer before the cd scope work); heldStack is its pushd stack.
	held      []string
	heldStack [][]string
}

// posixCommandDirectories is every working directory each POSIX command
// of facts may run in: the call cwd, moved by the earlier static cd, pushd
// and popd of the same shell. Pod check26 (GAP-2485): with the session cwd
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
//
// Pod check28: the commands of a nested script (`sh -c "cd X; rm -rf a/*"`)
// or under a wrapper (`sudo rm`) walk their own scope, which starts in the
// directories of the parent command; their cd moves them and never the
// outer shell. Every set is bounded (boundCommandDirectories).
//
// Pod check29: the bound always keeps the directory where every earlier cd
// held and the scope start, so 4 or more relative cds and a .. traversal
// (`sh -c "cd a; cd b; cd c; cd d; rm -rf ../../../../.defenseclaw/hooks/*"`)
// are still judged where the shell really is.
func posixCommandDirectories(facts actionfacts.Facts, home string) [][]string {
	dirs := make([][]string, len(facts.Commands))
	var callDirs []string
	if stateRootedPath(facts.CWD) {
		callDirs = []string{path.Clean(facts.CWD)}
	}
	stateRoot := home + "/.defenseclaw"
	scopes := map[int64]*commandDirectoryScope{0: {start: callDirs, current: callDirs, held: callDirs}}
	indexOfID := make(map[int64]int, len(facts.Commands))
	for index, command := range facts.Commands {
		indexOfID[command.ID] = index
		scopeID := int64(0)
		if parent, ok := indexOfID[command.ParentCommandID]; ok && command.ParentCommandID != 0 && parent < index {
			scopeID = command.ParentCommandID
			if scopes[scopeID] == nil {
				start := dirs[parent]
				if len(start) == 1 && start[0] == "" {
					start = nil
				}
				scopes[scopeID] = &commandDirectoryScope{start: start, current: start, held: start}
			}
		}
		scope := scopes[scopeID]
		here := scope.current
		if scope.listID != 0 && command.ShortCircuitListID == scope.listID &&
			command.ControlFlowOperator == actionfacts.ControlFlowOperatorAnd {
			here = scope.listDirs
		} else {
			scope.listID, scope.listDirs = 0, nil
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
		var next, heldNext []string
		words, ok := stateOperandWords(command)
		switch {
		case !ok:
		case program == "popd":
			if len(words) == 0 && len(scope.stack) != 0 {
				last := len(scope.stack) - 1
				next, scope.stack = scope.stack[last], scope.stack[:last]
				heldNext, scope.heldStack = scope.heldStack[last], scope.heldStack[:last]
			}
		default:
			next = cdTargets(program, words, home, here)
			heldNext = cdTargets(program, words, home, scope.held)
			if program == "pushd" && len(next) != 0 {
				scope.stack = append(scope.stack, here)
				scope.heldStack = append(scope.heldStack, scope.held)
			}
		}
		scope.held = heldNext
		if command.ShortCircuitListID != 0 &&
			command.ControlFlowOperator == actionfacts.ControlFlowOperatorAnd {
			scope.listID, scope.listDirs = command.ShortCircuitListID, next
		}
		scope.current = boundCommandDirectories(
			unionDirectories(scope.current, here, next, scope.held), scope.held, scope.start, next, home, stateRoot)
	}
	return dirs
}

// boundCommandDirectories keeps at most maxCommandDirectories of dirs, in
// this order: where every cd held, the start of the scope, the state root and its ancestors, the directories in the state
// root, the directories the cd just led to, the
// directories in the home, then the others. Within a class the shorter path
// is kept first: a chain of relative cds that did not hold leads ever
// deeper, while the shell is still in one of the shorter directories.
func boundCommandDirectories(dirs, held, start, next []string, home, stateRoot string) []string {
	if len(dirs) <= maxCommandDirectories {
		return dirs
	}
	kept := make([]string, 0, maxCommandDirectories)
	keep := func(from []string, want func(string) bool) {
		ordered := slices.Clone(from)
		slices.SortStableFunc(ordered, func(a, b string) int { return len(a) - len(b) })
		for _, dir := range ordered {
			if len(kept) == maxCommandDirectories {
				return
			}
			if want(dir) && !slices.Contains(kept, dir) {
				kept = append(kept, dir)
			}
		}
	}
	everyDir := func(string) bool { return true }
	keep(held, everyDir)
	keep(start, everyDir)
	keep(dirs, func(dir string) bool {
		return dir == stateRoot || dir == "/" || strings.HasPrefix(stateRoot, dir+"/")
	})
	keep(dirs, func(dir string) bool { return strings.HasPrefix(dir, stateRoot+"/") })
	keep(next, everyDir)
	keep(dirs, func(dir string) bool { return strings.HasPrefix(dir, home+"/") })
	keep(dirs, everyDir)
	return kept
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
