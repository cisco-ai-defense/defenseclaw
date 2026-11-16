// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// placedCalls answers, for a call of one command, the directories it can run
// in. A script a call names by a relative name is the file of that name in
// those directories (cd a && source ok.sh opens a/ok.sh, not the ok.sh of the
// folder the hook started in), so every reader of a script body reads it
// there. The placement is the statement walk of topLevelStatementDirectories:
// a call after cd ... && runs only in the new directory, one after ; or ||
// also where the shell stood before. A call that walk does not place (inside
// a function, a loop or a condition) and a command whose directory changes it
// cannot read keep the starting directory (rel-1-0-9:GAP-1038).
type placedCalls struct {
	file         *syntax.File
	cwd, home    string
	mayChangeDir bool
	read         bool
	dirs         map[*syntax.CallExpr][]string
}

func newPlacedCalls(file *syntax.File, command, cwd, home string) *placedCalls {
	placed := &placedCalls{file: file, cwd: cwd, home: home}
	for _, program := range cdPrograms {
		placed.mayChangeDir = placed.mayChangeDir || strings.Contains(command, program)
	}
	return placed
}

// of is the directories call can run in: at least one.
func (p *placedCalls) of(call *syntax.CallExpr) []string {
	if !p.mayChangeDir || call == nil {
		return []string{p.cwd}
	}
	if !p.read {
		p.read = true
		statements, dirs, known := topLevelStatementPlaces(p.file, p.cwd, p.home, true)
		if known {
			p.dirs = make(map[*syntax.CallExpr][]string)
			for i, stmt := range statements {
				if placedCall, ok := stmt.Cmd.(*syntax.CallExpr); ok && !slices.Contains(p.dirs[placedCall], dirs[i]) {
					p.dirs[placedCall] = append(p.dirs[placedCall], dirs[i])
				}
			}
		}
	}
	// A call after code this package does not read (a sourced file, a trap,
	// a function the command defines) may stand in a directory that code
	// changed, so it keeps the starting directory too.
	if dirs := p.dirs[call]; len(dirs) != 0 && !hiddenDirectoryChangeBefore(p.file, p.home, call.Pos().Offset()) {
		return dirs
	}
	return []string{p.cwd}
}
