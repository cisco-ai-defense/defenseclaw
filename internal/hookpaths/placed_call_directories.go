// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"cmp"
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
	// renamed marks a tree a reader renames while it asks (knownShadow): each
	// call then reads the hidden directory changes before it afresh. Any
	// other tree reads them once (hidden), which holds only while the tree
	// does not change as its calls are read: today only knownShadow renames,
	// and only in frames with an include (literal_write.go), so a new reader
	// that changes a tree with no include must set renamed too.
	renamed bool
	hidden  *hiddenChanges
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
	if dirs := p.dirs[call]; len(dirs) != 0 && !p.hiddenBefore(call.Pos().Offset()) {
		return dirs
	}
	return []string{p.cwd}
}

// hiddenBefore is hiddenDirectoryChangeBefore(p.file, p.home, offset). A
// tree no reader renames is read once for every call: each call walked the
// whole tree again, so a script of 1,500 touch statements after cd .cache
// and a here-string walked about two million nodes a decision, half of a
// copy-mode actor's time (rel-1-0-10:GAP-2226).
func (p *placedCalls) hiddenBefore(offset uint) bool {
	if p.renamed {
		return hiddenDirectoryChangeBefore(p.file, p.home, offset)
	}
	if p.hidden == nil {
		p.hidden = newHiddenChanges(p.file, p.home)
	}
	return p.hidden.before(offset)
}

// hiddenChanges answers hiddenDirectoryChangeBefore for the calls of one tree
// that does not change: its calls in the order they end, each read
// (callHidesDirectoryChange) at most once and only once a call after it asks,
// up to the first that hides a directory change.
type hiddenChanges struct {
	home      string
	functions map[string]bool
	calls     []*syntax.CallExpr
	next      int
	found     bool
	end       uint
}

func newHiddenChanges(file *syntax.File, home string) *hiddenChanges {
	hidden := &hiddenChanges{home: home, functions: definedFunctionNames(file)}
	syntax.Walk(file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			hidden.calls = append(hidden.calls, call)
		}
		return true
	})
	slices.SortStableFunc(hidden.calls, func(a, b *syntax.CallExpr) int {
		return cmp.Compare(a.End().Offset(), b.End().Offset())
	})
	return hidden
}

// before reports a call that hides a directory change and ends at or before
// offset (hiddenDirectoryChangeBefore).
func (h *hiddenChanges) before(offset uint) bool {
	for !h.found && h.next < len(h.calls) && h.calls[h.next].End().Offset() <= offset {
		call := h.calls[h.next]
		h.next++
		if callHidesDirectoryChange(call, h.functions, h.home, 0) {
			h.found, h.end = true, call.End().Offset()
		}
	}
	return h.found && h.end <= offset
}
