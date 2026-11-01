// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// stackPlace is one state of the shell a call may run in, for its bash
// directory-stack tilde words: the current directory, OLDPWD (the
// directory the last cd, pushd or popd that ran left) and the directories
// pushd saved (top last). An empty dir or old is not known.
type stackPlace struct {
	dir, old string
	saved    []string
}

// stackEditors are builtins that can change the directory, OLDPWD or the
// stack (dirs -c, eval "cd x", command cd, source) or the name a later word
// runs (alias): the walk below does not read them, so a command that runs
// one keeps every stack word unknown.
var stackEditors = []string{"dirs", "command", "builtin", "eval", "source", ".", "alias", "exec", "enable", "shopt", "trap"}

// directoryStackPlaces returns, for each call of a ; / && / || list (and
// plain subshells), every state of the directory stack it may run in. A cd,
// pushd or popd may fail: an && after it sees only the changed state, a ;
// or || also the one before (as topLevelStatementDirectories reads it). A
// pushd or cd of a bare relative name may follow CDPATH, so the directory
// it enters is not known, but the one it leaves is. nil means no stack word
// of the command is known: a cd, pushd or popd outside such a list or of
// another form, a stack editor, a function definition, a program word that
// is not static, or a command that names OLDPWD or DIRSTACK (GAP-2586).
func directoryStackPlaces(file *syntax.File, command, cwd, home string) map[*syntax.CallExpr][]stackPlace {
	if strings.Contains(command, "OLDPWD") || strings.Contains(command, "DIRSTACK") {
		return nil
	}
	topLevel := make(map[*syntax.CallExpr]bool)
	var collect func(*syntax.Stmt)
	collect = func(stmt *syntax.Stmt) {
		plain := len(stmt.Redirs) == 0 && !stmt.Background && !stmt.Negated
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && plain &&
			(pair.Op == syntax.AndStmt || pair.Op == syntax.OrStmt) {
			collect(pair.X)
			collect(pair.Y)
			return
		}
		if sub, ok := stmt.Cmd.(*syntax.Subshell); ok && plain {
			for _, inner := range sub.Stmts {
				collect(inner)
			}
			return
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && !stmt.Background {
			topLevel[call] = true
		}
	}
	for _, stmt := range file.Stmts {
		collect(stmt)
	}
	known := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if _, isFunction := node.(*syntax.FuncDecl); isFunction {
			known = false
		}
		call, ok := node.(*syntax.CallExpr)
		if !known || !ok || len(call.Args) == 0 {
			return known
		}
		program, static := StaticWord(call.Args[0], home)
		base := programBase(program)
		if !static || slices.Contains(stackEditors, base) || !topLevel[call] && slices.Contains(cdPrograms, base) {
			known = false
		}
		return known
	})
	if !known {
		return nil
	}
	const maxPlaces = 64
	key := func(p stackPlace) string {
		return p.dir + "\x00" + p.old + "\x00" + strings.Join(p.saved, "\x00")
	}
	join := func(sets ...[]stackPlace) []stackPlace {
		var out []stackPlace
		seen := make(map[string]bool)
		for _, set := range sets {
			for _, p := range set {
				if !seen[key(p)] {
					seen[key(p)] = true
					out = append(out, p)
				}
			}
		}
		return out
	}
	places := make(map[*syntax.CallExpr][]stackPlace)
	var run func(*syntax.Stmt, []stackPlace) (succeeded, failed []stackPlace, ok bool)
	runList := func(list []*syntax.Stmt, in []stackPlace) (succeeded, failed []stackPlace, ok bool) {
		succeeded, failed = in, in
		current := in
		for _, stmt := range list {
			if succeeded, failed, ok = run(stmt, current); !ok {
				return nil, nil, false
			}
			current = join(succeeded, failed)
		}
		return succeeded, failed, true
	}
	run = func(stmt *syntax.Stmt, in []stackPlace) (succeeded, failed []stackPlace, ok bool) {
		if len(in) > maxPlaces {
			return nil, nil, false
		}
		plain := len(stmt.Redirs) == 0 && !stmt.Background && !stmt.Negated
		if pair, isPair := stmt.Cmd.(*syntax.BinaryCmd); isPair && plain &&
			(pair.Op == syntax.AndStmt || pair.Op == syntax.OrStmt) {
			leftOK, leftFailed, ok := run(pair.X, in)
			if !ok {
				return nil, nil, false
			}
			if pair.Op == syntax.AndStmt {
				rightOK, rightFailed, ok := run(pair.Y, leftOK)
				return rightOK, join(leftFailed, rightFailed), ok
			}
			rightOK, rightFailed, ok := run(pair.Y, leftFailed)
			return join(leftOK, rightOK), rightFailed, ok
		}
		if sub, isSub := stmt.Cmd.(*syntax.Subshell); isSub && plain {
			if _, _, ok := runList(sub.Stmts, in); !ok {
				return nil, nil, false
			}
			return in, in, true
		}
		call, isCall := stmt.Cmd.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return in, in, true
		}
		program, _ := StaticWord(call.Args[0], home)
		base := programBase(program)
		if !slices.Contains(cdPrograms, base) {
			places[call] = append(places[call], in...)
			return in, in, true
		}
		if len(call.Assigns) != 0 {
			return nil, nil, false
		}
		var moved []stackPlace
		switch base {
		case "popd":
			if len(call.Args) != 1 {
				return nil, nil, false
			}
			for _, p := range in {
				if len(p.saved) > 0 {
					moved = append(moved, stackPlace{dir: p.saved[len(p.saved)-1], old: p.dir, saved: slices.Clone(p.saved[:len(p.saved)-1])})
				}
			}
			if len(moved) == 0 {
				return nil, nil, false
			}
		default:
			if len(call.Args) != 2 {
				return nil, nil, false
			}
			target, static := StaticWord(call.Args[1], home)
			if !static || target == "" || strings.HasPrefix(target, "-") || strings.HasPrefix(target, "+") {
				return nil, nil, false
			}
			for _, p := range in {
				next := stackPlace{old: p.dir, saved: slices.Clone(p.saved)}
				if p.dir != "" && pushdBypassesCDPath(target) || filepath.IsAbs(target) {
					next.dir = OperandPath(target, p.dir)
				}
				if base == "pushd" {
					next.saved = append(next.saved, p.dir)
				}
				moved = append(moved, next)
			}
		}
		moved = join(moved)
		if stmt.Negated {
			return in, moved, true
		}
		return moved, in, true
	}
	if _, _, ok := runList(file.Stmts, []stackPlace{{dir: filepath.Clean(cwd)}}); !ok {
		return nil
	}
	return places
}

// expandDirectoryStackWord expands a bash directory-stack tilde word (~N,
// ~+N, ~-N, ~+, ~-) the same way in every state of places, or reports it
// unknown: an entry that is not known, an index outside the stack (bash
// leaves such a word literal) or states that disagree.
func expandDirectoryStackWord(word string, places []stackPlace) (string, bool) {
	match := directoryStackTilde.FindStringSubmatch(word)
	if match == nil || len(places) == 0 {
		return "", false
	}
	spec, rest := match[1], word[1+len(match[1]):]
	expanded := ""
	for i, p := range places {
		full := []string{p.dir}
		for j := len(p.saved) - 1; j >= 0; j-- {
			full = append(full, p.saved[j])
		}
		index := -1
		path := ""
		switch {
		case spec == "+":
			path = p.dir
		case spec == "-":
			path = p.old
		case strings.HasPrefix(spec, "-"):
			if n, err := strconv.Atoi(spec[1:]); err == nil {
				index = len(full) - 1 - n
			}
		default:
			if n, err := strconv.Atoi(strings.TrimPrefix(spec, "+")); err == nil {
				index = n
			}
		}
		if index >= 0 && index < len(full) {
			path = full[index]
		}
		if path == "" || !filepath.IsAbs(path) || i > 0 && path != expanded {
			return "", false
		}
		expanded = path
	}
	return expanded + rest, true
}
