// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// actionHereDocDataPrograms are the programs whose standard input is only
// data: they print, count or order it and never read it as a command, a
// script or a list of paths.
var actionHereDocDataPrograms = map[string]bool{
	"cat": true, "tee": true, "head": true, "tail": true, "wc": true, "sort": true, "uniq": true,
}

// actionWindowsBlankHereDocData blanks, for the Windows target scan, the
// glob words of the literal body text of a here-document that a top-level data program reads
// (cat <<"EOT" ... EOT), alone or in a ; && || list, when no argument
// or output of the program runs code (actionHereDocOutputsRunNothing). The body is text, not words: its *** banner lines
// read as a glob that selects .ssh at the home, and Codex on Windows was denied
// a cat heredoc holding the apply_patch banner (rel-1-0-4:GAP-1717, still
// denied on 1.0.9). PowerShell cannot parse an unquoted << and runs nothing;
// Git Bash passes the text through. Everything that can run stays scanned:
// the expansions ($(...), backticks) of an unquoted body, the program words,
// the redirect targets, and every body whose reader could run it (bash,
// apply_patch, a pipeline into a shell). The literal protected-path spellings
// of any body are still read by actionWindowsLiteralHereDocumentTarget.
func actionWindowsBlankHereDocData(command string) string {
	if !strings.Contains(command, "<<") {
		return command
	}
	file, ok := parseShell(command)
	if !ok {
		return command
	}
	var spans [][2]int
	for _, stmt := range actionHereDocListStatements(file.Stmts) {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || stmt.Background || stmt.Coprocess || len(call.Args) == 0 || len(call.Assigns) > 0 {
			continue
		}
		program, ok := plainLiteralWord(call.Args[0])
		if !ok || !actionHereDocDataPrograms[programBase(program)] || !actionHereDocOutputsRunNothing(call, stmt) {
			continue
		}
		for _, redirect := range stmt.Redirs {
			if redirect.Hdoc == nil || redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc {
				continue
			}
			for _, part := range redirect.Hdoc.Parts {
				lit, ok := part.(*syntax.Lit)
				if !ok {
					continue
				}
				start := int(lit.ValuePos.Offset())
				end := start + len(lit.Value) // ValueEnd of a body literal also covers the delimiter line
				// Blank a span only when it is exactly the text the parser read;
				// any other spelling stays scanned (over-block, never under-block).
				if start < 0 || end > len(command) || start >= end || command[start:end] != lit.Value {
					continue
				}
				spans = append(spans, [2]int{start, end})
			}
		}
	}
	if len(spans) == 0 {
		return command
	}
	out := []byte(command)
	for _, span := range spans {
		// Only the words that hold a glob character are blanked. A literal
		// path stays scanned, as a mention of a protected state path in text
		// is still reported.
		for i := span[0]; i < span[1]; {
			if actionHereDocSeparator(out[i]) {
				i++
				continue
			}
			j := i
			glob := false
			for j < span[1] && !actionHereDocSeparator(out[j]) {
				glob = glob || strings.IndexByte("*?[]", out[j]) >= 0
				j++
			}
			if glob {
				for k := i; k < j; k++ {
					out[k] = 32
				}
			}
			i = j
		}
	}
	return string(out)
}

// actionHereDocListStatements returns the statements of a top-level list
// (a; b, a && b, a || b), each with its own redirects. A pipeline stage is
// not one: its standard output may feed a program that runs the body.
func actionHereDocListStatements(stmts []*syntax.Stmt) []*syntax.Stmt {
	var out []*syntax.Stmt
	var walk func(stmt *syntax.Stmt)
	walk = func(stmt *syntax.Stmt) {
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && len(stmt.Redirs) == 0 && !stmt.Negated &&
			(binary.Op == syntax.AndStmt || binary.Op == syntax.OrStmt) {
			walk(binary.X)
			walk(binary.Y)
			return
		}
		out = append(out, stmt)
	}
	for _, stmt := range stmts {
		walk(stmt)
	}
	return out
}

// actionHereDocOutputsRunNothing reports that no argument of the data
// program and no redirect word other than the here-documents can run code:
// no command or process substitution and no arithmetic. tee >(bash) <<EOT
// or cat <<EOT > >(bash) hand the body to a shell, so it is not data there.
func actionHereDocOutputsRunNothing(call *syntax.CallExpr, stmt *syntax.Stmt) bool {
	runs := func(word *syntax.Word) bool {
		found := false
		syntax.Walk(word, func(node syntax.Node) bool {
			switch node.(type) {
			case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp:
				found = true
			}
			return !found
		})
		return found
	}
	for _, arg := range call.Args[1:] {
		if runs(arg) {
			return false
		}
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc {
			continue
		}
		if redirect.Word != nil && runs(redirect.Word) {
			return false
		}
	}
	return true
}

func actionHereDocSeparator(c byte) bool {
	return strings.IndexByte(" \t\r\n\"(),;|&<>{}=", c) >= 0 || c == 39
}
