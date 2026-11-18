// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// lateMaxLeadingCDs bounds the leading cd steps LateChainCallGrade reads.
const lateMaxLeadingCDs = 4

// LateChainCallGrade is LateCallGrade as the late-ordinary rule of a per-user
// outage asks it (hookexec.LateOrdinaryBothScans, Linux and macOS,
// rel-1-0-10 GAP-1188). It also reads a call that starts with a cd chain,
// "cd DIR && rest" or "cd DIR; rest", up to lateMaxLeadingCDs steps, as the
// link-hop scan (LateOrdinaryCallAt) does: DIR is one literal word, entered as
// LateEnteredDirectory proves it, and rest is graded against the folder it
// enters. When rest may also run where the cd failed (after ";", or with a
// "||" in the chain) it is graded against the folder the call started in as
// well, and the grade is the higher one. Any other cd (a variable, -, +, ~, a
// glob, a substitution, an option, a redirect, a link, a folder that does not
// exist, a protected or state folder, a folder CDPATH may replace) keeps the
// call Possible, as LateCallGrade keeps every compound call with a cd. On
// Windows it is LateCallGrade.
func LateChainCallGrade(command, cwd, home string) Grade {
	return lateChainGrade(command, cwd, home, 0)
}

func lateChainGrade(command, cwd, home string, depth int) Grade {
	if runtime.GOOS == "windows" || !filepath.IsAbs(cwd) || !filepath.IsAbs(home) || len(command) > MaxPayloadBytes {
		return LateCallGrade(command, cwd, home)
	}
	dir, rest, enteredOnly, leading := lateLeadingCD(command)
	if !leading {
		return LateCallGrade(command, cwd, home)
	}
	if depth >= lateMaxLeadingCDs || !lateCDWithoutSearchPath(dir) {
		return GradePossible
	}
	entered, ok := LateEnteredDirectory(cwd, dir, home)
	if !ok {
		return GradePossible
	}
	grade := lateChainGrade(rest, entered, home, depth+1)
	if !enteredOnly && grade != GradeNamed {
		grade = grade.Max(lateChainGrade(rest, cwd, home, depth+1))
	}
	return grade
}

// lateLeadingCD splits a command that starts with "cd DIR" followed by "&&"
// or ";" (or a new line) into the literal DIR and the command text after it.
// enteredOnly reports a rest that runs only when the cd worked: the call is
// one statement whose and-or list has no "||". leading is false for every
// other shape: no cd first, a cd with assignments, options, redirects or a
// word that is not literal, a negated or background statement, or a "||" or
// pipe right after the cd.
func lateLeadingCD(command string) (dir, rest string, enteredOnly, leading bool) {
	file, parsed := parseShell(command)
	if !parsed || len(file.Stmts) == 0 {
		return "", "", false, false
	}
	first := file.Stmts[0]
	stmt, next := first, (*syntax.Stmt)(nil)
	for {
		if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || len(stmt.Redirs) != 0 {
			return "", "", false, false
		}
		binary, isBinary := stmt.Cmd.(*syntax.BinaryCmd)
		if !isBinary {
			break
		}
		if binary.Op != syntax.AndStmt {
			return "", "", false, false
		}
		// The command right after the cd is the second operand of the
		// innermost "&&" on the way to it, whichever way the list nests.
		next, stmt = binary.Y, binary.X
	}
	if next == nil {
		if len(file.Stmts) < 2 {
			return "", "", false, false
		}
		next = file.Stmts[1]
	}
	call, isCall := stmt.Cmd.(*syntax.CallExpr)
	if !isCall || len(call.Assigns) != 0 || len(call.Args) != 2 {
		return "", "", false, false
	}
	if program, ok := plainLiteralWord(call.Args[0]); !ok || program != "cd" {
		return "", "", false, false
	}
	dir, ok := lateLiteralDirectory(call.Args[1])
	if !ok || next == nil {
		return "", "", false, false
	}
	start := int(next.Pos().Offset())
	if start <= int(call.End().Offset()) || start >= len(command) {
		return "", "", false, false
	}
	return dir, command[start:], len(file.Stmts) == 1 && !lateAndOrHasOr(first), true
}

// lateAndOrHasOr reports an and-or list with a "||" in it.
func lateAndOrHasOr(stmt *syntax.Stmt) bool {
	binary, ok := stmt.Cmd.(*syntax.BinaryCmd)
	if !ok || binary.Op != syntax.AndStmt && binary.Op != syntax.OrStmt {
		return false
	}
	return binary.Op == syntax.OrStmt || lateAndOrHasOr(binary.X) || lateAndOrHasOr(binary.Y)
}

// lateLiteralDirectory is the text of a cd word that the shell leaves as it
// is: plain path characters, also in single or double quotes (where a space
// may be part of it). A tilde, a parameter, a substitution, a glob, a brace,
// an escape and an ANSI-C or locale quote are not literal.
func lateLiteralDirectory(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) == 0 {
		return "", false
	}
	var text strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if !lateDirectoryText(part.Value, false) {
				return "", false
			}
			text.WriteString(part.Value)
		case *syntax.SglQuoted:
			if part.Dollar || !lateDirectoryText(part.Value, true) {
				return "", false
			}
			text.WriteString(part.Value)
		case *syntax.DblQuoted:
			if part.Dollar {
				return "", false
			}
			for _, inner := range part.Parts {
				lit, isLit := inner.(*syntax.Lit)
				if !isLit || !lateDirectoryText(lit.Value, true) {
					return "", false
				}
				text.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return text.String(), true
}

// lateDirectoryText reports text of plain path characters; quoted text may
// also hold a space.
func lateDirectoryText(text string, quoted bool) bool {
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			strings.IndexByte("_./-,:@%+=", c) >= 0:
		case quoted && c == ' ':
		default:
			return false
		}
	}
	return true
}

// lateCDWithoutSearchPath reports a cd folder the shell does not look up in
// CDPATH: an absolute one, one that starts with ./ or ../ (or is . or ..),
// or any folder while the hook, which runs with the environment of the
// agent, has no CDPATH.
func lateCDWithoutSearchPath(dir string) bool {
	return os.Getenv("CDPATH") == "" || filepath.IsAbs(dir) || dir == "." || dir == ".." ||
		strings.HasPrefix(dir, "./") || strings.HasPrefix(dir, "../")
}

// LateEnteredDirectory is the folder "cd dir" enters from cwd, when the late
// scans can prove it (rel-1-0-10 GAP-1188), as the link-hop scan enters it
// (lateScan.chdir): dir is text with no option or directory-stack sign (- or +
// first), no tilde and no protected or state folder name; every component
// exists as a real folder (no link on the way); a ".." steps to the parent of
// the physical folder before it, and a dir with a ".." must name the same
// folder when the shell reads it from cwd as text (cd -L); the folder entered
// is not the root, the home or a parent of it, has no protected or state
// folder name and no protected reach (ProtectedReach). A relative Codex
// workdir is placed the same way. false on Windows.
func LateEnteredDirectory(cwd, dir, home string) (string, bool) {
	if runtime.GOOS == "windows" || !filepath.IsAbs(cwd) || !filepath.IsAbs(home) || dir == "" || len(dir) > 4096 ||
		strings.IndexByte(dir, 0) >= 0 || strings.ContainsAny(dir[:1], "-+~") || lateNamesProtected(dir) {
		return "", false
	}
	current := string(filepath.Separator)
	if !filepath.IsAbs(dir) {
		real, err := pathEvalSymlinks(cwd)
		if err != nil {
			return "", false
		}
		current = real
	}
	if info, err := pathLstat(current); err != nil || !info.IsDir() {
		return "", false
	}
	parentStep := false
	for _, name := range strings.Split(dir, "/") {
		switch name {
		case "", ".":
			continue
		case "..":
			parentStep = true
			current = filepath.Dir(current)
			continue
		}
		current = filepath.Join(current, name)
		if info, err := pathLstat(current); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", false
		}
	}
	if parentStep && current != filepath.Clean(JoinDirectoryText(cwd, dir)) {
		return "", false
	}
	realHome, err := pathEvalSymlinks(home)
	if err != nil {
		return "", false
	}
	separator := string(filepath.Separator)
	for _, place := range []string{realHome, filepath.Clean(home)} {
		if current == place || strings.HasPrefix(place, current+separator) {
			return "", false
		}
	}
	if current == separator || lateNamesProtected(current) || ProtectedReach(current, home, NewTargetMemo()) != GradeNone {
		return "", false
	}
	return current, true
}
