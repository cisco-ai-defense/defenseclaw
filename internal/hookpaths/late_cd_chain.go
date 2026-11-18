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

// lateMaxChainCDs bounds the cd steps LateChainCallGrade reads.
const lateMaxChainCDs = 4

// LateChainCallGrade is LateCallGrade as the late-ordinary rule of a per-user
// outage asks it (hookexec.LateOrdinaryBothScans, Linux and macOS,
// rel-1-0-10 GAP-1188, GAP-1303). It also reads a call with a cd at any step
// of its top-level lists, "cd DIR && rest", "cd DIR; rest", "before && cd DIR
// && rest", "before; cd DIR" and the like, up to lateMaxChainCDs cd steps, as
// the link-hop scan (LateOrdinaryCallAt) does: DIR is one literal word,
// entered as LateEnteredDirectory proves it; the steps before the first cd
// are graded against the folder the call is in, as part of a compound call
// (lateChainedCallGrade: none of them may change the shell context), and rest
// against the folder the cd enters. When rest may also run where the cd
// failed or did not run (after ";", or with a "||" in the call) it is graded
// against the folder the call started in as well, and the grade is the
// higher one. Any other cd (a variable, -, +, ~, a glob, a substitution, an
// option, a redirect, a link, a folder that does not exist, a protected or
// state folder, a folder CDPATH may replace, a cd followed by "||" or inside
// a group, subshell or pipeline) keeps the call Possible, as LateCallGrade
// keeps every compound call with a cd. On Windows it is LateCallGrade.
func LateChainCallGrade(command, cwd, home string) Grade {
	return lateChainGrade(command, cwd, home, 0)
}

func lateChainGrade(command, cwd, home string, depth int) Grade {
	if runtime.GOOS == "windows" || !filepath.IsAbs(cwd) || !filepath.IsAbs(home) || len(command) > MaxPayloadBytes {
		return LateCallGrade(command, cwd, home)
	}
	step, modelled := lateChainCD(command)
	if !modelled {
		return LateCallGrade(command, cwd, home)
	}
	if depth >= lateMaxChainCDs || !lateCDWithoutSearchPath(step.dir) {
		return GradePossible
	}
	entered, ok := LateEnteredDirectory(cwd, step.dir, home)
	if !ok {
		return GradePossible
	}
	grade := GradeNone
	if step.before != "" {
		grade = lateChainedCallGrade(step.before, cwd, home)
	}
	if step.rest == "" || grade == GradeNamed {
		return grade
	}
	grade = grade.Max(lateChainGrade(step.rest, entered, home, depth+1))
	if !step.enteredOnly && grade != GradeNamed {
		grade = grade.Max(lateChainGrade(step.rest, cwd, home, depth+1))
	}
	return grade
}

// lateCDStep is the first cd of a call as lateChainCD splits it: the text of
// the steps before it, the literal folder, and the text after it.
// enteredOnly reports a rest that runs only when the cd worked: the call is
// one statement whose and-or list has no "||".
type lateCDStep struct {
	before, dir, rest string
	enteredOnly       bool
}

// lateListStep is one command of a top-level and-or list, in order, with the
// operator that joins it to the next one (andNext: "&&"; endsStatement: the
// last of its statement, so ";", a new line or the end follows).
type lateListStep struct {
	stmt                   *syntax.Stmt
	andNext, endsStatement bool
}

// lateChainCD finds the first cd among the commands of the top-level and-or
// lists of a call and splits the call at it. modelled is false when there is
// no such cd and for every cd shape it does not model: a cd with
// assignments, options, redirects or a word that is not literal; a negated,
// background or coprocess cd; a "||" right after the cd; and a call that is
// only "cd DIR", which LateCallGrade reads. A cd inside a group, subshell,
// pipeline, negated or background list is not found here; the call then
// keeps a compound with a cd, which LateCallGrade keeps Possible.
func lateChainCD(command string) (lateCDStep, bool) {
	file, parsed := parseShell(command)
	if !parsed || len(file.Stmts) == 0 {
		return lateCDStep{}, false
	}
	var steps []lateListStep
	for _, stmt := range file.Stmts {
		steps = lateAndOrSteps(stmt, steps)
		steps[len(steps)-1].endsStatement = true
	}
	at := -1
	for i, step := range steps {
		if lateCDCall(step.stmt) {
			at = i
			break
		}
	}
	if at < 0 {
		return lateCDStep{}, false
	}
	cd := steps[at]
	if cd.stmt.Negated || cd.stmt.Background || cd.stmt.Coprocess || len(cd.stmt.Redirs) != 0 {
		return lateCDStep{}, false
	}
	call := cd.stmt.Cmd.(*syntax.CallExpr)
	if len(call.Assigns) != 0 || len(call.Args) != 2 {
		return lateCDStep{}, false
	}
	dir, ok := lateLiteralDirectory(call.Args[1])
	if !ok || !cd.andNext && !cd.endsStatement {
		return lateCDStep{}, false
	}
	step := lateCDStep{dir: dir, enteredOnly: len(file.Stmts) == 1 && !lateAndOrHasOr(file.Stmts[0])}
	if at > 0 {
		if !lateStepsKeepCD(steps[:at]) {
			return lateCDStep{}, false
		}
		end := int(steps[at-1].stmt.End().Offset())
		if end <= 0 || end > int(cd.stmt.Pos().Offset()) {
			return lateCDStep{}, false
		}
		step.before = command[:end]
	}
	if at+1 == len(steps) {
		// Nothing runs after a last cd. A call that is only "cd DIR" stays
		// with LateCallGrade, as before GAP-1303.
		return step, at > 0
	}
	start := int(steps[at+1].stmt.Pos().Offset())
	if start <= int(call.End().Offset()) || start >= len(command) {
		return lateCDStep{}, false
	}
	step.rest = command[start:]
	return step, true
}

// lateAndOrSteps appends the commands of an and-or list in the order they
// are written. A negated, background or coprocess list, or one with
// redirects, is one command: a cd inside it is not a step of the call.
func lateAndOrSteps(stmt *syntax.Stmt, steps []lateListStep) []lateListStep {
	binary, isBinary := stmt.Cmd.(*syntax.BinaryCmd)
	if !isBinary || binary.Op != syntax.AndStmt && binary.Op != syntax.OrStmt ||
		stmt.Negated || stmt.Background || stmt.Coprocess || len(stmt.Redirs) != 0 {
		return append(steps, lateListStep{stmt: stmt})
	}
	steps = lateAndOrSteps(binary.X, steps)
	steps[len(steps)-1].andNext = binary.Op == syntax.AndStmt
	return lateAndOrSteps(binary.Y, steps)
}

// lateStepsKeepCD reports steps before a cd that cannot change how the shell
// resolves it, at any depth (a zsh pipeline runs its last command in the
// shell itself): no assignment to CDPATH or cdpath, and no program that is not
// one plain word or that sets a shell variable or option, an alias or a trap
// (read, printf -v, shopt, setopt, ...). The steps that change the folder or
// the shell context (cd, pushd, source, export, exec, ...) are refused by
// lateChainedCallGrade.
func lateStepsKeepCD(steps []lateListStep) bool {
	keeps := true
	for _, step := range steps {
		syntax.Walk(step.stmt, func(node syntax.Node) bool {
			call, isCall := node.(*syntax.CallExpr)
			if !keeps || !isCall {
				return keeps
			}
			for _, assign := range call.Assigns {
				if assign == nil || assign.Name == nil || assign.Name.Value == "CDPATH" || assign.Name.Value == "cdpath" {
					keeps = false
				}
			}
			if len(call.Args) == 0 {
				return keeps
			}
			program, plain := plainLiteralWord(call.Args[0])
			if !plain || lateSetsShellState(filepath.Base(program), call.Args[1:]) {
				keeps = false
			}
			return keeps
		})
		if !keeps {
			return false
		}
	}
	return true
}

// lateSetsShellState reports a bash or zsh builtin that may set a shell
// variable or option, an alias, a hash entry or a trap; printf and print only
// with an option (printf -v).
func lateSetsShellState(program string, args []*syntax.Word) bool {
	switch program {
	case "read", "mapfile", "readarray", "getopts", "let", "local", "alias", "unalias", "shopt", "setopt",
		"unsetopt", "emulate", "enable", "disable", "hash", "trap", "vared", "zparseopts", "zmodload", "autoload":
		return true
	case "printf", "print":
		for _, arg := range args {
			if word, plain := plainLiteralWord(arg); !plain || strings.HasPrefix(word, "-") {
				return true
			}
		}
	}
	return false
}

// lateCDCall reports a simple command whose program is the literal word cd.
func lateCDCall(stmt *syntax.Stmt) bool {
	call, isCall := stmt.Cmd.(*syntax.CallExpr)
	if !isCall || len(call.Args) == 0 {
		return false
	}
	program, ok := plainLiteralWord(call.Args[0])
	return ok && program == "cd"
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
