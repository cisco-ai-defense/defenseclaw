// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A shell call carries a working folder: the one the hook reports, moved by
// every cd, pushd and popd the call has run before a command. A relative
// operand names a file in THAT folder, so `cd .git/hooks && echo x > pre-push`
// writes .git/hooks/pre-push, `cd ~/.ssh; cat id_rsa` reads ~/.ssh/id_rsa and
// `cd ~/.aws && cp credentials /tmp/x` reads ~/.aws/credentials. Every rule
// that judges a path (the protected writes and reads) judges the path the
// command reaches, so the path facts of a command are resolved against the
// folder it runs in (rel-1-0-10 T-DETECT, substrate-1:GAP-0327).
//
// The folder is tracked by the shape of the shell, not by a word list:
//
//   - a cd runs in the shell that reads it: `cd X && a` and `cd X; a` run a in
//     X; `( cd X; a )` runs a in X and leaves the shell where it was; a pipe
//     member, a background statement, a command or process substitution and a
//     function body run in a copy and change nothing outside;
//   - `a || cd X` and a cd inside a compound command (if, while, for, case)
//     may or may not have run: what follows is not read (the folder is
//     unknown), never guessed;
//   - a cd whose target is not one static word (a variable, a glob, `-`) or
//     that cannot be resolved (a relative step with no known folder, ~user)
//     leaves the folder unknown.
//
// An unknown folder changes nothing: the operands keep the resolution they had
// before this tracking (against the hook's folder), so the tracking only ever
// adds the path a command really reaches, and no verdict gets weaker.

// workFolder is the chain of cd targets that moved the folder of one command.
type workFolder struct {
	steps   []string
	unknown bool
}

func (w workFolder) moved() bool { return len(w.steps) > 0 || w.unknown }

func (w workFolder) with(step string) workFolder {
	return workFolder{steps: append(append([]string(nil), w.steps...), step), unknown: w.unknown}
}

func (w workFolder) lost() workFolder { return workFolder{steps: w.steps, unknown: true} }

func (w workFolder) same(other workFolder) bool {
	if w.unknown != other.unknown || len(w.steps) != len(other.steps) {
		return false
	}
	for i := range w.steps {
		if w.steps[i] != other.steps[i] {
			return false
		}
	}
	return true
}

// maxWorkFolderSteps bounds the chain one command carries; past it the folder
// is unknown (the one bound rule: never read what was not read in full).
const maxWorkFolderSteps = 32

// resolveWorkFolder is the folder a command runs in: cwd moved by steps. ok is
// false when a step cannot be resolved (the folder is then not known).
func resolveWorkFolder(cwd, home string, w workFolder) (string, bool) {
	if w.unknown {
		return "", false
	}
	current := cwd
	for _, step := range w.steps {
		switch {
		case step == "~" || step == "":
			if !strings.HasPrefix(home, "/") {
				return "", false
			}
			current = path.Clean(home)
		case strings.HasPrefix(step, "~/"):
			if !strings.HasPrefix(home, "/") {
				return "", false
			}
			current = path.Join(home, step[2:])
		case strings.HasPrefix(step, "~"):
			return "", false
		case strings.HasPrefix(step, "/"):
			current = path.Clean(step)
		default:
			if !strings.HasPrefix(current, "/") {
				return "", false
			}
			current = path.Join(current, step)
		}
	}
	return current, true
}

// posixWorkFolders returns, for every statement of file, the folder chain its
// command runs in.
func posixWorkFolders(file *syntax.File) map[*syntax.Stmt]workFolder {
	folders := make(map[*syntax.Stmt]workFolder)
	if file == nil {
		return folders
	}
	state := workFolder{}
	for _, stmt := range file.Stmts {
		state = trackWorkFolder(stmt, state, folders)
	}
	return folders
}

// trackWorkFolder records the folder stmt starts in and returns the folder the
// shell is in after it.
func trackWorkFolder(stmt *syntax.Stmt, in workFolder, folders map[*syntax.Stmt]workFolder) workFolder {
	if stmt == nil {
		return in
	}
	folders[stmt] = in
	out := in
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if target, isCD := staticWorkFolderMove(cmd); isCD {
			switch {
			case stmt.Background:
				// a background cd moves a subshell, not this shell
			case target == "\x00" || len(in.steps) >= maxWorkFolderSteps:
				out = in.lost()
			default:
				out = in.with(target)
			}
		}
		for _, word := range cmd.Args {
			trackWordWorkFolders(word, in, folders)
		}
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.AndStmt:
			out = trackWorkFolder(cmd.Y, trackWorkFolder(cmd.X, in, folders), folders)
		case syntax.OrStmt:
			left := trackWorkFolder(cmd.X, in, folders)
			right := trackWorkFolder(cmd.Y, in, folders)
			if !left.same(in) || !right.same(in) {
				out = in.lost()
			}
		default: // a pipe: each member runs in a copy of the shell
			trackWorkFolder(cmd.X, in, folders)
			trackWorkFolder(cmd.Y, in, folders)
		}
	case *syntax.Subshell:
		state := in
		for _, inner := range cmd.Stmts {
			state = trackWorkFolder(inner, state, folders)
		}
	case *syntax.Block:
		state := in
		for _, inner := range cmd.Stmts {
			state = trackWorkFolder(inner, state, folders)
		}
		if !stmt.Background {
			out = state
		}
	case *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
		// A body may or may not run: a cd inside leaves the folder unknown.
		changed := false
		syntax.Walk(cmd, func(node syntax.Node) bool {
			inner, ok := node.(*syntax.Stmt)
			if !ok || inner == stmt {
				return true
			}
			folders[inner] = in
			if call, isCall := inner.Cmd.(*syntax.CallExpr); isCall {
				if _, isCD := staticWorkFolderMove(call); isCD {
					changed = true
				}
			}
			return true
		})
		if changed {
			out = in.lost()
		}
	default:
		// Anything else (a function body, a time or coproc clause, a
		// declaration): its statements run in a copy of the shell.
		syntax.Walk(stmt.Cmd, func(node syntax.Node) bool {
			if inner, ok := node.(*syntax.Stmt); ok && inner != stmt {
				folders[inner] = in
			}
			return true
		})
	}
	return out
}

// trackWordWorkFolders gives the statements inside a word (a command or
// process substitution) the folder of the command that holds them; they run in
// a copy of the shell.
func trackWordWorkFolders(word *syntax.Word, in workFolder, folders map[*syntax.Stmt]workFolder) {
	syntax.Walk(word, func(node syntax.Node) bool {
		if inner, ok := node.(*syntax.Stmt); ok {
			folders[inner] = in
		}
		return true
	})
}

// staticWorkFolderMove reports a cd, pushd or chdir call and its target: one
// static word, "~" forms kept as written ("" for a bare cd, the home). The
// target "\x00" marks a move whose target is not read (popd, an expansion, `-`,
// a glob, an option other than -L and -P).
func staticWorkFolderMove(call *syntax.CallExpr) (target string, isCD bool) {
	if call == nil || len(call.Args) == 0 {
		return "", false
	}
	name := projectPOSIXWord(call.Args[0])
	if name.Expands {
		return "", false
	}
	switch name.Value {
	case "cd", "chdir", "pushd":
	case "popd":
		return "\x00", true
	default:
		return "", false
	}
	target = ""
	have := false
	for _, word := range call.Args[1:] {
		value, static := staticWorkFolderWord(word)
		if !static {
			return "\x00", true
		}
		if !have && (value == "-L" || value == "-P" || value == "--") {
			continue
		}
		if have || value == "-" || strings.HasPrefix(value, "-") && value != "" {
			return "\x00", true
		}
		target, have = value, true
	}
	if strings.ContainsAny(target, "*?[]{}$`\\") {
		return "\x00", true
	}
	return target, true
}

// staticWorkFolderWord is the text of one static cd operand: a literal, or a
// home spelling ($HOME, ${HOME}, a leading ~).
func staticWorkFolderWord(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) == 0 {
		return "", false
	}
	if spelling := posixHomeSpelling(word); spelling != "" {
		return spelling, true
	}
	argument := projectPOSIXWord(word)
	if !argument.Expands {
		return argument.Value, true
	}
	// A leading tilde the shell expands: all literal parts.
	var text strings.Builder
	for _, part := range word.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			return "", false
		}
		text.WriteString(lit.Value)
	}
	value := text.String()
	if strings.HasPrefix(value, "~") && (value == "~" || strings.HasPrefix(value, "~/")) {
		return value, true
	}
	return "", false
}

// windowsWorkFolders is the same tracking for the PowerShell and CMD dialects,
// read from the commands in source order (their parsers flatten blocks and
// pipelines): a cd, Set-Location, Push-Location or pushd with one static
// target moves the folder of every later command; anything the reader cannot
// place (a variable or glob target, popd, Pop-Location, a pipeline member, a
// command that sits in a block or under uncertain control flow, a bare drive)
// leaves the folder unknown for the rest of the call. An unknown folder keeps
// the hook's folder, as for POSIX.
func windowsWorkFolders(commands []CommandFact) map[int64]workFolder {
	var folders map[int64]workFolder
	state := workFolder{}
	for _, command := range commands {
		if command.Dialect != DialectPowerShell && command.Dialect != DialectCMD {
			continue
		}
		if folders == nil {
			folders = make(map[int64]workFolder)
		}
		folders[command.ID] = state
		if !windowsFolderMove(command) {
			continue
		}
		unconditional := command.ParentCommandID == 0 && command.PipelineID == 0 && !command.Background &&
			(!command.ControlFlowUncertain || command.ControlFlowOperator == ControlFlowOperatorAnd)
		target, ok := windowsFolderTarget(command)
		switch {
		case !unconditional || !ok || len(state.steps) >= maxWorkFolderSteps:
			state = state.lost()
		default:
			state = state.with(target)
		}
	}
	return folders
}

func windowsFolderMove(command CommandFact) bool {
	switch strings.ToLower(command.Program) {
	case "cd", "chdir", "pushd", "set-location", "sl", "push-location", "popd", "pop-location":
		return true
	}
	return false
}

// windowsFolderTarget is the one static target of a folder move.
func windowsFolderTarget(command CommandFact) (string, bool) {
	switch strings.ToLower(command.Program) {
	case "popd", "pop-location":
		return "", false
	}
	target, have := "", false
	for index, argument := range command.Arguments {
		if index == 0 {
			continue
		}
		if argument.Expands {
			return "", false
		}
		value := argument.Value
		lower := strings.ToLower(value)
		switch {
		case lower == "/d" && command.Dialect == DialectCMD, lower == "-path" || lower == "-literalpath":
			continue
		case strings.HasPrefix(value, "-") || command.Dialect == DialectCMD && strings.HasPrefix(value, "/") && len(value) <= 3:
			return "", false
		case have:
			return "", false
		}
		target, have = value, true
	}
	if !have || target == "" || strings.ContainsAny(target, "*?[]$`%") {
		return "", false
	}
	if len(target) == 2 && target[1] == ':' { // a bare drive: another drive's own folder
		return "", false
	}
	return target, true
}

// resolveWindowsWorkFolder is cwd moved by the steps of a Windows call.
func resolveWindowsWorkFolder(cwd, home string, w workFolder) (string, bool) {
	if w.unknown {
		return "", false
	}
	current := cwd
	for _, step := range w.steps {
		_, _, resolved := deriveWindowsPathWithPolicy(step, current, home, pathExpansionPolicy{expandTilde: true})
		if resolved == "" {
			return "", false
		}
		current = resolved
	}
	return current, true
}
