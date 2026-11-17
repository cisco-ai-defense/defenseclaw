// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// A shell call carries a working folder: the one the hook reports, moved by
// every cd, pushd and popd the call has run before a command. A relative
// operand names a file in THAT folder, so `cd .git/hooks && echo x > pre-push`
// writes .git/hooks/pre-push, `cd ~/.ssh && cat id_rsa` reads ~/.ssh/id_rsa and
// `cd ~/.aws && cp credentials /tmp/x` reads ~/.aws/credentials. Every rule
// that judges a path (the protected writes and reads) judges the path the
// command reaches, so the path facts of a command are resolved against the
// folders it may run in (rel-1-0-10 T-DETECT, substrate-1:GAP-0327).
//
// A move counts only where it is proven to have run and worked: a command
// runs in the moved folder ONLY when it is on the right side of an && whose
// left side ends with the cd (`cd X && a`), or in the then-branch of
// `if cd X`. Everywhere else the cd may have failed or not run at all (`cd X;
// a`, a newline, `false && cd X; a`, `a || cd X; a`, a cd in a loop or a
// branch, `test -d X && cd X; a`), so the command may run in the folder before
// the move as well as in the moved one, and it is read in EACH of them: the
// strongest proven finding decides (rel-1-0-10:GAP-0869, the class of
// GAP-0852 for the awk reader). The folder is tracked by the shape of the
// shell, not by a word list:
//
//   - `a && b` runs b where a succeeded; `a || b` runs b where a failed; `a;
//     b` runs b wherever a left the shell;
//   - `( cd X; a )` runs a as above and leaves the shell where it was; a pipe
//     member, a background statement, a command or process substitution and a
//     coprocess run in a copy and change nothing outside;
//   - an if, while, until, for or case reads every branch, and a loop that
//     moves by a relative step on each pass leaves an unresolved folder;
//   - a cd whose target is not one static word (a variable, a command
//     substitution, a glob, `-`, popd) or that cannot be resolved (a relative
//     step with no known folder, ~user) moves to an UNRESOLVED folder, and a
//     call of a function whose body moves may too.
//
// An unresolved folder is never a confident path: the operand keeps its
// reading against the hook's folder (what it had before this tracking, so no
// verdict gets weaker), and the fact is marked (PathFact.UnresolvedFolder),
// so the gateway gives a relative operand there the unknown tier of the one
// bound rule (rel-1-0-10:GAP-0871).

// workFolder is the chain of cd targets that moved the folder of one command,
// or an unresolved folder.
type workFolder struct {
	steps   []string
	unknown bool
}

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

// maxWorkFolderSteps bounds the chain one folder carries, and maxWorkFolders
// the folders one command is read in; past either the folder is unresolved
// (the one bound rule: never read what was not read in full).
const (
	maxWorkFolderSteps = 32
	maxWorkFolders     = 8
)

// workFolders are the folders a command may run in. Empty means the hook's
// own folder only.
type workFolders []workFolder

var (
	hookWorkFolders       = workFolders{{}}
	unresolvedWorkFolders = workFolders{{unknown: true}}
)

func (s workFolders) orHook() workFolders {
	if len(s) == 0 {
		return hookWorkFolders
	}
	return s
}

// moved reports folders other than the hook's own.
func (s workFolders) moved() bool {
	s = s.orHook()
	return len(s) != 1 || s[0].unknown || len(s[0].steps) != 0
}

// unionWorkFolders is every folder of the sets, each once, in order. Past
// maxWorkFolders it keeps the hook's own folder (the reading every call had
// before the tracking) and the first other folders, and the rest is one
// unresolved folder: the cap of the one bound rule.
func unionWorkFolders(sets ...workFolders) workFolders {
	var all workFolders
	for _, set := range sets {
		for _, folder := range set.orHook() {
			seen := false
			for _, have := range all {
				seen = seen || have.same(folder)
			}
			if !seen {
				all = append(all, folder)
			}
		}
	}
	if len(all) <= maxWorkFolders {
		return all
	}
	out := make(workFolders, 0, maxWorkFolders)
	hook := false
	for _, folder := range all {
		hook = hook || !folder.unknown && len(folder.steps) == 0
	}
	room := maxWorkFolders - 1
	if hook {
		out = append(out, workFolder{})
		room--
	}
	for _, folder := range all {
		if room == 0 {
			break
		}
		if folder.unknown || len(folder.steps) == 0 {
			continue
		}
		out = append(out, folder)
		room--
	}
	return append(out, workFolder{unknown: true})
}

func sameWorkFolders(a, b workFolders) bool {
	a, b = a.orHook(), b.orHook()
	if len(a) != len(b) {
		return false
	}
	for _, folder := range a {
		found := false
		for _, other := range b {
			if folder.same(other) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// with is every folder of s moved by one more step; target "\x00" is a move
// to a folder the words do not give.
func (s workFolders) with(target string) workFolders {
	if target == "\x00" {
		return unresolvedWorkFolders
	}
	out := make(workFolders, 0, len(s.orHook()))
	for _, folder := range s.orHook() {
		switch {
		case folder.unknown:
			out = append(out, folder)
		case len(folder.steps) >= maxWorkFolderSteps:
			out = append(out, workFolder{unknown: true})
		default:
			out = append(out, workFolder{steps: append(append([]string(nil), folder.steps...), target)})
		}
	}
	return unionWorkFolders(out)
}

// within is s read inside a nested command text (a `sh -c` body, a `su -c`
// body, a wrapped call) that a command running in outer runs: the body starts
// where its caller is, so its own moves come after the caller's.
func (s workFolders) within(outer workFolders) workFolders {
	if !outer.moved() {
		return s
	}
	var out workFolders
	for _, start := range outer.orHook() {
		for _, folder := range s.orHook() {
			if start.unknown || folder.unknown {
				out = append(out, workFolder{unknown: true})
				continue
			}
			out = append(out, workFolder{steps: append(append([]string(nil), start.steps...), folder.steps...)})
		}
	}
	return unionWorkFolders(out)
}

// resolveWorkFolder is the folder a command runs in: cwd moved by the steps
// of w. ok is false when the folder is unresolved or a step cannot be
// resolved.
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

// workFolderTracker records, for every statement, the folders it may start
// in.
type workFolderTracker struct {
	folders map[*syntax.Stmt]workFolders
	// movers are the functions of the text whose body may move the folder.
	movers map[string]bool
}

// posixWorkFolders returns, for every statement of file, the folders its
// command may run in.
func posixWorkFolders(file *syntax.File) map[*syntax.Stmt]workFolders {
	tracker := &workFolderTracker{folders: make(map[*syntax.Stmt]workFolders), movers: map[string]bool{}}
	if file == nil {
		return tracker.folders
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok && decl.Name != nil && decl.Body != nil && workFolderBodyMoves(decl.Body) {
			tracker.movers[decl.Name.Value] = true
		}
		return true
	})
	tracker.list(file.Stmts, hookWorkFolders)
	return tracker.folders
}

// workFolderBodyMoves reports a function body with a folder move in it.
func workFolderBodyMoves(body *syntax.Stmt) bool {
	moves := false
	syntax.Walk(body, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			if _, isCD := staticWorkFolderMove(call); isCD {
				moves = true
			}
		}
		return !moves
	})
	return moves
}

// list tracks statements run one after the other from in: ok are the folders
// the shell may be in when the last one succeeded, after the folders it may
// be in at the end whatever happened.
func (t *workFolderTracker) list(stmts []*syntax.Stmt, in workFolders) (ok, after workFolders) {
	ok, after = in, in
	for _, stmt := range stmts {
		ok, after = t.stmt(stmt, after)
	}
	return ok, after
}

// stmt records the folders stmt starts in and returns the folders the shell
// may be in after it: ok when it succeeded, after whatever its status.
func (t *workFolderTracker) stmt(stmt *syntax.Stmt, in workFolders) (ok, after workFolders) {
	if stmt == nil {
		return in, in
	}
	t.folders[stmt] = in
	for _, redirect := range stmt.Redirs {
		if redirect.Word != nil {
			t.substitutions(redirect.Word, in)
		}
		if redirect.Hdoc != nil {
			t.substitutions(redirect.Hdoc, in)
		}
	}
	ok, after = t.command(stmt, in)
	if stmt.Background || stmt.Coprocess {
		// It runs in a copy of the shell.
		return in, in
	}
	if stmt.Negated {
		return after, after
	}
	return ok, after
}

func (t *workFolderTracker) command(stmt *syntax.Stmt, in workFolders) (ok, after workFolders) {
	switch cmd := stmt.Cmd.(type) {
	case nil:
		// A statement with no command (a bare redirect: > file, 2>&1).
		return in, in
	case *syntax.CallExpr:
		t.substitutions(cmd, in)
		if target, isCD := staticWorkFolderMove(cmd); isCD {
			moved := in.with(target)
			for _, candidate := range cdPathCandidates(cmd, target) {
				moved = unionWorkFolders(moved, in.with(candidate))
			}
			// The cd may fail: after it the shell is in the moved folder if
			// it worked, where it was if not.
			return moved, unionWorkFolders(moved, in)
		}
		if len(cmd.Args) != 0 {
			if name := projectPOSIXWord(cmd.Args[0]); !name.Expands && t.movers[name.Value] {
				moved := unionWorkFolders(in, unresolvedWorkFolders)
				return moved, moved
			}
		}
		return in, in
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.AndStmt:
			leftOK, leftAfter := t.stmt(cmd.X, in)
			rightOK, rightAfter := t.stmt(cmd.Y, leftOK)
			return rightOK, unionWorkFolders(leftAfter, rightAfter)
		case syntax.OrStmt:
			leftOK, leftAfter := t.stmt(cmd.X, in)
			rightOK, rightAfter := t.stmt(cmd.Y, leftAfter)
			return unionWorkFolders(leftOK, rightOK), unionWorkFolders(leftAfter, rightAfter)
		default: // a pipe: each member runs in a copy of the shell
			t.stmt(cmd.X, in)
			t.stmt(cmd.Y, in)
			return in, in
		}
	case *syntax.Subshell:
		t.list(cmd.Stmts, in)
		return in, in
	case *syntax.Block:
		return t.list(cmd.Stmts, in)
	case *syntax.IfClause:
		after := t.ifClause(cmd, in)
		return after, after
	case *syntax.WhileClause:
		return t.loop(cmd.Cond, cmd.Do, in)
	case *syntax.ForClause:
		t.substitutions(cmd.Loop, in)
		return t.loop(nil, cmd.Do, in)
	case *syntax.CaseClause:
		if cmd.Word != nil {
			t.substitutions(cmd.Word, in)
		}
		after := in
		for _, item := range cmd.Items {
			for _, pattern := range item.Patterns {
				t.substitutions(pattern, in)
			}
			_, itemAfter := t.list(item.Stmts, in)
			after = unionWorkFolders(after, itemAfter)
		}
		return after, after
	case *syntax.FuncDecl:
		// The body runs where the function is called; its moves are read at
		// the call (movers).
		t.stmt(cmd.Body, in)
		return in, in
	case *syntax.TimeClause:
		if cmd.Stmt != nil {
			return t.stmt(cmd.Stmt, in)
		}
		return in, in
	case *syntax.CoprocClause:
		t.stmt(cmd.Stmt, in)
		return in, in
	default:
		// A declaration, let, test or arithmetic command: only its
		// substitutions hold statements, and they run in a copy.
		t.substitutions(stmt.Cmd, in)
		return in, in
	}
}

// ifClause reads the condition, then every branch: a then-branch runs where
// its condition succeeded, the rest where it failed.
func (t *workFolderTracker) ifClause(clause *syntax.IfClause, in workFolders) workFolders {
	condOK, condAfter := t.list(clause.Cond, in)
	_, thenAfter := t.list(clause.Then, condOK)
	switch {
	case clause.Else == nil:
		return unionWorkFolders(thenAfter, condAfter)
	case len(clause.Else.Cond) == 0:
		_, elseAfter := t.list(clause.Else.Then, condAfter)
		return unionWorkFolders(thenAfter, elseAfter)
	default:
		return unionWorkFolders(thenAfter, t.ifClause(clause.Else, condAfter))
	}
}

// loop reads a loop body twice: the second pass starts wherever a pass may
// leave the shell. A body that moves further on every pass (a relative step)
// leaves an unresolved folder.
func (t *workFolderTracker) loop(cond, body []*syntax.Stmt, in workFolders) (ok, after workFolders) {
	pass := func(start workFolders) workFolders {
		_, condAfter := t.list(cond, start)
		_, bodyAfter := t.list(body, condAfter)
		return unionWorkFolders(start, condAfter, bodyAfter)
	}
	first := pass(in)
	second := pass(first)
	if !sameWorkFolders(first, second) {
		second = unionWorkFolders(second, unresolvedWorkFolders)
	}
	return second, second
}

// substitutions tracks the statements of the command and process
// substitutions in node: each list runs in a copy of the shell that starts in
// the folders of the command that holds it.
func (t *workFolderTracker) substitutions(node syntax.Node, in workFolders) {
	if node == nil {
		return
	}
	syntax.Walk(node, func(inner syntax.Node) bool {
		switch sub := inner.(type) {
		case *syntax.CmdSubst:
			t.list(sub.Stmts, in)
			return false
		case *syntax.ProcSubst:
			t.list(sub.Stmts, in)
			return false
		}
		return true
	})
}

// cdPathCandidates are the folders a cd of a relative target may also reach
// through a static CDPATH assignment on the call itself (CDPATH=/srv cd app):
// the shell tries each entry before the folder it is in. A CDPATH that is
// not one static word is an unresolved folder.
func cdPathCandidates(call *syntax.CallExpr, target string) []string {
	if target == "\x00" || target == "" || strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") ||
		target == "." || target == ".." || strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
		return nil
	}
	var out []string
	for _, assign := range call.Assigns {
		if assign == nil || assign.Name == nil || assign.Name.Value != "CDPATH" {
			continue
		}
		if assign.Value == nil {
			continue
		}
		value := projectPOSIXWord(assign.Value)
		if value.Expands {
			return []string{"\x00"}
		}
		for _, entry := range strings.Split(value.Value, ":") {
			if entry == "" {
				continue
			}
			out = append(out, strings.TrimRight(entry, "/")+"/"+target)
		}
	}
	return out
}

// staticWorkFolderMove reports a cd, pushd or chdir call (also behind
// `builtin` or `command`) and its target: one static word, "~" forms kept as
// written ("" for a bare cd, the home). The target "\x00" marks a move whose
// target is not read (popd, an expansion, `-`, a glob, an option other than
// -L and -P).
func staticWorkFolderMove(call *syntax.CallExpr) (target string, isCD bool) {
	if call == nil || len(call.Args) == 0 {
		return "", false
	}
	args := call.Args
	for len(args) > 1 {
		name := projectPOSIXWord(args[0])
		if name.Expands || name.Value != "builtin" && name.Value != "command" {
			break
		}
		args = args[1:]
	}
	name := projectPOSIXWord(args[0])
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
	for _, word := range args[1:] {
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
		if strings.HasPrefix(argument.Value, "~") {
			// A quoted tilde is a folder of that name in the folder the
			// shell is in (cd '~', the twin of env --chdir=~), not the home.
			return "./" + argument.Value, true
		}
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
// pipelines). A failed Set-Location is not a terminating error and a failed
// CMD cd does not stop the next command after & or a newline, so a move with
// one static target adds its folder to the folders of every later command
// and keeps the folders before it; a move the reader cannot place (a variable
// or glob target, popd, Pop-Location, a pipeline member, a command that sits
// in a block or under uncertain control flow, a bare drive) adds an
// unresolved folder.
func windowsWorkFolders(commands []CommandFact) map[int64]workFolders {
	var folders map[int64]workFolders
	state := hookWorkFolders
	for _, command := range commands {
		if command.Dialect != DialectPowerShell && command.Dialect != DialectCMD {
			continue
		}
		if folders == nil {
			folders = make(map[int64]workFolders)
		}
		folders[command.ID] = state
		if !windowsFolderMove(command) {
			continue
		}
		unconditional := command.ParentCommandID == 0 && command.PipelineID == 0 && !command.Background &&
			(!command.ControlFlowUncertain || command.ControlFlowOperator == ControlFlowOperatorAnd)
		target, ok := windowsFolderTarget(command)
		if !unconditional || !ok {
			target = "\x00"
		}
		state = unionWorkFolders(state, state.with(target))
	}
	return folders
}

// MovesWindowsFolder reports a PowerShell or CMD reading with a folder move
// (Set-Location, cd, chdir, Push-Location, pushd, Pop-Location, popd): the
// relative operands after it are read in every folder it may leave the shell
// in (windowsWorkFolders, SimpleCommands).
func (f Facts) MovesWindowsFolder() bool {
	if f.Parse.Dialect != DialectPowerShell && f.Parse.Dialect != DialectCMD {
		return false
	}
	for _, command := range f.Commands {
		if (command.Dialect == DialectPowerShell || command.Dialect == DialectCMD) && windowsFolderMove(command) {
			return true
		}
	}
	return false
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

// commandWorkFolderDirs are the folders the path facts of command are read
// in: primary is the hook's folder when the command may run there (or its
// folder is unresolved), else the first folder it may run in; others are the
// other folders; unresolved is set when one of its folders is not known.
func commandWorkFolderDirs(cwd, home string, command *CommandFact, windows map[int64]workFolders) (primary string, others []string, unresolved bool) {
	if command == nil || cwd == "" {
		// With no folder of its own (a managed gateway behind ProtectHome, an
		// agent that sends none) a relative operand stays unplaced, as before
		// the tracking: the managed hook client walks the cd chain in the
		// folder it ran the call in and keys its facts there, and the gateway
		// places the call in that folder (toolChainPlacedFacts,
		// managedLinkWalkView), where this tracking runs. A reading against
		// no folder would disagree with the client's keys (GAP-0426).
		return cwd, nil, false
	}
	var folders workFolders
	resolve := resolveWorkFolder
	switch command.Dialect {
	case DialectPOSIX:
		folders = command.workFolders
	case DialectPowerShell, DialectCMD:
		folders = windows[command.ID]
		resolve = resolveWindowsWorkFolder
	default:
		return cwd, nil, false
	}
	if !folders.moved() {
		return cwd, nil, false
	}
	hook := false
	var dirs []string
	for _, folder := range folders.orHook() {
		dir, ok := resolve(cwd, home, folder)
		switch {
		case !ok:
			hook, unresolved = true, true
		case dir == cwd:
			hook = true
		default:
			seen := false
			for _, have := range dirs {
				seen = seen || have == dir
			}
			if !seen {
				dirs = append(dirs, dir)
			}
		}
	}
	if hook || len(dirs) == 0 {
		return cwd, dirs, unresolved
	}
	return dirs[0], dirs[1:], unresolved
}

// MayRunInUnresolvedFolder reports a call with a command that may run in a
// folder the call does not give (cd "$X", cd "$(...)", popd, a loop that
// moves on each pass): the commands whose path facts are UnresolvedFolder,
// with or without a path fact (an unquoted pathname pattern has none).
func (f Facts) MayRunInUnresolvedFolder() bool {
	windows := windowsWorkFolders(f.Commands)
	for index := range f.Commands {
		if _, _, unresolved := commandWorkFolderDirs(f.CWD, f.ActiveHome, &f.Commands[index], windows); unresolved {
			return true
		}
	}
	return false
}

// withWorkFoldersOf is f, the analysis of a twin of the action original was
// read from (a sequence of the same commands: ShortCircuitListReduction,
// CompoundCommandReduction), with its paths read in the folders each command
// may run in in the action itself (a twin may spell a word anew, the home
// for ~ say, so the commands pair up by program and number of words). The
// twin drops the && and || of the
// action, so a cd in it reads as one that may fail before every later
// command, and `cd X && cd Y && b` would read b in X: a folder the action
// never runs it in. When the commands of the two do not pair up one to one
// (same program and number of words in the same order), the twin reads its paths in the
// hook's folder alone, as every reading did before the folders were tracked.
func (f Facts) withWorkFoldersOf(original Facts, windowsShellCWD bool) Facts {
	moved := false
	for _, command := range f.Commands {
		moved = moved || command.workFolders.moved()
	}
	if !moved {
		return f
	}
	if len(original.Commands) != len(f.Commands) {
		return f.AtHookFolder()
	}
	commands := cloneCommands(f.Commands)
	for index := range commands {
		source := original.Commands[index]
		if source.Program != commands[index].Program || len(source.Argv) != len(commands[index].Argv) {
			return f.AtHookFolder()
		}
		commands[index].workFolders = source.workFolders
	}
	paths := make([]PathFact, 0, len(f.Paths))
	for _, path := range f.Paths {
		if path.otherFolder {
			continue
		}
		path.Flavor = path.parsedFlavor
		path.Normalized, path.Absolute, path.Resolved = "", false, ""
		path.atHook, path.unresolvedFolder = nil, false
		paths = append(paths, path)
	}
	// The commands of the twin stay as the twin has them; only its paths
	// are read in the folders of the action.
	f.Paths = normalizePathFactsForCommandsInShell(paths, f.CWD, f.ActiveHome, commands, windowsShellCWD)
	return f
}

// simplePartWorkFolders are, for each statement of a split call
// (sequenceStatementDetails of source), the resolved folders the working
// folder tracking says it may run in (the hook's own folder included: a
// background cd moves nothing); none where cwd is not known.
func simplePartWorkFolders(source string, parts []sequenceStatement, cwd, home string) [][]string {
	out := make([][]string, len(parts))
	if !path.IsAbs(cwd) || len(parts) == 0 {
		return out
	}
	file, ok := shellparse.Parse(source)
	if !ok {
		return out
	}
	// The statement each part starts at: the innermost statement there (the
	// walk visits a list before its members, so the last one wins).
	byOffset := make(map[int]*syntax.Stmt)
	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, isStmt := node.(*syntax.Stmt); isStmt {
			byOffset[int(stmt.Pos().Offset())] = stmt
		}
		return true
	})
	tracked := posixWorkFolders(file)
	for index, part := range parts {
		stmt := byOffset[part.sourceStart]
		if stmt == nil || strings.Contains(part.scope, "/f") || strings.Contains(part.scope, "/e") {
			// A function body runs where it is called; the walk reads it there.
			continue
		}
		folders := tracked[stmt].orHook()
		if slices.ContainsFunc(folders, func(folder workFolder) bool { return folder.unknown }) {
			// A folder the tracking cannot give (cd -, popd, a variable):
			// the walk reads those moves itself (OLDPWD, the directory
			// stack, the values it knows) or leaves the statement unplaced.
			continue
		}
		for _, folder := range folders {
			dir, resolved := resolveWorkFolder(cwd, home, folder)
			if !resolved || slices.Contains(out[index], dir) {
				continue
			}
			out[index] = append(out[index], dir)
		}
	}
	return out
}
