// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"path/filepath"
	"slices"
	"strconv"
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
// of w, by the rules the walk moves its own folder by (simpleChangedDir): a
// POSIX folder joins a step with POSIX rules, a native Windows folder or
// home (C:\Users\alice, the folder Git Bash runs a POSIX call in) with
// native ones. ok is false when the folder is unresolved or a step cannot be
// resolved. A Windows home once gave up on ~ and every step relative to a
// Windows folder, so the folder of cd ~/.defenseclaw was dropped from the
// folders a later statement may run in after a cd that may fail, and a write
// there through a variable was allowed on a Windows gateway
// (rel-1-0-10:GAP-1880).
func resolveWorkFolder(cwd, home string, w workFolder) (string, bool) {
	if w.unknown {
		return "", false
	}
	current := cwd
	for _, step := range w.steps {
		switch {
		case step == "~" || step == "":
			if !simplePathAbs(home) {
				return "", false
			}
			current = simplePathClean(home)
		case strings.HasPrefix(step, "~/"):
			if !simplePathAbs(home) {
				return "", false
			}
			current = workFolderJoin(home, step[2:])
		case strings.HasPrefix(step, "~"):
			return "", false
		case simplePathAbs(step):
			current = simplePathClean(step)
		default:
			if !simplePathAbs(current) {
				return "", false
			}
			current = workFolderJoin(current, step)
		}
	}
	return current, true
}

// workFolderJoin is the folder step names from the absolute folder dir: as
// the walk joins a cd operand to its folder, with POSIX rules under a POSIX
// folder and native ones under a Windows folder.
func workFolderJoin(dir, step string) string {
	if simplePOSIXAbs(dir) {
		return path.Join(dir, step)
	}
	return filepath.Clean(filepath.Join(dir, step))
}

// workFolderTracker records, for every statement, the folders it may start
// in.
type workFolderTracker struct {
	folders map[*syntax.Stmt]workFolders
	// movers are the functions of the text whose body may move the folder.
	movers map[string]bool
	// runners are the functions of the text whose every definition only
	// runs its arguments in the shell (f() { "$@"; }): a call f cd X is the
	// cd X (substrate-1:GAP-0713).
	runners map[string]bool
	// shadowed: the text defines a function named cd, chdir, pushd, popd,
	// builtin or command, so a call of that name may run it instead of the
	// builtin: every move may go to an unresolved folder (substrate-1:GAP-0684)
	// as well as where the builtin goes (substrate-1:GAP-0686).
	shadowed bool
	// exitShadowed: the text defines a function named exit or builtin, so
	// an exit call may return (substrate-1:GAP-0699).
	exitShadowed bool
	// unset holds the function names an unset of the text may remove, and
	// unsetAny says one may remove any function (workFolderUnsetNames): a
	// definition of such a name may be gone at a call, which then runs the
	// builtin or program of the name (substrate-1:GAP-1166).
	unset    map[string]bool
	unsetAny bool
	// decls are the definitions of the movers the text defines once (nil
	// for one defined more than once): a call of one the definition may
	// have run before (workFolderDefinedAt) leaves the shell in the folders
	// its body may leave it in, read from where the call runs.
	decls map[string]*syntax.FuncDecl
	// defs says where the text defines each mover, and callsOf holds the
	// calls of each function name of the text.
	defs    map[*syntax.FuncDecl]workFolderDef
	callsOf map[string][]*syntax.CallExpr
	// depth counts the mover bodies being read for a call, and calls the
	// bodies read so far (shared): past either bound a call of a mover
	// leaves an unresolved folder. inBody counts the function bodies the
	// tracking is in.
	depth, inBody int
	calls         *int
	// defined holds the definedAt answers of the scan (shared with the
	// trackers of the mover bodies it reads), so each is worked out once
	// (rel-1-0-10:GAP-1292).
	defined map[workFolderDefinedKey]bool
	// firstRun holds, per outer definition, climb depth and body flag, the
	// earliest call of the outer function after which a definition in its
	// body may have run (shared like defined), so a call of the inner
	// function compares one offset instead of asking each outer call again
	// (rel-1-0-10:GAP-1293).
	firstRun map[workFolderDefinedKey]workFolderFirstRun
	// returned holds the folders of the calls that may return from the
	// mover body being read, and returnedOK those whose status may be 0:
	// a call of the mover may end there, before the rest of its body
	// (substrate-1:GAP-0690). They are kept per body: a return in the body
	// of a function defined or called in it ends only that function.
	returned, returnedOK workFolders
	// unreadMovers: every mover call leaves an unresolved folder, as no
	// body of one is read (rel 740c0de8fd's reading of every mover call,
	// posixWorkFolders).
	unreadMovers bool
}

// workFolderFirstRun is the earliest offset of a call of an outer function
// whose definition may have run there (ok false when no call qualifies).
type workFolderFirstRun struct {
	from uint
	ok   bool
}

// workFolderDefinedKey is everything a definedAt answer depends on beyond
// the scan: the definition, the call, the depth of the climb and whether
// the tracking is in a function body.
type workFolderDefinedKey struct {
	decl   *syntax.FuncDecl
	call   *syntax.CallExpr
	depth  int
	inBody bool
}

// workFolderDef is where the text defines a mover. topLevel: a statement of
// the top level of the text, which runs before every statement after it.
// outer is the function whose body defines it (nil when the text itself
// does, in a list, a group, a branch or a loop of it). scopes are the
// subshells, command and process substitutions and pipeline stages the
// definition is in: it defines nothing for the shell outside them.
type workFolderDef struct {
	topLevel bool
	outer    *syntax.FuncDecl
	scopes   []workFolderSpan
}

// workFolderSpan is the source range [from, to) of a node.
type workFolderSpan struct{ from, to uint }

func workFolderSpanOf(node syntax.Node) workFolderSpan {
	return workFolderSpan{from: node.Pos().Offset(), to: node.End().Offset()}
}

func (s workFolderSpan) holds(offset uint) bool { return s.from <= offset && offset < s.to }

// maxWorkFolderCallDepth bounds the nested mover calls whose bodies the
// tracking reads, and maxWorkFolderCalls the bodies it reads for one text.
const (
	maxWorkFolderCallDepth = 4
	maxWorkFolderCalls     = 64
)

// newWorkFolderTracker is a tracker of file with its movers and their
// bodies.
func newWorkFolderTracker(file *syntax.File) *workFolderTracker {
	tracker := &workFolderTracker{folders: make(map[*syntax.Stmt]workFolders)}
	if file == nil {
		return tracker
	}
	// The tracker is made for every text the reader parses, most of them
	// one statement with no function: the scopes and calls are only kept
	// here and worked out below for a text that defines a function, and
	// the calls only by the name of a function another mover is defined in
	// (rel-1-0-10:GAP-1293).
	var all []*syntax.FuncDecl
	var scopeNodes []syntax.Node
	var calls []*syntax.CallExpr
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if node.Name != nil {
				// A function of a move's name may run instead of the
				// builtin (substrate-1:GAP-0684): every move may go to an
				// unresolved folder, in the text and in mover bodies.
				switch node.Name.Value {
				case "cd", "chdir", "pushd", "popd", "builtin", "command":
					tracker.shadowed = true
				}
				// A function named exit (or builtin) may return: an exit
				// call ends nothing (substrate-1:GAP-0699).
				switch node.Name.Value {
				case "exit", "builtin":
					tracker.exitShadowed = true
				}
			}
			if node.Name != nil && node.Body != nil {
				all = append(all, node)
			}
		case *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
			scopeNodes = append(scopeNodes, node)
		case *syntax.BinaryCmd:
			if node.Op == syntax.Pipe || node.Op == syntax.PipeAll {
				scopeNodes = append(scopeNodes, node.X, node.Y)
			}
		case *syntax.CallExpr:
			if len(node.Args) != 0 {
				calls = append(calls, node)
			}
		}
		return true
	})
	if len(all) == 0 {
		return tracker // no function, so no mover
	}
	tracker.movers, tracker.decls = map[string]bool{}, map[string]*syntax.FuncDecl{}
	tracker.runners = map[string]bool{}
	notRunner := map[string]bool{}
	for _, decl := range all {
		if workFolderArgRunner(decl.Body) {
			tracker.runners[decl.Name.Value] = true
		} else {
			notRunner[decl.Name.Value] = true
		}
	}
	for name := range notRunner {
		delete(tracker.runners, name)
	}
	tracker.unset, tracker.unsetAny = workFolderUnsetNames(calls, all, tracker.runners)
	tracker.defs, tracker.callsOf = map[*syntax.FuncDecl]workFolderDef{}, map[string][]*syntax.CallExpr{}
	tracker.calls, tracker.defined = new(int), map[workFolderDefinedKey]bool{}
	tracker.firstRun = map[workFolderDefinedKey]workFolderFirstRun{}
	topLevel := make(map[*syntax.FuncDecl]bool)
	for _, stmt := range file.Stmts {
		if decl, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
			topLevel[decl] = true
		}
	}
	scopes := make([]workFolderSpan, 0, len(scopeNodes))
	for _, node := range scopeNodes {
		scopes = append(scopes, workFolderSpanOf(node))
	}
	// A function whose body moves, or calls a function that does, is a
	// mover.
	for changed := true; changed; {
		changed = false
		for _, decl := range all {
			if !tracker.movers[decl.Name.Value] && workFolderBodyMoves(decl.Body, tracker.movers) {
				tracker.movers[decl.Name.Value], changed = true, true
			}
		}
	}
	for _, decl := range all {
		name := decl.Name.Value
		if !tracker.movers[name] && !tracker.runners[name] {
			// A runner keeps its definition too: its call is read as its
			// arguments only where the definition has run
			// (substrate-1:GAP-0713, CHK-T6-SCB).
			continue
		}
		if _, seen := tracker.decls[name]; seen {
			tracker.decls[name] = nil
			continue
		}
		tracker.decls[name] = decl
		// A definition anywhere in the text, not only at its top level,
		// defines a mover (rel-1-0-10:GAP-1229): `cd D && f() { cd X ||
		// return; }; f; <write>` leaves the shell in X or D.
		def := workFolderDef{topLevel: topLevel[decl]}
		span := workFolderSpanOf(decl)
		for _, scope := range scopes {
			if scope.from <= span.from && span.to <= scope.to {
				def.scopes = append(def.scopes, scope)
			}
		}
		for _, other := range all {
			if other == decl {
				continue
			}
			body := workFolderSpanOf(other.Body)
			if body.from <= span.from && span.to <= body.to &&
				(def.outer == nil || body.from >= def.outer.Body.Pos().Offset()) {
				def.outer = other // the innermost body around it
			}
		}
		tracker.defs[decl] = def
	}
	// definedAt reads the calls of the function each mover is defined in.
	outers := map[string]bool{}
	for _, def := range tracker.defs {
		if def.outer != nil {
			outers[def.outer.Name.Value] = true
		}
	}
	if len(outers) != 0 {
		for _, call := range calls {
			if name := projectPOSIXWord(call.Args[0]); !name.Expands && outers[name.Value] {
				tracker.callsOf[name.Value] = append(tracker.callsOf[name.Value], call)
			}
		}
	}
	return tracker
}

// definedAt reports a definition of a mover that may have run before call
// (the one bound of a call is its depth): a call in the subshells and
// substitutions of the definition, and, for one made at the top level of
// the text, after it (a call in a function body runs when that body runs).
// A definition in a function body has run only after a call of that body:
// a function defined in the body of a function the text never calls is not
// defined (rel-1-0-10:GAP-1144, the envelope rows). Each answer is worked
// out once per scan: the climb asks the same (outer definition, outer call)
// for every call of the inner one, which made nested definitions with many
// calls of each outer function cost the product of those counts
// (rel-1-0-10:GAP-1292). The calls of the outer function are asked once per
// outer definition and depth (outerFirstRun), not once per inner call: a
// top-level call of the inner function is defined when one of them before
// it is, which is when the earliest of them is (rel-1-0-10:GAP-1293).
func (t *workFolderTracker) definedAt(decl *syntax.FuncDecl, call *syntax.CallExpr, depth int) bool {
	key := workFolderDefinedKey{decl: decl, call: call, depth: depth, inBody: t.inBody != 0}
	if defined, seen := t.defined[key]; seen {
		return defined
	}
	defined := t.definedAtUncached(decl, call, depth)
	t.defined[key] = defined
	return defined
}

func (t *workFolderTracker) definedAtUncached(decl *syntax.FuncDecl, call *syntax.CallExpr, depth int) bool {
	def, known := t.defs[decl]
	at := call.Pos().Offset()
	if !known || depth > maxWorkFolderCallDepth || slices.ContainsFunc(def.scopes, func(scope workFolderSpan) bool { return !scope.holds(at) }) {
		return false
	}
	if def.outer == nil {
		return t.inBody != 0 || at >= decl.Pos().Offset()
	}
	if workFolderSpanOf(def.outer.Body).holds(at) {
		return true // the body that defines it calls it
	}
	if t.decls[def.outer.Name.Value] != def.outer {
		return false
	}
	first := t.outerFirstRun(def.outer, depth+1)
	// In a function body the call runs when the body does, after any
	// call of the outer function; at the top level only one before it.
	return first.ok && (t.inBody != 0 || first.from < at)
}

// outerFirstRun returns the earliest call of the function outer, outside
// its own body, at which outer may have been defined (definedAt at depth).
// Every such call is asked once, whatever the order of callsOf.
func (t *workFolderTracker) outerFirstRun(outer *syntax.FuncDecl, depth int) workFolderFirstRun {
	key := workFolderDefinedKey{decl: outer, depth: depth, inBody: t.inBody != 0}
	if first, seen := t.firstRun[key]; seen {
		return first
	}
	var first workFolderFirstRun
	body := workFolderSpanOf(outer.Body)
	for _, outerCall := range t.callsOf[outer.Name.Value] {
		from := outerCall.Pos().Offset()
		if body.holds(from) || first.ok && from >= first.from {
			continue
		}
		if t.definedAt(outer, outerCall, depth) {
			first = workFolderFirstRun{from: from, ok: true}
		}
	}
	t.firstRun[key] = first
	return first
}

// posixWorkFolders returns, for every statement of file, the folders its
// command may run in, and, when the tracking read the body of a mover call,
// unread: the folders of every statement when no mover body is read, so
// every mover call leaves an unresolved folder (Facts.WithMoverCallsUnread).
func posixWorkFolders(file *syntax.File) (folders, unread map[*syntax.Stmt]workFolders) {
	tracker := newWorkFolderTracker(file)
	if file == nil {
		return tracker.folders, nil
	}
	tracker.list(file.Stmts, hookWorkFolders)
	if tracker.calls == nil || *tracker.calls == 0 {
		return tracker.folders, nil // no mover body was read: the readings agree
	}
	other := &workFolderTracker{folders: make(map[*syntax.Stmt]workFolders), movers: tracker.movers, unreadMovers: true,
		exitShadowed: tracker.exitShadowed}
	other.list(file.Stmts, hookWorkFolders)
	return tracker.folders, other.folders
}

// functionBodyWorkFolders returns, for every statement of a function body
// of file, the folders it may run in relative to the folder the body starts
// in (the folder of the call that runs it). A statement of a function
// defined in another function's body is read relative to its own body.
func functionBodyWorkFolders(file *syntax.File) map[*syntax.Stmt]workFolders {
	tracker := newWorkFolderTracker(file)
	if file == nil {
		return tracker.folders
	}
	var bodies []*syntax.Stmt
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok && decl.Body != nil {
			bodies = append(bodies, decl.Body)
		}
		return true
	})
	// The walk meets an enclosing definition before the ones in its body,
	// so the innermost body is read last and its reading stays.
	tracker.inBody = 1
	for _, body := range bodies {
		tracker.stmt(body, hookWorkFolders)
	}
	return tracker.folders
}

// moverCall returns the folders the shell may be in after call, a call of
// the mover name that starts in in: those its body leaves, read from in (ok
// where the body succeeded), and where the call started when the
// definition may not have run. A mover the tracking cannot tie to one
// definition that may have run before the call (defined more than once, a
// top-level call before the definition, a definition in a subshell or in the
// body of a function the text does not call first; definedAt), or past the
// bounds of the tracking, leaves an unresolved folder.
func (t *workFolderTracker) moverCall(name string, call *syntax.CallExpr, in workFolders) (ok, after workFolders) {
	decl := t.decls[name]
	if decl == nil || t.depth >= maxWorkFolderCallDepth || *t.calls >= maxWorkFolderCalls || !t.definedAt(decl, call, 0) {
		moved := unionWorkFolders(in, unresolvedWorkFolders)
		return moved, moved
	}
	*t.calls++
	// The body statements keep the folders recorded where they are; only
	// the folders the call leaves are read here.
	inner := &workFolderTracker{folders: make(map[*syntax.Stmt]workFolders), movers: t.movers, decls: t.decls,
		defs: t.defs, callsOf: t.callsOf, depth: t.depth + 1, inBody: t.inBody + 1, calls: t.calls, defined: t.defined,
		firstRun: t.firstRun, shadowed: t.shadowed, exitShadowed: t.exitShadowed, unset: t.unset, unsetAny: t.unsetAny}
	ok, after = inner.stmt(decl.Body, in)
	// `f() { test -f .bashrc && return; cd /tmp; }; f && echo x >> .bashrc`
	// may leave the shell where the body returned, with status 0 (the
	// substrate-1:GAP-0690 rows); the folder of its last cd alone is wrong.
	// The folders stay exact: an unresolved folder here (rel's reading of
	// every mover call) drops the block of a protected write the body may
	// return in (`cd ~/.defenseclaw && f() { cd X || return 0; }; f && echo
	// m > config.yaml`, rel-1-0-10:GAP-1229).
	if len(inner.returned) != 0 {
		after = unionWorkFolders(after, inner.returned)
	}
	if len(inner.returnedOK) != 0 {
		ok = unionWorkFolders(ok, inner.returnedOK)
	}
	if t.mayUnset(name) {
		// An unset of the name may have removed the definition: the call
		// then runs the builtin or program of the name, which may succeed
		// where the shell was (substrate-1:GAP-1166).
		ok, after = unionWorkFolders(ok, in), unionWorkFolders(after, in)
	} else if !t.defs[decl].topLevel {
		// A definition in a list, a branch or a body may not have run: the
		// call then finds no function, fails and leaves the shell where it
		// was.
		after = unionWorkFolders(after, in)
	}
	return ok, after
}

// mayUnset reports a function name an unset of the text may remove.
func (t *workFolderTracker) mayUnset(name string) bool { return t.unsetAny || t.unset[name] }

// workFolderUnsetNames returns the function names the unset calls among
// calls may remove: unset -f NAME, and unset NAME, which removes the function
// when no variable has the name (only -v or -n with no -f leaves functions
// alone). It reads every unset of the text, before or after a call: one
// after a call in a loop runs before its next turn, and one after the last
// call (a script that removes its helper at its end) only adds the folder
// the shell was in. An unset run through builtin or command, with or
// without their options, is read the same. expands says the text may run
// an unset it does not spell out, so it may remove any function
// (substrate-1:GAP-1166): an option or operand of an unset expands, a
// command name expands ($u -f f), or eval or trap runs text that expands or
// names unset. A runner's name before an unset runs it too.
func workFolderUnsetNames(calls []*syntax.CallExpr, decls []*syntax.FuncDecl, runners map[string]bool) (names map[string]bool, expands bool) {
	// The "$@" of a runner body runs the arguments of its calls, read
	// below as the command after the runner's name.
	runs := map[*syntax.CallExpr]bool{}
	for _, decl := range decls {
		if runners[decl.Name.Value] && workFolderArgRunner(decl.Body) {
			runs[decl.Body.Cmd.(*syntax.Block).Stmts[0].Cmd.(*syntax.CallExpr)] = true
		}
	}
	for _, call := range calls {
		if runs[call] {
			continue
		}
		args := call.Args
		for len(args) > 1 {
			prefix := projectPOSIXWord(args[0])
			if !prefix.Expands && runners[prefix.Value] {
				args = args[1:] // f unset -f g runs the unset
				continue
			}
			if prefix.Expands || prefix.Value != "builtin" && prefix.Value != "command" {
				break
			}
			// command -p unset ...: the options of builtin and command
			// do not change the command they run.
			for args = args[1:]; len(args) > 1; args = args[1:] {
				if option := projectPOSIXWord(args[0]); option.Expands || len(option.Value) < 2 || option.Value[0] != '-' {
					break
				}
			}
		}
		program := projectPOSIXWord(args[0])
		if program.Expands {
			return nil, true
		}
		if program.Value == "eval" || program.Value == "trap" {
			for _, arg := range args[1:] {
				if word := projectPOSIXWord(arg); word.Expands || strings.Contains(word.Value, "unset") {
					return nil, true
				}
			}
			continue
		}
		if program.Value != "unset" {
			continue
		}
		functions, variablesOnly, operands := false, false, false
		var unset []string
		for _, arg := range args[1:] {
			word := projectPOSIXWord(arg)
			if word.Expands {
				if variablesOnly && !functions {
					// unset -v "$X" removes a variable: a word that
					// expands to -f then is a usage error.
					break
				}
				return nil, true
			}
			if !operands && word.Value == "--" {
				operands = true
				continue
			}
			if !operands && len(word.Value) > 1 && word.Value[0] == '-' {
				functions = functions || strings.Contains(word.Value, "f")
				variablesOnly = variablesOnly || strings.ContainsAny(word.Value, "vn")
				continue
			}
			operands = true
			unset = append(unset, word.Value)
		}
		if variablesOnly && !functions {
			continue
		}
		for _, name := range unset {
			if names == nil {
				names = map[string]bool{}
			}
			names[name] = true
		}
	}
	return names, false
}

// add is s with the folders of in, the hook's own folder for an empty in.
func (s workFolders) add(in workFolders) workFolders {
	if len(s) == 0 {
		return in.orHook()
	}
	return unionWorkFolders(s, in)
}

// workFolderReturn reports a call that may return from the function body it
// runs in: `return` (also behind builtin or command), eval, or a command
// whose name the tracking does not read (`$r`); ok when its status may be 0
// (a static nonzero `return N` cannot pass an &&). An exit leaves the shell and runs nothing after it,
// and a break or continue only leaves a loop, whose folders the loop
// reading already keeps.
func workFolderReturn(call *syntax.CallExpr) (returns, ok bool) {
	args, prefix := call.Args, false
	for len(args) > 1 {
		word := projectPOSIXWord(args[0])
		if word.Expands {
			break
		}
		if word.Value == "builtin" || word.Value == "command" || prefix && strings.HasPrefix(word.Value, "-") {
			args, prefix = args[1:], true
			continue
		}
		break
	}
	if len(args) == 0 {
		return false, false
	}
	name := projectPOSIXWord(args[0])
	switch {
	case name.Expands, name.Value == "eval":
		return true, true
	case name.Value != "return":
		return false, false
	case len(args) < 2:
		return true, true
	}
	status := projectPOSIXWord(args[1])
	if n, err := strconv.Atoi(status.Value); !status.Expands && err == nil && n&0xff != 0 {
		return true, false
	}
	return true, true
}

// workFolderArgRunner reports a function body that only runs the
// function's arguments as a command in the shell: { "$@"; } with no
// redirect, background or negation (a ( ) body runs them in a copy).
func workFolderArgRunner(body *syntax.Stmt) bool {
	block, ok := body.Cmd.(*syntax.Block)
	if !ok || len(body.Redirs) != 0 || len(block.Stmts) != 1 {
		return false
	}
	stmt := block.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Background || stmt.Negated || stmt.Coprocess || len(stmt.Redirs) != 0 ||
		len(call.Assigns) != 0 || len(call.Args) != 1 || len(call.Args[0].Parts) != 1 {
		return false
	}
	quoted, ok := call.Args[0].Parts[0].(*syntax.DblQuoted)
	if !ok || quoted.Dollar || len(quoted.Parts) != 1 {
		return false
	}
	param, ok := quoted.Parts[0].(*syntax.ParamExp)
	return ok && param.Param != nil && param.Param.Value == "@" &&
		param.Exp == nil && param.Repl == nil && param.Slice == nil && param.Index == nil &&
		!param.Excl && !param.Length && !param.Width && param.Names == 0
}

// workFolderBodyMoves reports a function body with a folder move in it, or
// a call of one of movers.
func workFolderBodyMoves(body *syntax.Stmt, movers map[string]bool) bool {
	moves := false
	syntax.Walk(body, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			if _, isCD := staticWorkFolderMove(call); isCD {
				moves = true
			} else if len(call.Args) != 0 {
				if name := projectPOSIXWord(call.Args[0]); !name.Expands && movers[name.Value] {
					moves = true
				}
			}
		}
		return !moves
	})
	return moves
}

// exits reports a statement after which the shell runs nothing more: a
// call of the exit builtin (or builtin exit), alone or as the last statement
// of a { } group, in the shell itself (not in the background, a pipe or a
// subshell), when no function of the text is named exit.
func (t *workFolderTracker) exits(stmt *syntax.Stmt) bool {
	for stmt != nil && !t.exitShadowed && !stmt.Background && !stmt.Coprocess && !stmt.Negated {
		switch cmd := stmt.Cmd.(type) {
		case *syntax.Block:
			if len(cmd.Stmts) == 0 {
				return false
			}
			stmt = cmd.Stmts[len(cmd.Stmts)-1]
		case *syntax.CallExpr:
			args := cmd.Args
			if len(args) > 1 {
				if word := projectPOSIXWord(args[0]); !word.Expands && word.Value == "builtin" {
					args = args[1:]
				}
			}
			if len(args) == 0 {
				return false
			}
			name := projectPOSIXWord(args[0])
			return !name.Expands && name.Value == "exit"
		default:
			return false
		}
	}
	return false
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
		if returns, ok := workFolderReturn(cmd); returns {
			t.returned = t.returned.add(in)
			if ok {
				t.returnedOK = t.returnedOK.add(in)
			}
		}
		if target, isCD := staticWorkFolderMove(cmd); isCD {
			moved := in.with(target)
			for _, candidate := range cdPathCandidates(cmd, target) {
				moved = unionWorkFolders(moved, in.with(candidate))
			}
			if t.shadowed {
				// A function of the move's name may run instead of the
				// builtin and go anywhere, or where the builtin goes
				// (cd(){ builtin cd "$@"; }): both, so the call is never
				// weaker than its plain form (substrate-1:GAP-0686).
				moved = unionWorkFolders(moved, unresolvedWorkFolders)
			}
			// The cd may fail: after it the shell is in the moved folder if
			// it worked, where it was if not.
			return moved, unionWorkFolders(moved, in)
		}
		if len(cmd.Args) != 0 && len(t.movers) != 0 {
			if name := projectPOSIXWord(cmd.Args[0]); !name.Expands && t.movers[name.Value] {
				if t.unreadMovers {
					moved := unionWorkFolders(in, unresolvedWorkFolders)
					return moved, moved
				}
				// After `f() { cd X || cd Y; }; f` the shell is in X, Y or
				// where it was (rel-1-0-10:GAP-1144).
				return t.moverCall(name.Value, cmd, in)
			}
		}
		if len(cmd.Args) > 1 && len(t.runners) != 0 {
			if name := projectPOSIXWord(cmd.Args[0]); !name.Expands && t.runners[name.Value] {
				// After f() { "$@"; }, f cd X is the cd X, run in the shell
				// itself (substrate-1:GAP-0713). Only a definition at the
				// top level of the text before the call has surely run; one
				// that may have run (in a list, a branch or a body) may leave
				// the call to a builtin or program of the name, so the shell
				// may also stay where it was; one that cannot have run yet
				// leaves it there (CHK-T6-SCB). So does one an unset of the
				// text may remove (unset -f f, or unset f): the call may run
				// the builtin of the name (substrate-1:GAP-1166).
				decl := t.decls[name.Value]
				if decl == nil || !t.definedAt(decl, cmd, 0) {
					return in, in
				}
				ok, after := t.command(&syntax.Stmt{Cmd: &syntax.CallExpr{Args: cmd.Args[1:]}}, in)
				if !t.defs[decl].topLevel || t.mayUnset(name.Value) {
					ok, after = unionWorkFolders(ok, in), unionWorkFolders(after, in)
				}
				return ok, after
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
			if t.exits(cmd.Y) {
				// After `cd X || exit` the shell goes on only where the
				// left side succeeded: the exit ends it where the cd failed
				// (substrate-1:GAP-0699).
				return leftOK, leftOK
			}
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
		t.inBody++
		returned, returnedOK := t.returned, t.returnedOK
		t.stmt(cmd.Body, in)
		t.returned, t.returnedOK = returned, returnedOK // its returns end that body only
		t.inBody--
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
	// The commands of the twin stay as the twin has them; only its paths
	// are read in the folders of the action.
	f.Paths = f.pathsReadIn(commands, windowsShellCWD)
	return f
}

// pathsReadIn are the path facts of f, each operand read anew in the
// folders commands give its command.
func (f Facts) pathsReadIn(commands []CommandFact, windowsShellCWD bool) []PathFact {
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
	return normalizePathFactsForCommandsInShell(paths, f.CWD, f.ActiveHome, commands, windowsShellCWD)
}

// WithMoverCallsUnread is f read as rel 740c0de8fd read every call of a
// function whose body moves the folder: the call leaves an unresolved
// folder (and the one it started in), so a relative operand after it keeps
// its reading in the folder before the call and is UnresolvedFolder. The
// tracking reads such a body (rel-1-0-10:GAP-1144), which is right for a
// call it reads in full; a call with a part the split cannot read may undo
// any cd of the body (substrate-1:GAP-0702, GAP-0711), so the gateway also
// judges it by this reading. ok is false when f read no mover body: the two
// readings are the same. windowsShellCWD is Input.MovedWindowsShellCWD.
func (f Facts) WithMoverCallsUnread(windowsShellCWD bool) (unread Facts, ok bool) {
	commands := cloneCommands(f.Commands)
	for index := range commands {
		if commands[index].moverUnread {
			commands[index].workFolders, ok = commands[index].moverUnreadFolders, true
		}
	}
	if !ok {
		return f, false
	}
	f.Paths = f.pathsReadIn(commands, windowsShellCWD)
	f.Commands, f.moverCallsUnread = commands, true
	return f, true
}

// MoverCallsUnread reports facts that are the reading of
// WithMoverCallsUnread.
func (f Facts) MoverCallsUnread() bool { return f.moverCallsUnread }

// simplePartWorkFolders are, for each statement of a split call
// (sequenceStatementDetails of source), the resolved folders the working
// folder tracking says it may run in (the hook's own folder included: a
// background cd moves nothing); none where cwd is not known. A Windows hook
// folder (C:\Users\alice, the folder Git Bash runs a POSIX call in) is
// known: path.IsAbs alone left every statement of such a call read only
// where the walk moved, so after `[ -e .bashrc ] || cd /tmp` or a mover
// call that may return, a write was never read in the hook's folder on a
// Windows gateway (substrate-1:GAP-0696). resolveWorkFolder reads a step
// from it, and from a Windows home, as the walk does (rel-1-0-10:GAP-1880),
// and gives up on a relative one.
func simplePartWorkFolders(source string, parts []sequenceStatement, cwd, home string) [][]string {
	out := make([][]string, len(parts))
	if !simplePathAbs(cwd) || len(parts) == 0 {
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
	tracked, _ := posixWorkFolders(file)
	// The call statements, by the offset of their call, and the folders of
	// function body statements relative to the call that runs the body.
	var calls map[int]*syntax.Stmt
	var inBody map[*syntax.Stmt]workFolders
	for index, part := range parts {
		stmt := byOffset[part.sourceStart]
		if stmt == nil {
			continue
		}
		folders := tracked[stmt]
		if strings.Contains(part.scope, "/f") || strings.Contains(part.scope, "/e") {
			// A function body runs where it is called: in each folder the
			// call may run in, moved by the steps of the body before the
			// statement. After `cd X || cd Y && f` that is X and Y, not the
			// one folder the walk moved to (rel-1-0-10:GAP-1144). A body the
			// text never calls, or a call the tracking did not record, is
			// read by the walk alone.
			if calls == nil {
				calls, inBody = workFolderCallStatements(file), functionBodyWorkFolders(file)
			}
			var placed bool
			folders, placed = calledBodyWorkFolders(part.callStarts, stmt, calls, tracked, inBody)
			if !placed {
				continue
			}
		}
		folders = folders.orHook()
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

// workFolderCallStatements maps the offset of every call of file to the
// statement whose command it is.
func workFolderCallStatements(file *syntax.File) map[int]*syntax.Stmt {
	calls := make(map[int]*syntax.Stmt)
	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, ok := node.(*syntax.Stmt); ok {
			if call, isCall := stmt.Cmd.(*syntax.CallExpr); isCall {
				calls[int(call.Pos().Offset())] = stmt
			}
		}
		return true
	})
	return calls
}

// calledBodyWorkFolders are the folders a statement of a function body runs
// in when the calls at callStarts (outermost first) run it: the folders of
// the outermost call, then the steps of each inner call and of the
// statement in their bodies. placed is false when a call is not one the
// tracking read.
func calledBodyWorkFolders(callStarts []int, stmt *syntax.Stmt, calls map[int]*syntax.Stmt,
	tracked, inBody map[*syntax.Stmt]workFolders) (workFolders, bool) {
	if len(callStarts) == 0 {
		return nil, false
	}
	outer, found := calls[callStarts[0]]
	if !found {
		return nil, false
	}
	folders, found := tracked[outer]
	if !found {
		return nil, false
	}
	for _, start := range callStarts[1:] {
		inner, found := calls[start]
		if !found {
			return nil, false
		}
		relative, found := inBody[inner]
		if !found {
			return nil, false
		}
		folders = relative.within(folders)
	}
	relative, found := inBody[stmt]
	if !found {
		return nil, false
	}
	return relative.within(folders), true
}
