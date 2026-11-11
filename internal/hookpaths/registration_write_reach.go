// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// registrationWriteReachedAs is RegistrationWriteReached in one reading of
// the command: it runs the shared concrete shell mutation reader against a caller-supplied registration set and returns the members of that
// set the command provably writes, in the order given. It uses the same
// value, directory and link resolution as the protected state decision,
// including ordered shell assignments and cd-relative operands. The command
// is parsed and every member is stat-ed once; the set is then narrowed by
// halves, so a command that reaches k members costs about k*log(n) reads of
// the command rather than one per member. A write proof concerns one member,
// so a half reaches exactly when one of its members does.
func registrationWriteReachedAs(command, cwd, home string, names []string) []string {
	if command == "" || !filepath.IsAbs(cwd) || len(names) == 0 {
		return nil
	}
	if !RegistrationWriteCandidate(command) {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	protected := make(protectedFiles, 0, len(names))
	origin := make([]string, 0, len(names))
	for _, name := range names {
		if !filepath.IsAbs(name) {
			continue
		}
		entry := protectedFile{path: filepath.Clean(name)}
		if info, err := pathStat(entry.path); err == nil {
			entry.info = info
		} else if !os.IsNotExist(err) {
			entry.unknown = true
		}
		protected = append(protected, entry)
		origin = append(origin, name)
	}
	var reached []string
	var narrow func(lo, hi int)
	narrow = func(lo, hi int) {
		if lo >= hi || !registrationWriteReach(file, command, cwd, home, protected[lo:hi]) {
			return
		}
		if hi-lo == 1 {
			reached = append(reached, origin[lo])
			return
		}
		mid := lo + (hi-lo)/2
		narrow(lo, mid)
		narrow(mid, hi)
	}
	narrow(0, len(protected))
	// A write-capable command that holds a flow construct and names a
	// registered file is a reach, whatever the exact reading made of it.
	flow := registrationFlowMembers(file, command, cwd, home, protected)
	if !slices.Contains(flow, true) {
		return reached
	}
	var merged []string
	for index, name := range origin {
		if flow[index] || slices.Contains(reached, name) {
			merged = append(merged, name)
		}
	}
	return merged
}

func registrationWriteReach(file *syntax.File, command, cwd, home string, protected protectedFiles) bool {
	fileProtected := make(protectedFiles, 0, len(protected))
	for _, entry := range protected {
		if entry.info == nil || !entry.info.IsDir() {
			fileProtected = append(fileProtected, entry)
		}
	}
	if actionClientResolvedProtectedWrite(file, command, cwd, home, protected, "") {
		return true
	}
	readOperands := func(body, dir string, user KnownUser) bool {
		writes := LiteralWriteOperands(body, dir, home)
		writes = append(writes, InPlaceEditOperands(body, dir, home, user)...)
		if strings.Contains(body, ">") {
			redirects, _, _ := ShellWriteOperands(body, dir, home)
			writes = append(writes, redirects...)
			bounded, _ := BoundedShellWriteOperands(body, dir, home)
			writes = append(writes, bounded...)
		}
		for _, path := range writes {
			if protectedReachPath(OperandPath(path, dir), fileProtected, "") {
				return true
			}
		}
		return false
	}
	if readOperands(command, cwd, KnownUser{Name: ActionKnownUser(command, home)}) {
		return true
	}
	if registrationPatchReach(file, cwd, home, protected) {
		return true
	}
	if registrationCopyReach(file, cwd, home, fileProtected) {
		return true
	}
	if registrationLoopReach(file, command, cwd, home, protected) ||
		registrationFindRsyncReach(file, cwd, home, protected) {
		return true
	}
	if strings.Contains(command, "cd ") || strings.Contains(command, "pushd ") {
		if statements, ok := TopLevelStatements(command, cwd, home); ok {
			for _, statement := range statements {
				if readOperands(statement.Command, statement.Dir, statement.User) {
					return true
				}
			}
		}
	}
	if registrationWalkLinks(file, command, cwd, home, protected, false, pipeEachChild) {
		return true
	}
	if !registrationOpaqueFlow(file) {
		return false
	}
	// The command carries state through a pipeline, ends or shadows a builtin
	// the exact reading models, or runs text it builds: it is not straight-line
	// code. A write it names is judged as reaching the target, so every way the
	// shell may carry the values (each pipe stage in a child shell, in the
	// current shell, or only the last one there) is read with every part
	// running.
	for _, pipes := range []registrationPipes{pipeEachChild, pipeLastInParent, pipeAllInParent} {
		if registrationWalkLinks(file, command, cwd, home, protected, true, pipes) {
			return true
		}
	}
	return false
}

// registrationPipes says which stages of a pipeline run in the current shell.
type registrationPipes int

const (
	pipeEachChild    registrationPipes = iota // every stage runs in a shell of its own
	pipeLastInParent                          // lastpipe: only the last stage runs in the current shell
	pipeAllInParent                           // the state of every stage is read as the current shell
)

// registrationWalkLinks reads the command in execution order with the shell
// state it holds at each point. Loose reading drops what only straight-line
// code can promise: a branch a fixed condition rules out and an unset -f.
func registrationWalkLinks(file *syntax.File, command, cwd, home string, protected protectedFiles, loose bool, pipes registrationPipes) bool {
	values := actionValues{"HOME": home, "PWD": cwd}
	currentCWD := cwd
	var stack []string
	found := false
	uncalled := actionUncalledFunctions(file, command)
	called := registrationCalledFunctions(file)
	functions := make(map[string]*syntax.FuncDecl)
	running := make(map[*syntax.FuncDecl]bool)
	// inert counts the enclosing parts that do not run at this point: a branch
	// a fixed condition rules out and the body of a function that is read at
	// its calls. Inside them the shell state and the link arm stand still.
	inert := 0
	var visit func(node syntax.Node) bool
	walkInert := func(stmts ...*syntax.Stmt) {
		inert++
		for _, stmt := range stmts {
			syntax.Walk(stmt, visit)
		}
		inert--
	}
	// isolated reads a part that runs in a child shell (a subshell, a command
	// or process substitution, a background command, a pipe stage): what it
	// assigns, changes the directory to or defines stays in the child.
	isolated := func(read func()) {
		savedValues, savedFunctions := maps.Clone(values), maps.Clone(functions)
		savedCWD, savedStack := currentCWD, slices.Clone(stack)
		read()
		clear(values)
		maps.Copy(values, savedValues)
		clear(functions)
		maps.Copy(functions, savedFunctions)
		currentCWD, stack = savedCWD, savedStack
	}
	walkList := func(stmts []*syntax.Stmt) {
		for _, stmt := range stmts {
			syntax.Walk(stmt, visit)
		}
	}
	visit = func(node syntax.Node) bool {
		if found {
			return false
		}
		switch node := node.(type) {
		case *syntax.Subshell:
			isolated(func() { walkList(node.Stmts) })
			return false
		case *syntax.CmdSubst:
			isolated(func() { walkList(node.Stmts) })
			return false
		case *syntax.ProcSubst:
			isolated(func() { walkList(node.Stmts) })
			return false
		case *syntax.Stmt:
			if node.Background {
				foreground := *node
				foreground.Background = false
				isolated(func() { syntax.Walk(&foreground, visit) })
				return false
			}
		case *syntax.FuncDecl:
			if uncalled[node] {
				return false
			}
			if node.Name != nil {
				// A definition registers the name only where it runs.
				if inert == 0 {
					functions[node.Name.Value] = node
				}
				if called[node.Name.Value] {
					walkInert(node.Body)
					return false
				}
			}
		case *syntax.BinaryCmd:
			if node.Op == syntax.Pipe || node.Op == syntax.PipeAll {
				if pipes == pipeAllInParent {
					return true
				}
				isolated(func() { syntax.Walk(node.X, visit) })
				if pipes == pipeLastInParent {
					syntax.Walk(node.Y, visit)
				} else {
					isolated(func() { syntax.Walk(node.Y, visit) })
				}
				return false
			}
			truth := 0
			if !loose {
				truth = declaredRedirectTruth(node.X, home)
			}
			if node.Op == syntax.AndStmt && truth < 0 || node.Op == syntax.OrStmt && truth > 0 {
				syntax.Walk(node.X, visit)
				walkInert(node.Y)
				return false
			}
		case *syntax.IfClause:
			if loose || len(node.Cond) == 0 {
				break
			}
			truth := declaredRedirectTruth(node.Cond[len(node.Cond)-1], home)
			if truth == 0 {
				break
			}
			for _, stmt := range node.Cond {
				syntax.Walk(stmt, visit)
			}
			if truth > 0 {
				for _, stmt := range node.Then {
					syntax.Walk(stmt, visit)
				}
			} else {
				walkInert(node.Then...)
			}
			if node.Else != nil {
				if truth > 0 {
					inert++
				}
				syntax.Walk(node.Else, visit)
				if truth > 0 {
					inert--
				}
			}
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok {
			return true
		}
		values["PWD"] = currentCWD
		if inert == 0 {
			// The loose reading keeps the values across text the command runs
			// (eval, source): the exact reading forgets them there.
			if !loose || !registrationRunsText(call) {
				actionUpdateValues(stmt, values, currentCWD, home)
			}
			if !loose {
				registrationUnsetFunctions(call, functions, home)
			}
			registrationRunFunction(call, functions, running, visit, values, &currentCWD, home)
		}
		if len(call.Args) < 2 {
			if inert == 0 {
				actionPosixAdvanceDirectory(call, values, home, &currentCWD, &stack)
			}
			return true
		}
		program, known := staticProgramWord(call.Args[0], home)
		base := programBase(program)
		if known && (base == "rm" || base == "rmdir" || base == "unlink" || base == "mv" ||
			base == "chmod" || base == "chown" || base == "chgrp" || base == "setfacl" || base == "chattr") {
			lastOperand := len(call.Args) - 1
			targetDir := false
			for _, word := range call.Args[1:] {
				value, fixed := StaticWord(word, home)
				if fixed && (value == "-t" || value == "--target-directory" || strings.HasPrefix(value, "--target-directory=")) {
					targetDir = true
				}
			}
			for index, word := range call.Args[1:] {
				receives := base == "mv" && !targetDir && index+1 == lastOperand
				if receives && !actionWordHasBraceText(word) {
					continue // the last operand receives the source
				}
				if actionWordHasBraceText(word) {
					fields := actionMentionBraceFields(word, home)
					if receives && len(fields) > 0 {
						// mv dir{,.bak}: the last field receives the first.
						fields = fields[:len(fields)-1]
					}
					for _, value := range fields {
						if protectedReachPath(OperandPath(value, currentCWD), protected, "") {
							found = true
							return false
						}
					}
					continue
				}
				value, known := actionWordValueWithGlob(word, values, currentCWD, home, true)
				if !known || value == "" || strings.HasPrefix(value, "-") {
					continue
				}
				if strings.ContainsAny(value, "*?[") && actionWordHasUnquotedGlob(word, command) {
					paths := actionBoundedGlob(OperandPath(value, currentCWD), false)
					if len(paths) > 64 {
						continue
					}
					for _, path := range paths {
						if protectedReachPath(path, protected, "") {
							found = true
							return false
						}
					}
					continue
				}
				if !strings.ContainsAny(value, "*?[") && protectedReachPath(OperandPath(value, currentCWD), protected, "") {
					found = true
					return false
				}
			}
		}
		if known && inert == 0 && (base == "ln" || base == "gln") {
			// A link is judged by where it is placed: its operands go through
			// the values the command has bound so far (a name, a folder or a
			// source set by an earlier assignment), and only a destination
			// that resolves to a registered file counts. A link that cannot
			// run (an uncalled function, a branch a fixed condition rules out)
			// is untouched, and a called function is read at its calls.
			words := []string{program}
			fixedWords := []bool{true}
			for _, word := range call.Args[1:] {
				value, fixed := actionWordValue(word, values, currentCWD, home)
				words, fixedWords = append(words, value), append(fixedWords, fixed)
			}
			for _, path := range registrationPlacedPaths(words, fixedWords, currentCWD) {
				if protectedReachPath(path, protected, "") {
					found = true
					return false
				}
			}
		}
		if known && inert == 0 && base == "find" {
			// find writes through its action predicates: the file of -fprint,
			// -fprint0, -fprintf and -fls, and what an -exec child writes. The
			// values the command bound so far resolve a name, so a link or a
			// folder spelled through a variable is read like a literal one.
			for _, path := range registrationFindActionTargets(call.Args[1:], values, currentCWD, home, protected) {
				if protectedReachPath(OperandPath(path, currentCWD), protected, "") {
					found = true
					return false
				}
			}
		}
		if inert == 0 {
			actionPosixAdvanceDirectory(call, values, home, &currentCWD, &stack)
		}
		return true
	}
	syntax.Walk(file, visit)
	return found
}

// registrationShadowable names the builtins and programs the exact reading
// models: a function of the same name replaces them.
var registrationShadowable = map[string]bool{
	"unset": true, "exit": true, "return": true, "command": true, "builtin": true,
	"cd": true, "pushd": true, "popd": true, "eval": true, "source": true, ".": true,
	"declare": true, "typeset": true, "local": true, "export": true, "readonly": true,
	"true": true, "false": true, "test": true, "[": true, ":": true, "let": true,
	"read": true, "set": true, "shopt": true, "echo": true, "printf": true,
	"ln": true, "gln": true, "rm": true, "rmdir": true, "unlink": true, "mv": true,
	"chmod": true, "chown": true, "chgrp": true, "setfacl": true, "chattr": true,
}

// registrationStateWords change the shell state the exact reading follows.
var registrationStateWords = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "unset": true, "read": true,
	"mapfile": true, "readarray": true, "let": true, "set": true, "shopt": true,
	"source": true, ".": true, "eval": true,
}

// registrationCommandWord is the first static word of the call after any
// builtin or command prefix, or "" when it is not static.
func registrationCommandWord(call *syntax.CallExpr) string {
	for _, word := range call.Args {
		value, fixed := StaticWord(word, "")
		if !fixed {
			return ""
		}
		if value != "builtin" && value != "command" {
			return value
		}
	}
	return ""
}

// registrationRunsText reports whether the call runs text it is given.
func registrationRunsText(call *syntax.CallExpr) bool {
	switch registrationCommandWord(call) {
	case "eval", "source", ".":
		return true
	}
	return false
}

// registrationOpaqueFlow reports whether the command is not plain
// straight-line code: it ends a list or a function early (exit, return), runs
// text it builds (eval, source), defines a function with the name of a
// builtin or program the exact reading models, or carries state through a
// pipeline.
func registrationOpaqueFlow(file *syntax.File) bool {
	declared := make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok && decl.Name != nil {
			declared[decl.Name.Value] = true
		}
		return true
	})
	opaque := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.FuncDecl:
			opaque = node.Name != nil && registrationShadowable[node.Name.Value]
		case *syntax.CallExpr:
			switch registrationCommandWord(node) {
			case "exit", "return":
				opaque = true
			default:
				opaque = registrationRunsText(node)
			}
		case *syntax.BinaryCmd:
			opaque = (node.Op == syntax.Pipe || node.Op == syntax.PipeAll) &&
				(registrationCarriesState(node.X, declared) || registrationCarriesState(node.Y, declared))
		}
		return !opaque
	})
	return opaque
}

// registrationCarriesState reports whether a pipe stage can change shell
// state: an assignment, a declaration, a function definition or call, or a
// builtin that sets a value, the directory or the options.
func registrationCarriesState(node syntax.Node, declared map[string]bool) bool {
	carries := false
	syntax.Walk(node, func(inner syntax.Node) bool {
		switch inner := inner.(type) {
		case *syntax.FuncDecl, *syntax.DeclClause, *syntax.ArithmCmd, *syntax.LetClause:
			carries = true
		case *syntax.ParamExp:
			carries = carries || inner.Exp != nil &&
				(inner.Exp.Op == syntax.AssignUnset || inner.Exp.Op == syntax.AssignUnsetOrNull)
		case *syntax.CallExpr:
			name := registrationCommandWord(inner)
			carries = carries || len(inner.Assigns) > 0 || declared[name] || registrationStateWords[name]
		}
		return !carries
	})
	return carries
}

// registrationCalledFunctions names the functions the command runs only by
// plain call words, the ones read at their calls. A name the command also
// spells as an argument or a declaration keeps its body read where it is
// defined, and so does every function when a call word is not static.
func registrationCalledFunctions(file *syntax.File) map[string]bool {
	if _, static := actionStaticCallWords(file); !static {
		return nil
	}
	called, spelled := make(map[string]bool), make(map[string]bool)
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CallExpr:
			unset := registrationUnsetCall(node)
			for index, word := range node.Args {
				if value, fixed := StaticWord(word, ""); fixed && index == 0 {
					called[value] = true
				} else if fixed && !unset {
					spelled[value] = true
				}
			}
		case *syntax.DeclClause:
			for _, assign := range node.Args {
				if assign.Name != nil {
					spelled[assign.Name.Value] = true
				}
				if value, fixed := StaticWord(assign.Value, ""); fixed {
					spelled[value] = true
				}
			}
		}
		return true
	})
	for name := range spelled {
		delete(called, name)
	}
	return called
}

// registrationUnsetCall reports whether the call is unset (possibly behind
// builtin or command), whose arguments are names to forget, not uses of them.
func registrationUnsetCall(call *syntax.CallExpr) bool {
	for _, word := range call.Args {
		value, fixed := StaticWord(word, "")
		if !fixed {
			return false
		}
		if value != "builtin" && value != "command" {
			return value == "unset"
		}
	}
	return false
}

// registrationUnsetFunctions forgets the functions an unset -f call removes.
func registrationUnsetFunctions(call *syntax.CallExpr, functions map[string]*syntax.FuncDecl, home string) {
	if !registrationUnsetCall(call) {
		return
	}
	functionMode, seenUnset := false, false
	for _, word := range call.Args {
		value, fixed := StaticWord(word, home)
		switch {
		case !fixed:
			return
		case !seenUnset:
			seenUnset = value == "unset"
		case strings.HasPrefix(value, "-") && len(value) > 1:
			if strings.Contains(value, "v") {
				functionMode = false
			} else if strings.Contains(value, "f") {
				functionMode = true
			}
		case functionMode:
			delete(functions, value)
		}
	}
}

// registrationRunFunction reads the body of a function the call names, with
// the positional parameters bound to the call words and the values the
// command holds at that point. A function calling itself or nesting past
// four calls is read once.
func registrationRunFunction(call *syntax.CallExpr, functions map[string]*syntax.FuncDecl, running map[*syntax.FuncDecl]bool, visit func(syntax.Node) bool, values actionValues, cwd *string, home string) {
	if len(call.Args) == 0 {
		return
	}
	name, fixed := StaticWord(call.Args[0], home)
	if !fixed {
		return
	}
	decl := functions[name]
	if decl == nil || running[decl] || len(running) >= 4 {
		return
	}
	var bound [9]string
	var known [9]bool
	for index := 1; index <= 9 && index < len(call.Args); index++ {
		bound[index-1], known[index-1] = actionWordValue(call.Args[index], values, *cwd, home)
	}
	previous := make(map[string]string)
	for index := 1; index <= 9; index++ {
		key := strconv.Itoa(index)
		if old, had := values[key]; had {
			previous[key] = old
		}
		delete(values, key)
		if known[index-1] {
			values[key] = bound[index-1]
		}
	}
	running[decl] = true
	syntax.Walk(decl.Body, visit)
	delete(running, decl)
	for index := 1; index <= 9; index++ {
		key := strconv.Itoa(index)
		delete(values, key)
		if old, had := previous[key]; had {
			values[key] = old
		}
	}
}

// registrationItemPaths lists the paths one word of a loop list or an
// operand names: its brace fields, its unquoted glob matches, or its value.
func registrationItemPaths(word *syntax.Word, command, cwd, home string) []string {
	if actionWordHasBraceText(word) {
		return actionMentionBraceFields(word, home)
	}
	value, known := actionWordValueWithGlob(word, actionValues{"HOME": home, "PWD": cwd}, cwd, home, true)
	if !known || value == "" {
		return nil
	}
	if strings.ContainsAny(value, "*?[") && actionWordHasUnquotedGlob(word, command) {
		matches := actionBoundedGlob(OperandPath(value, cwd), false)
		if len(matches) > 64 {
			return nil
		}
		return matches
	}
	return []string{value}
}

// registrationLoopReach reads a for loop over literal, brace or glob items
// whose body removes or moves the loop variable (for f in dir/hook-*; do
// rm -f "$f"; done) with the loop name bound to each item.
func registrationLoopReach(file *syntax.File, command, cwd, home string, protected protectedFiles) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		loop, ok := node.(*syntax.ForClause)
		if found || !ok || loop.Select {
			return !found
		}
		iteration, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iteration.Name == nil || len(iteration.Items) == 0 || len(iteration.Items) > 8 {
			return true
		}
		var items []string
		for _, item := range iteration.Items {
			items = append(items, registrationItemPaths(item, command, cwd, home)...)
		}
		for _, item := range items {
			values := actionValues{"HOME": home, "PWD": cwd, iteration.Name.Value: item}
			for _, body := range loop.Do {
				syntax.Walk(body, func(inner syntax.Node) bool {
					stmt, ok := inner.(*syntax.Stmt)
					if !ok || found {
						return !found
					}
					for _, path := range registrationLoopStatementTargets(stmt, values, cwd, home) {
						if protectedReachPath(OperandPath(path, cwd), protected, "") {
							found = true
							return false
						}
					}
					return true
				})
			}
		}
		return true
	})
	return found
}

// registrationLoopStatementTargets lists the paths one statement of a loop
// body writes, removes, moves, re-modes or replaces, with the loop name bound
// to the current item: its output redirects and the target operands of the
// mutating programs the straight-line reader also knows.
func registrationLoopStatementTargets(stmt *syntax.Stmt, values actionValues, cwd, home string) []string {
	var targets []string
	add := func(word *syntax.Word) {
		path, fixed := actionWordValue(word, values, cwd, home)
		if fixed && path != "" && !strings.HasPrefix(path, "-") {
			targets = append(targets, path)
		}
	}
	for _, redirect := range stmt.Redirs {
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.AppClob, syntax.RdrAll, syntax.AppAll:
			add(redirect.Word)
		}
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return targets
	}
	// The runner grammar the other readers share (env, command, nice,
	// timeout, ...) is stripped first: the program it runs is the one judged.
	args := call.Args
	if words, known := actionLiteralCommandWords(args, home); known {
		args = words
	}
	if len(args) < 2 {
		return targets
	}
	program, fixed := StaticWord(args[0], home)
	if !fixed {
		return targets
	}
	operands := args[1:]
	switch programBase(program) {
	case "rm", "unlink", "shred", "rmdir", "chmod", "chown", "chgrp", "setfacl", "chattr", "truncate", "tee":
		for _, word := range operands {
			add(word)
		}
	case "mv":
		sources := operands
		toDirectory := false
		for _, word := range operands {
			value, fixed := StaticWord(word, home)
			toDirectory = toDirectory || fixed && (value == "-t" || strings.HasPrefix(value, "--target-directory"))
		}
		if !toDirectory && len(sources) > 1 {
			sources = sources[:len(sources)-1]
		}
		for _, word := range sources {
			add(word)
		}
	case "cp", "gcp", "install", "ln":
		words := []string{program}
		known := []bool{true}
		for _, word := range operands {
			value, fixed := actionWordValue(word, values, cwd, home)
			words, known = append(words, value), append(known, fixed)
		}
		targets = append(targets, registrationPlacedPaths(words, known, cwd)...)
	case "sed", "gsed", "perl":
		words := []string{program}
		for _, word := range operands {
			value, fixed := actionWordValue(word, values, cwd, home)
			if !fixed {
				return targets
			}
			words = append(words, value)
		}
		if programBase(program) == "perl" {
			targets = append(targets, perlInPlaceFiles(words)...)
		} else {
			targets = append(targets, sedInPlaceFiles(words)...)
		}
	case "dd":
		for _, word := range operands {
			if value, fixed := actionWordValue(word, values, cwd, home); fixed {
				if target, ok := strings.CutPrefix(value, "of="); ok && target != "" {
					targets = append(targets, target)
				}
			}
		}
	}
	return targets
}

// registrationFindActionTargets lists the paths the output and command
// actions of a find call write (args are the words after the program): the
// file of -fprint, -fprint0, -fprintf and -fls, and the targets of the program
// an -exec, -execdir, -ok or -okdir action runs, read by the loop-statement
// reader with the given values bound. In a child, {} stands for each
// protected file the search stands on (registrationFindReachedFiles), and an
// -execdir or -okdir child runs in that file folder, so a relative name there
// is the file beside it. -delete names no path of its own; the folder reader
// judges it by the search root.
func registrationFindActionTargets(args []*syntax.Word, values actionValues, cwd, home string, protected protectedFiles) []string {
	var targets []string
	var reached []string
	scanned := false
	registrationFindActions(args, home, func(action string, operands []*syntax.Word) bool {
		switch action {
		case "-delete":
		case "-exec", "-execdir", "-ok", "-okdir":
			if len(operands) == 0 {
				return false
			}
			if !scanned {
				reached, scanned = registrationFindReachedFiles(args, values, cwd, home, protected), true
			}
			run := func(words []*syntax.Word, dir string) {
				stmt := &syntax.Stmt{Cmd: &syntax.CallExpr{Args: words}}
				targets = append(targets, registrationLoopStatementTargets(stmt, values, dir, home)...)
			}
			run(operands, cwd)
			for _, file := range reached {
				dir := cwd
				if action == "-execdir" || action == "-okdir" {
					dir = filepath.Dir(file)
				}
				run(registrationFindFileWords(operands, file, home), dir)
			}
		default:
			if len(operands) > 0 {
				if path, fixed := actionWordValue(operands[0], values, cwd, home); fixed && path != "" {
					targets = append(targets, path)
				}
			}
		}
		return false
	})
	return targets
}

// registrationFindFileWords returns the words of an -exec child with the file
// the search stands on put in place of every {}.
func registrationFindFileWords(words []*syntax.Word, file, home string) []*syntax.Word {
	out := make([]*syntax.Word, len(words))
	for i, word := range words {
		out[i] = word
		if text, fixed := StaticWord(word, home); fixed && strings.Contains(text, "{}") {
			out[i] = &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: strings.ReplaceAll(text, "{}", file)}}}
		}
	}
	return out
}

// registrationFindReachedFiles lists the protected files a find call stands
// on: each search root that names one directly (the file, or a link to it),
// and the protected files below a root folder that a -name, -iname, -path,
// -ipath, -wholename or -iwholename test matches. A root or test value that is
// neither spelled out nor bound is no root and no test, and a negated test
// selects nothing.
func registrationFindReachedFiles(args []*syntax.Word, values actionValues, cwd, home string, protected protectedFiles) []string {
	type nameTest struct {
		pattern     string
		whole, fold bool
	}
	var roots []string
	var tests []nameTest
	rootsOpen, negated := true, false
	for index := 0; index < len(args); index++ {
		text, fixed := StaticWord(args[index], home)
		if rootsOpen && (text == "-H" || text == "-L" || text == "-P") {
			continue
		}
		if rootsOpen && (!fixed || !strings.HasPrefix(text, "-") && text != "!" && text != "(") {
			if value, known := actionWordValue(args[index], values, cwd, home); known && value != "" {
				roots = append(roots, value)
			}
			continue
		}
		rootsOpen = false
		if !fixed {
			continue
		}
		switch text {
		case "!", "-not":
			negated = !negated
			continue
		case "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename":
			if index+1 < len(args) {
				if pattern, known := StaticWord(args[index+1], home); known && !negated {
					tests = append(tests, nameTest{pattern, strings.Contains(text, "path") || strings.Contains(text, "wholename"), strings.HasPrefix(text, "-i")})
				}
				index++
			}
		case "-exec", "-execdir", "-ok", "-okdir":
			for index+1 < len(args) {
				index++
				if end, _ := StaticWord(args[index], home); end == ";" || end == "+" {
					break
				}
			}
		default:
			if registrationFindValueOptions[text] || strings.HasPrefix(text, "-newer") && len(text) == len("-newerXY") {
				index++
			}
		}
		negated = false
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	var reached []string
	for _, root := range roots {
		path := OperandPath(root, cwd)
		if info, err := pathStat(path); err == nil && info.IsDir() {
			for _, target := range protected {
				if !strings.HasPrefix(target.path, path+string(filepath.Separator)) {
					continue
				}
				for _, test := range tests {
					text := filepath.Base(target.path)
					if test.whole {
						text = target.path
					}
					if registrationGlobMatch(test.pattern, text, test.fold) {
						reached = append(reached, target.path)
						break
					}
				}
			}
		} else if protectedReachPath(path, protected, "") {
			reached = append(reached, path)
		}
	}
	return reached
}

// registrationGlobMatch matches text against a find glob: * and ? also match
// a path separator, [..] is a class ([!..] negates it) and a backslash quotes
// the next character.
func registrationGlobMatch(pattern, text string, fold bool) bool {
	if fold {
		pattern, text = strings.ToLower(pattern), strings.ToLower(text)
	}
	for pattern != "" {
		_, size := utf8.DecodeRuneInString(text)
		switch pattern[:1] {
		case "*":
			pattern = strings.TrimLeft(pattern, "*")
			if pattern == "" {
				return true
			}
			for offset := range text {
				if registrationGlobMatch(pattern, text[offset:], false) {
					return true
				}
			}
			return false
		case "?":
			if text == "" {
				return false
			}
			pattern, text = pattern[1:], text[size:]
		case "[":
			end := strings.Index(pattern[1:], "]") + 1
			if end < 2 || text == "" {
				return false
			}
			class := pattern[:end+1]
			if strings.HasPrefix(class, "[!") {
				class = "[^" + class[2:]
			}
			if matched, err := filepath.Match(class, text[:size]); err != nil || !matched {
				return false
			}
			pattern, text = pattern[end+1:], text[size:]
		case "\\":
			if len(pattern) < 2 {
				return false
			}
			pattern = pattern[1:]
			fallthrough
		default:
			if text == "" || pattern[:1] != text[:1] {
				return false
			}
			pattern, text = pattern[1:], text[1:]
		}
	}
	return text == ""
}

// registrationFindRsyncReach reads the two tools that empty a folder without
// naming what they remove: find with -delete or an rm/mv -exec (narrowed by
// -name or -iname when given), and rsync --delete into a folder.
func registrationFindRsyncReach(file *syntax.File, cwd, home string, protected protectedFiles) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if found || !ok || len(call.Args) < 2 {
			return !found
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			value, fixed := StaticWord(arg, home)
			if !fixed {
				return true
			}
			words[i] = value
		}
		switch programBase(words[0]) {
		case "find":
			found = registrationFindReach(words, cwd, protected)
		case "rsync":
			found = registrationRsyncReach(words, cwd, protected)
		case "install", "ginstall":
			found = registrationInstallReach(words, cwd, protected)
		case "dd":
			for _, word := range words[1:] {
				target, ok := strings.CutPrefix(word, "of=")
				if rest, tilde := strings.CutPrefix(target, "~/"); tilde {
					target = filepath.Join(home, rest)
				}
				if ok && target != "" && protectedReachPath(OperandPath(target, cwd), protected, "") {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// findChildRemovesTree reports whether the options of an rm-like find child
// (the words after its program) ask it to remove folders with their content.
func findChildRemovesTree(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--recursive" || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") &&
			strings.ContainsAny(arg, "rR") {
			return true
		}
	}
	return false
}

func registrationFindReach(words []string, cwd string, protected protectedFiles) bool {
	var roots, names []string
	deletes, insensitive := false, false
	// A walk cut at -maxdepth N reaches nothing deeper than N below a root.
	// Several limits or one that is not a number leave the walk unbounded.
	maxDepth, limits := 0, 0
	// A child that removes a folder with what it holds, or moves it, takes
	// the whole tree under a root whatever the depth limit.
	tree := false
	for i := 1; i < len(words); i++ {
		switch word := words[i]; word {
		case "-delete":
			deletes = true
		case "-maxdepth":
			if i+1 < len(words) {
				depth, err := strconv.Atoi(words[i+1])
				if err != nil || depth < 0 {
					depth = -1
				}
				maxDepth, limits = depth, limits+1
				i++
			}
		case "-exec", "-execdir", "-ok", "-okdir":
			// A child removes what the walk found only when it is handed the
			// found name ({}); one that names its own operands is judged on
			// those, as registrationFindActionTargets reads them.
			if i+1 < len(words) && slices.ContainsFunc(words[i+1:], func(arg string) bool { return strings.Contains(arg, "{}") }) {
				switch programBase(words[i+1]) {
				case "rm", "unlink", "shred":
					deletes = true
					tree = tree || findChildRemovesTree(words[i+2:])
				case "mv":
					deletes, tree = true, true
				}
			}
		case "-name", "-iname":
			if i+1 < len(words) {
				insensitive = insensitive || word == "-iname"
				names = append(names, words[i+1])
				i++
			}
		default:
			if len(roots) == i-1 && !strings.HasPrefix(word, "-") && word != "!" && word != "(" {
				roots = append(roots, word)
			}
		}
	}
	if !deletes {
		return false
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	for _, root := range roots {
		root = OperandPath(root, cwd)
		for _, target := range protected {
			if target.path != root && !strings.HasPrefix(target.path, root+string(filepath.Separator)) {
				continue
			}
			if !tree && limits == 1 && maxDepth >= 0 && target.path != root &&
				strings.Count(strings.TrimPrefix(target.path, root+string(filepath.Separator)), string(filepath.Separator)) >= maxDepth {
				continue
			}
			if len(names) == 0 {
				return true
			}
			base := filepath.Base(target.path)
			for _, pattern := range names {
				if insensitive {
					pattern, base = strings.ToLower(pattern), strings.ToLower(base)
				}
				if matched, _ := filepath.Match(pattern, base); matched {
					return true
				}
			}
		}
	}
	return false
}

// registrationInstallReach reads install SOURCE DEST, install SOURCE... DIR
// and install -t DIR SOURCE...: the destination file or the file the
// source name takes in the destination folder.
func registrationInstallReach(words []string, cwd string, protected protectedFiles) bool {
	for _, path := range registrationPlacedPaths(words, nil, cwd) {
		if protectedReachPath(path, protected, "") {
			return true
		}
	}
	return false
}

// registrationPlacedPaths lists the paths a cp, install or ln call writes
// (words[0] is the program): the last operand when it is a plain file name,
// and, when it is a folder (or is written with a trailing separator, or
// -t names it), the file each source name takes in that folder. A folder
// that receives a source under an unrelated name is not itself written. The
// straight-line install reader and the loop-body reader share this one
// destination-role rule. known marks the words whose value is fixed (nil:
// all); an unknown destination lists nothing and an unknown source places
// nothing.
func registrationPlacedPaths(words []string, known []bool, cwd string) []string {
	var operands []string
	directory := ""
	noTarget, optionsEnded, parents := false, false, false
	program := programBase(words[0])
	for i := 1; i < len(words); i++ {
		if known != nil && !known[i] {
			operands = append(operands, "")
			continue
		}
		word := words[i]
		if !optionsEnded {
			word = registrationLongWord(program, word)
		}
		switch {
		case optionsEnded:
			operands = append(operands, word)
		case word == "--":
			optionsEnded = true
		case word == "--parents" && (program == "cp" || program == "gcp"):
			parents = true
		case word == "--target-directory":
			if i+1 < len(words) {
				if known != nil && !known[i+1] {
					return nil
				}
				directory = words[i+1]
				i++
			}
		case strings.HasPrefix(word, "--target-directory="):
			directory = strings.TrimPrefix(word, "--target-directory=")
		case word == "--no-target-directory":
			noTarget = true
		case word == "--mode" || word == "--owner" || word == "--group" || word == "--suffix":
			i++
		case strings.HasPrefix(word, "--"):
		case strings.HasPrefix(word, "-") && word != "-":
			// A short cluster (-t DIR, -rt DIR, -aTS.bak): -T is a flag, and the
			// first letter that takes a value takes the rest of the word or
			// the next word.
			for position := 1; position < len(word); position++ {
				letter := word[position : position+1]
				if letter == "T" {
					noTarget = true
					continue
				}
				if !strings.Contains(registrationValueLetters(program), letter) {
					continue
				}
				value := word[position+1:]
				if value == "" && i+1 < len(words) {
					i++
					if known != nil && !known[i] {
						if letter == "t" {
							return nil
						}
						break
					}
					value = words[i]
				}
				if letter == "t" && value != "" {
					directory = value
				}
				break
			}
		default:
			operands = append(operands, word)
		}
	}
	var placed []string
	single := len(operands) == 1
	if directory == "" && len(operands) >= 2 {
		last := operands[len(operands)-1]
		operands = operands[:len(operands)-1]
		if last == "" {
			return nil
		}
		if parents {
			directory = last
		} else if !noTarget {
			if info, err := pathStat(OperandPath(last, cwd)); strings.HasSuffix(last, "/") || (err == nil && info.IsDir()) {
				directory = last
			}
		}
		if directory == "" {
			placed = append(placed, OperandPath(last, cwd))
		}
	}
	if directory == "" && single && operands[0] != "" && (program == "ln" || program == "gln") {
		// ln SOURCE links it under its own name in the working folder.
		placed = append(placed, OperandPath(filepath.Base(operands[0]), cwd))
	}
	if directory != "" {
		for _, source := range operands {
			if source == "" {
				continue
			}
			name := filepath.Base(source)
			if parents {
				name = source
			}
			placed = append(placed, filepath.Join(OperandPath(directory, cwd), name))
		}
	}
	return placed
}

// registrationValueLetters lists the short options of a cp, install or ln
// call that take a value (the target folder -t, the backup suffix -S, and
// install's mode, owner and group).
func registrationValueLetters(program string) string {
	if program == "install" || program == "ginstall" {
		return "tSmog"
	}
	return "tS"
}

// registrationLongWord spells an abbreviated long option of a cp, install or
// ln call in full (GNU accepts any unambiguous prefix: --target-d is
// --target-directory). A word that is not an option of the program, or is
// ambiguous, is returned as it is.
func registrationLongWord(program, word string) string {
	if !strings.HasPrefix(word, "--") || word == "--" {
		return word
	}
	var options []string
	switch program {
	case "cp", "gcp":
		options = cpLongOptions
	case "ln", "gln":
		options = lnLongOptions
	case "install", "ginstall":
		options = installLongOptions
	default:
		return word
	}
	name, value, joined := strings.Cut(word[2:], "=")
	option := ExpandLongOption(name, options)
	if option == "" {
		return word
	}
	if joined {
		return "--" + option + "=" + value
	}
	return "--" + option
}

func registrationRsyncReach(words []string, cwd string, protected protectedFiles) bool {
	deletes := false
	destination := ""
	for _, word := range words[1:] {
		if strings.HasPrefix(word, "--delete") {
			deletes = true
		}
		if !strings.HasPrefix(word, "-") {
			destination = word
		}
	}
	if !deletes || destination == "" || strings.Contains(destination, ":") {
		return false
	}
	destination = OperandPath(destination, cwd)
	for _, target := range protected {
		if target.path == destination || strings.HasPrefix(target.path, destination+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// registrationCopyReach resolves a copy into a directory to the actual file
// name supplied by its source. A directory receiving some other name is not
// itself a registration write.
func registrationCopyReach(file *syntax.File, cwd, home string, protected protectedFiles) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok || found {
			return !found
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}
		argv := make([]string, len(call.Args))
		for i, word := range call.Args {
			value, fixed := StaticWord(word, home)
			if !fixed {
				return true
			}
			argv[i] = value
		}
		if !IsCopyProgram(argv) {
			return true
		}
		dest := CopyDestination(argv, cwd)
		if dest == "" {
			return true
		}
		source := argv[len(argv)-2]
		if CopyDestinationOperand(argv) != argv[len(argv)-1] {
			source = argv[len(argv)-1]
		}
		if source == "" || strings.HasPrefix(source, "-") {
			return true
		}
		if info, err := pathStat(dest); err != nil || !info.IsDir() {
			return true
		}
		name := filepath.Base(source)
		if args, _ := copyProgramArgs(argv); len(args) > 0 {
			if parsed := cpOperands(args, makeStatic(len(args))); parsed.ok && parsed.parents {
				name = source
			}
		}
		if protectedReachPath(filepath.Join(dest, name), protected, "") {
			found = true
			return false
		}
		return true
	})
	return found
}

// registrationArchivePossibleReachAs is RegistrationArchivePossibleReach in
// one reading of the command.
func registrationArchivePossibleReachAs(command, cwd, home string, names []string) string {
	if !strings.Contains(command, "tar") && !strings.Contains(command, "unzip") {
		return ""
	}
	file, ok := parseShell(command)
	if !ok {
		return ""
	}
	found := ""
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 || found != "" {
			return found == ""
		}
		program, fixed := StaticWord(call.Args[0], home)
		if !fixed {
			return true
		}
		args := make([]string, 0, len(call.Args)-1)
		for _, word := range call.Args[1:] {
			value, fixed := StaticWord(word, home)
			if !fixed {
				return true
			}
			args = append(args, value)
		}
		for _, dest := range ArchiveExtractionDestinations(program, args) {
			folder := OperandPath(dest, cwd)
			// A generic ancestor such as /tmp is not a registered hook
			// folder merely because a test home happens to live below it.
			if !slices.Contains(names, folder) {
				continue
			}
			for _, name := range names {
				if name != folder && strings.HasPrefix(name, folder+string(filepath.Separator)) {
					found = folder
					return false
				}
			}
		}
		return true
	})
	return found
}

// RegistrationWriteCandidate is the shared reader's cheap hot-path gate.
func RegistrationWriteCandidate(command string) bool {
	if strings.ContainsAny(command, ">") {
		return true
	}
	for _, word := range []string{"rm", "mv", "cp", "ln", "sed", "perl", "patch", "chmod", "chown", "chgrp", "setfacl", "chattr", "find", "truncate", "touch", "install", "rsync", "tar", "unzip", "dd", "tee", "sponge", "python", "node", "ruby", "bash", "zsh", "dash", "ksh", "sh"} {
		if strings.Contains(command, word) {
			return true
		}
	}
	return false
}

// registrationReadSmall reads a patch source of at most 1 MiB through the
// network-share-bounded opener.
func registrationReadSmall(name string) ([]byte, bool) {
	f, err := pathOpen(name)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	return body, err == nil && len(body) <= 1<<20
}

// registrationPatchReach reads a literal patch source named by the same
// command. It uses the caller's registration set for the target comparison.
func registrationPatchReach(file *syntax.File, cwd, home string, protected protectedFiles) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok || found {
			return !found
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		program, fixed := StaticWord(call.Args[0], home)
		if !fixed || programBase(program) != "patch" {
			return true
		}
		var operands []string
		patchSource := ""
		for i := 1; i < len(call.Args); i++ {
			word, fixed := StaticWord(call.Args[i], home)
			if !fixed {
				return true
			}
			if word == "--dry-run" {
				return true
			}
			if word == "-i" || word == "--input" {
				i++
				if i < len(call.Args) {
					patchSource, _ = StaticWord(call.Args[i], home)
				}
				continue
			}
			if value, ok := strings.CutPrefix(word, "--input="); ok {
				patchSource = value
				continue
			}
			if strings.HasPrefix(word, "-") {
				continue
			}
			operands = append(operands, word)
		}
		if len(operands) > 0 && protectedReachPath(OperandPath(operands[0], cwd), protected, "") {
			found = true
			return false
		}
		if patchSource == "" && len(operands) > 1 {
			patchSource = operands[len(operands)-1]
		}
		if patchSource == "" {
			for _, redirect := range stmt.Redirs {
				if redirect.Op == syntax.RdrIn && redirect.Word != nil {
					patchSource, _ = StaticWord(redirect.Word, home)
					break
				}
			}
		}
		if patchSource == "" {
			return true
		}
		body, ok := registrationReadSmall(OperandPath(patchSource, cwd))
		if !ok {
			return true
		}
		for _, line := range strings.Split(string(body), "\n") {
			if path, ok := strings.CutPrefix(line, "+++ b/"); ok {
				path, _, _ = strings.Cut(path, "\t")
				if protectedReachPath(OperandPath(path, cwd), protected, "") {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}
