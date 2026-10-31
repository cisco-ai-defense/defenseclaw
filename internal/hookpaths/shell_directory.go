// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"bytes"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// DirectoryFactPrefix carries the physical directory observed by the hook
// for a logical shell directory. A question mark means it was not readable.
const DirectoryFactPrefix = "\x00directory:"

type shellDirectoryState struct {
	logical, physical string
	known             bool
	changed           bool
	stack             []string // top of the directory stack is last
}

func (s shellDirectoryState) clone() shellDirectoryState {
	s.stack = slices.Clone(s.stack)
	return s
}

// merge joins the state after a branch that may or may not have run. A
// directory or stack the branch changed is no longer known.
func (s *shellDirectoryState) merge(branch shellDirectoryState) {
	if branch.logical != s.logical || branch.known != s.known {
		s.known, s.changed = false, true
	}
	if !slices.Equal(branch.stack, s.stack) {
		s.stack, s.changed = nil, true
	}
}

// ShellDirectoryWriteOperands follows shell directory changes through statement
// bodies. A branch or subshell gets its own directory state. unknown reports a
// write that may name authorized_keys after an unresolved directory change.
func ShellDirectoryWriteOperands(command, cwd, home string, directoryFacts map[string]string, record, strict bool) (operands []RedirectOccurrence, unknown bool) {
	file, parsed := parseShell(command)
	if !parsed || !filepath.IsAbs(cwd) {
		return nil, false
	}
	physical := func(logical string) (string, bool) {
		key := DirectoryFactPrefix + logical
		if !record && directoryFacts != nil {
			if value, present := directoryFacts[key]; present {
				return value, filepath.IsAbs(value)
			}
			if strict && directoryFactRequired(logical, home) {
				return "", false
			}
		}
		if !record && strict && directoryFactRequired(logical, home) {
			return "", false
		}
		value, ok := ResolveWriteTarget(logical)
		if record && directoryFacts != nil {
			if ok {
				directoryFacts[key] = value
			} else {
				directoryFacts[key] = "?"
			}
		}
		return value, ok
	}
	// directory is expanded: StaticWord already read an unquoted ~ or ~/
	// from home, so a ~ left here was quoted and names a directory called ~
	// (RV-c7-1); env --chdir=~/x does not expand it either.
	setDirectory := func(s *shellDirectoryState, directory string, physicalMode bool) {
		absolute := filepath.IsAbs(directory)
		if absolute {
			s.logical = filepath.Clean(directory)
		} else {
			s.logical = filepath.Join(s.logical, directory)
		}
		wasKnown := s.known
		s.physical, s.known = physical(s.logical)
		s.known = s.known && (absolute || wasKnown)
		if physicalMode && s.known {
			s.logical = s.physical
		}
		s.changed = true
	}
	state := shellDirectoryState{logical: filepath.Clean(cwd)}
	state.physical, state.known = physical(state.logical)
	safety := SafeShellRedirectOccurrencesWithFacts(command, cwd, home, directoryFacts)
	redirectIndex := 0
	functions := map[string]*syntax.Stmt{}
	// Function calls are expanded at each call site with the caller's
	// directory. The depth and the statements read inside bodies are bounded,
	// so nested fan-out stays linear; past either bound a body that may write
	// or change directory is unknown.
	functionDepth, functionStatements := 0, 0
	var walkList func([]*syntax.Stmt, *shellDirectoryState)
	var walk func(*syntax.Stmt, *shellDirectoryState)
	write := func(stmt *syntax.Stmt, s *shellDirectoryState) {
		// The command substitution of a word runs in another shell. Only the
		// statement's own redirects belong to this directory state.
		var rendered bytes.Buffer
		if syntax.NewPrinter().Print(&rendered, stmt) != nil {
			unknown = true
			return
		}
		statement := rendered.String()
		redirects := make([]string, 0, len(stmt.Redirs))
		// The redirect safety list is keyed in the starting directory.
		keys := make([]string, 0, len(stmt.Redirs))
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			default:
				continue
			}
			name, ok := StaticWord(redirect.Word, home)
			if !ok {
				if s.changed && (!s.known || sameShellDirectory(s.physical, filepath.Join(home, ".ssh"))) {
					unknown = true
				}
				continue
			}
			if s.changed && !s.known && !filepath.IsAbs(name) &&
				!strings.HasPrefix(name, "~/") && shellAuthorizedKeysBase(name) {
				unknown = true
			}
			redirects = append(redirects, OperandPath(name, s.logical))
			keys = append(keys, OperandPath(name, cwd))
		}
		if !s.changed {
			redirectIndex += len(redirects)
			return
		}
		literals, literalCopies := LiteralWriteOperandsWithCopies(statement, s.logical, home)
		ownCopies := make(map[string]int, len(literalCopies))
		for _, literal := range literalCopies {
			ownCopies[literal]++
		}
		inner := actionfacts.Input{Tool: "Bash", Command: statement, CWD: s.logical, ActiveHome: home}
		facts := actionfacts.Analyze(inner)
		writes := make([]RedirectOccurrence, 0, len(redirects)+len(literals))
		for i, redirect := range redirects {
			occurrence := RedirectOccurrence{Path: redirect}
			// A function body or eval text can list a redirect the plain
			// walk does not; only the same operand inherits its safety.
			if redirectIndex < len(safety) && safety[redirectIndex].Path == keys[i] {
				occurrence.Safe = safety[redirectIndex].Safe
			}
			redirectIndex++
			writes = append(writes, occurrence)
		}
		for _, literal := range literals {
			own := ownCopies[literal] > 0
			if own {
				ownCopies[literal]--
			}
			writes = append(writes, RedirectOccurrence{Path: literal, OwnCopy: own})
		}
		for _, candidate := range facts.Paths {
			if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
				continue
			}
			target := candidate.Resolved
			if target == "" {
				target = candidate.Normalized
			}
			if raw, ok := RawDotDotOperand(candidate.Value, s.logical); ok {
				target = raw
			}
			if !filepath.IsAbs(target) && candidate.Value != "" &&
				!strings.HasPrefix(candidate.Value, "/") &&
				!strings.ContainsAny(candidate.Value, "*?[]$`~\x00\r\n") {
				target = OperandPath(candidate.Value, s.logical)
			}
			if target != "" && filepath.IsAbs(target) {
				if slices.Contains(redirects, target) && pathFactIsRedirect(candidate, facts.Commands) {
					continue
				}
				// A copy call writing its own destination, as the gateway reads
				// the path facts of the whole command (GAP-2579).
				own := false
				for _, command := range facts.Commands {
					if command.ID == candidate.CommandID {
						own = IsCopyProgram(command.Argv) && target == CopyDestination(command.Argv, s.logical)
						break
					}
				}
				writes = append(writes, RedirectOccurrence{Path: target, OwnCopy: own})
			}
		}
		if s.known {
			for i, item := range writes {
				if strings.HasPrefix(item.Path, s.logical+string(filepath.Separator)) {
					writes[i].Path = OperandPath(strings.TrimPrefix(item.Path, s.logical+string(filepath.Separator)), s.physical)
				}
			}
		} else {
			for _, item := range writes {
				if strings.HasPrefix(item.Path, s.logical+string(filepath.Separator)) &&
					shellAuthorizedKeysBase(item.Path) {
					unknown = true
				}
			}
		}
		operands = append(operands, writes...)
	}
	change := func(call *syntax.CallExpr, s *shellDirectoryState) bool {
		program, arg, ok := shellCommandWord(call, home)
		if !ok {
			// A program word that is not static may be cd.
			if len(call.Args) > 0 {
				s.known, s.changed, s.stack = false, true, nil
			}
			return false
		}
		if program == "eval" || program == "source" || program == "." {
			s.changed = true
			script, static := "", program == "eval"
			for _, word := range call.Args[arg:] {
				value, ok := StaticWord(word, home)
				static = static && ok
				script += " " + value
			}
			if file, parsed := parseShell(script); static && parsed {
				walkList(file.Stmts, s)
			} else {
				s.known, s.stack = false, nil
			}
			return false
		}
		if program != "cd" && program != "pushd" && program != "popd" {
			return false
		}
		s.changed = true
		unmodeled := func() { s.known = false; s.stack = nil }
		physicalMode, noChange, endOptions := false, false, false
		for arg < len(call.Args) {
			option, static := StaticWord(call.Args[arg], home)
			if !static {
				break
			}
			if option == "--" {
				arg++
				endOptions = true
				break
			}
			if program == "pushd" && option == "-n" || program == "popd" && option == "-n" {
				noChange = true
				arg++
				continue
			}
			if program == "cd" && len(option) > 1 && option[0] == '-' && strings.Trim(option[1:], "PLe@") == "" {
				for _, flag := range option[1:] {
					if flag == 'P' {
						physicalMode = true
					} else if flag == 'L' {
						physicalMode = false
					}
				}
				arg++
				continue
			}
			break
		}
		if program == "popd" {
			if arg < len(call.Args) {
				option, static := StaticWord(call.Args[arg], home)
				index, valid := shellStackIndex(option, len(s.stack))
				if !static || !valid || arg+1 != len(call.Args) {
					unmodeled()
					return true
				}
				if index == 0 {
					index = 1
				}
				at := len(s.stack) - index
				if at < 0 {
					unmodeled()
					return true
				}
				if !noChange && index == 1 {
					setDirectory(s, s.stack[at], false)
				}
				s.stack = append(s.stack[:at], s.stack[at+1:]...)
				return true
			}
			if len(s.stack) == 0 {
				unmodeled()
				return true
			}
			next := s.stack[len(s.stack)-1]
			s.stack = s.stack[:len(s.stack)-1]
			if !noChange {
				setDirectory(s, next, false)
			}
			return true
		}
		if program == "pushd" && arg == len(call.Args) {
			if len(s.stack) == 0 {
				unmodeled()
				return true
			}
			top := len(s.stack) - 1
			next := s.stack[top]
			s.stack[top] = s.logical
			if !noChange {
				setDirectory(s, next, false)
			}
			return true
		}
		if program == "cd" && arg == len(call.Args) {
			if home == "" {
				unmodeled()
			} else {
				setDirectory(s, home, physicalMode)
			}
			return true
		}
		if arg+1 != len(call.Args) {
			unmodeled()
			return true
		}
		directory, static := StaticWord(call.Args[arg], home)
		if !static {
			unmodeled()
			return true
		}
		if !endOptions && len(directory) > 1 && directory[0] == '-' {
			_, stackIndex := shellStackIndex(directory, len(s.stack))
			if program != "pushd" || !stackIndex {
				unmodeled()
				return true
			}
		}
		if program == "pushd" {
			if index, valid := shellStackIndex(directory, len(s.stack)); valid {
				if index == 0 {
					return true
				}
				at := len(s.stack) - index
				if at < 0 {
					unmodeled()
					return true
				}
				next := s.stack[at]
				if !noChange {
					s.stack = append(s.stack[:at], s.stack[at+1:]...)
					s.stack = append(s.stack, s.logical)
					setDirectory(s, next, false)
				}
				return true
			}
			previous, previousPhysical, previousKnown := s.logical, s.physical, s.known
			setDirectory(s, directory, false)
			if noChange {
				stackEntry := s.logical
				s.logical = previous
				s.physical, s.known = previousPhysical, previousKnown
				s.stack = append(s.stack, stackEntry)
			} else {
				s.stack = append(s.stack, previous)
			}
			return true
		}
		if directory == "-" {
			unmodeled()
			return true
		}
		setDirectory(s, directory, physicalMode)
		return true
	}
	walkList = func(stmts []*syntax.Stmt, s *shellDirectoryState) {
		for _, stmt := range stmts {
			walk(stmt, s)
		}
	}
	walk = func(stmt *syntax.Stmt, s *shellDirectoryState) {
		if stmt == nil {
			return
		}
		if functionDepth > 0 {
			functionStatements++
		}
		if stmt.Background {
			child := s.clone()
			copyStmt := *stmt
			copyStmt.Background = false
			walk(&copyStmt, &child)
			return
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
				left, right := s.clone(), s.clone()
				walk(cmd.X, &left)
				walk(cmd.Y, &right)
			} else {
				walk(cmd.X, s)
				walk(cmd.Y, s)
			}
		case *syntax.Subshell:
			child := s.clone()
			walkList(cmd.Stmts, &child)
		case *syntax.Block:
			walkList(cmd.Stmts, s)
		case *syntax.IfClause:
			walkList(cmd.Cond, s)
			thenState := s.clone()
			walkList(cmd.Then, &thenState)
			if cmd.Else != nil {
				elseState := s.clone()
				walk(&syntax.Stmt{Cmd: cmd.Else}, &elseState)
				s.merge(elseState)
			}
			s.merge(thenState)
		case *syntax.WhileClause:
			walkList(cmd.Cond, s)
			body := s.clone()
			walkList(cmd.Do, &body)
			s.merge(body)
		case *syntax.ForClause:
			body := s.clone()
			walkList(cmd.Do, &body)
			s.merge(body)
		case *syntax.CaseClause:
			for _, item := range cmd.Items {
				branch := s.clone()
				walkList(item.Stmts, &branch)
				s.merge(branch)
			}
		case *syntax.TimeClause:
			walk(cmd.Stmt, s)
		case *syntax.CoprocClause:
			child := s.clone()
			walk(cmd.Stmt, &child)
		case *syntax.FuncDecl:
			if cmd.Name != nil && cmd.Body != nil {
				functions[cmd.Name.Value] = cmd.Body
			}
		case *syntax.CallExpr:
			if name, _, static := shellCommandWord(cmd, home); static && functions[name] != nil {
				if functionDepth < 8 && functionStatements < maxFunctionStatements {
					functionDepth++
					walk(functions[name], s)
					functionDepth--
				} else if !recursiveSelfCallsOnly(functions[name], name, home) {
					s.known, s.changed = false, true
					unknown = true
				}
				write(stmt, s)
				break
			}
			if change(cmd, s) {
				break
			}
			if directory, inner, tail, recognized := shellEnvChdir(cmd, home); recognized {
				child := s.clone()
				if directory == "" {
					child.known = false
					child.changed = true
				} else {
					setDirectory(&child, directory, false)
				}
				if inner != "" {
					if file, ok := parseShell(inner); ok {
						walkList(file.Stmts, &child)
					}
				} else if tail != nil {
					walk(&syntax.Stmt{Cmd: tail}, &child)
				}
			} else if body := literalShellCallBody(cmd, home); body != "" {
				// A literal sh -c body runs in a subshell: its directory
				// changes end with it and its writes are read in the
				// directories it stands in (GAP-2602).
				if file, ok := parseShell(body); ok {
					child := s.clone()
					walkList(file.Stmts, &child)
				}
			}
			write(stmt, s)
		default:
			// An unmodeled command, such as a function definition, may change
			// the directory later. Its redirects are still inspected using the
			// state at this point.
			if cmd != nil {
				syntax.Walk(cmd, func(node syntax.Node) bool {
					if call, ok := node.(*syntax.CallExpr); ok {
						if program, _, static := shellCommandWord(call, home); !static ||
							program == "cd" || program == "pushd" || program == "popd" ||
							program == "eval" || program == "source" || program == "." {
							s.known, s.changed, s.stack = false, true, nil
						}
					}
					return true
				})
			}
			write(stmt, s)
		}
	}
	walkList(file.Stmts, &state)
	return operands, unknown
}

// maxFunctionStatements bounds the statements read inside function bodies
// for one command.
const maxFunctionStatements = 4096

// A body made only of calls to itself cannot produce a file write or change
// the working directory when the bounded walk reaches its limit.
func recursiveSelfCallsOnly(body *syntax.Stmt, name, home string) bool {
	if body == nil {
		return false
	}
	safe := true
	syntax.Walk(body, func(node syntax.Node) bool {
		if !safe {
			return false
		}
		switch item := node.(type) {
		case *syntax.CallExpr:
			program, _, static := shellCommandWord(item, home)
			safe = static && program == name && len(item.Assigns) == 0
		case *syntax.Redirect, *syntax.CmdSubst, *syntax.ProcSubst, *syntax.FuncDecl:
			safe = false
		}
		return safe
	})
	return safe
}

// shellCommandWord returns the program a call runs in this shell after builtin
// and command prefixes, and the index of its first argument. ok is false when
// the program word is not static. command -v and -V only describe a program.
func shellCommandWord(call *syntax.CallExpr, home string) (program string, arg int, ok bool) {
	for arg < len(call.Args) {
		program, ok = StaticWord(call.Args[arg], home)
		if !ok {
			return "", arg, false
		}
		arg++
		if program == "builtin" {
			continue
		}
		if program != "command" {
			return program, arg, true
		}
		for arg < len(call.Args) {
			option, static := StaticWord(call.Args[arg], home)
			if !static || len(option) < 2 || option[0] != '-' {
				break
			}
			if strings.ContainsAny(option, "vV") {
				return "command", arg, true
			}
			arg++
		}
	}
	return program, arg, ok
}

// literalShellCallBody is the literal command body of a static sh -c call
// (bash -lc BODY too), or "" for any other call.
func literalShellCallBody(call *syntax.CallExpr, home string) string {
	words := make([]string, len(call.Args))
	static := make([]bool, len(call.Args))
	for i, arg := range call.Args {
		words[i], static[i] = StaticWord(arg, home)
	}
	if len(words) == 0 || !static[0] {
		return ""
	}
	return literalShellBody(programBase(words[0]), words, static)
}

func shellAuthorizedKeysBase(name string) bool {
	base := filepath.Base(name)
	if runtime.GOOS == "windows" {
		base = strings.ToLower(base)
	}
	return base == "authorized_keys" || base == "authorized_keys2"
}

func sameShellDirectory(a, b string) bool { return a != "" && filepath.Clean(a) == filepath.Clean(b) }

func shellStackIndex(option string, size int) (int, bool) {
	if len(option) < 2 || option[0] != '+' && option[0] != '-' {
		return 0, false
	}
	n, err := strconv.Atoi(option[1:])
	if err != nil || n < 0 || n > size {
		return 0, false
	}
	if option[0] == '-' {
		n = size - n
	}
	return n, true
}

// shellEnvChdir recognizes env's directory option. The invoked command runs
// in the child directory; redirects on env itself run in the parent's.
func shellEnvChdir(call *syntax.CallExpr, home string) (directory, inner string, tail *syntax.CallExpr, recognized bool) {
	if len(call.Args) < 3 {
		return "", "", nil, false
	}
	program, ok := StaticWord(call.Args[0], home)
	if !ok || program != "env" {
		return "", "", nil, false
	}
	arg := 1
	option, ok := StaticWord(call.Args[arg], home)
	switch {
	case ok && (option == "-C" || option == "--chdir"):
		arg++
		if arg >= len(call.Args) {
			return "", "", nil, true
		}
		directory, _ = StaticWord(call.Args[arg], home)
		arg++
	case ok && strings.HasPrefix(option, "--chdir="):
		directory = strings.TrimPrefix(option, "--chdir=")
		arg++
	case ok && strings.HasPrefix(option, "-C"):
		directory = strings.TrimPrefix(option, "-C")
		arg++
	default:
		return "", "", nil, false
	}
	if arg >= len(call.Args) {
		return directory, "", nil, true
	}
	tail = &syntax.CallExpr{Args: call.Args[arg:]}
	if arg+2 >= len(call.Args) {
		return directory, "", tail, true
	}
	shell, shellOK := StaticWord(call.Args[arg], home)
	flag, flagOK := StaticWord(call.Args[arg+1], home)
	inner, ok = StaticWord(call.Args[arg+2], home)
	if !shellOK || !flagOK || !ok || arg+3 != len(call.Args) ||
		(shell != "sh" && shell != "bash") || flag != "-c" {
		return directory, "", tail, true
	}
	return directory, inner, tail, true
}

func directoryFactRequired(directory, home string) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	for _, root := range []string{home, "/home", "/tmp", "/var/tmp"} {
		if root != "" && (directory == root || strings.HasPrefix(directory, root+string(filepath.Separator))) {
			return true
		}
	}
	return false
}
