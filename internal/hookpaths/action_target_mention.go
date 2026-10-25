// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf16"

	"mvdan.cc/sh/v3/syntax"
)

// actionProtectedTargetMention is independent of a program's operand roles.
// A resolved protected path in a writable command is enough for the action
// decision; commands with no such path continue through the existing proof.
func actionProtectedTargetMention(command, cwd, home string) bool {
	return actionProtectedTargetMentionDepth(command, cwd, home, 0, false)
}

// ActionStateTargetMention applies the same independent target scan to the
// active DefenseClaw security state, without attributing it to SSH keys.
func ActionStateTargetMention(command, cwd, home string) bool {
	return actionProtectedTargetMentionDepth(command, cwd, home, 0, true)
}

func actionProtectedTargetMentionDepth(command, cwd, home string, depth int, stateOnly bool) bool {
	if command == "" || home == "" || len(command) > MaxPayloadBytes || depth >= 8 {
		return false
	}
	if actionWindowsHome(home) {
		return actionWindowsTargetMention(command, cwd, home, depth, stateOnly)
	}
	if !filepath.IsAbs(cwd) && (!actionPosixWindowsHome(home) || !path.IsAbs(cwd)) {
		return false
	}
	file, parsed := parseShell(command)
	if depth == 0 && parsed && actionKnownReadOnlyShell(file, home) {
		return false
	}
	if parsed && actionPosixNestedShellMention(file, cwd, home, depth, stateOnly) {
		return true
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	// base places a relative value: the effective cwd for a parsed word,
	// the request cwd for the text scan.
	check := func(value string, tilde bool, base string) bool {
		if len(value) == 0 || len(value) > MaxWriteTargetPathBytes {
			return false
		}
		if tilde && strings.HasPrefix(value, "~/") {
			if actionPosixWindowsHome(home) {
				value = path.Join(home, value[2:])
			} else {
				value = filepath.Join(home, value[2:])
			}
		}
		if strings.ContainsAny(value, "*?[]") {
			if stateOnly {
				return false
			}
			if actionPosixWindowsHome(home) {
				return actionPosixWindowsProtectedGlob(value, base, home)
			}
			return actionProtectedFileGlobReach(value, base, protected, ssh, home)
		}
		if actionPosixWindowsHome(home) {
			if stateOnly {
				return actionPosixWindowsStatePath(value, base, home)
			}
			return actionPosixWindowsProtected(value, base, home)
		}
		operand := OperandPath(value, base)
		if stateOnly {
			return actionProtectedStatePath(operand, home)
		}
		return protectedReachPath(operand, protected, ssh)
	}
	if parsed {
		values := actionValues{"HOME": home, "PWD": cwd}
		found := false
		effectiveCWD := cwd
		var directoryStack []string
		checkWord := func(word *syntax.Word) bool {
			value, known := actionWordValue(word, values, effectiveCWD, home)
			activeGlob := actionWordHasUnquotedGlob(word, command)
			if !known && activeGlob {
				value, known = actionWordValueWithGlob(word, values, effectiveCWD, home, true)
			}
			if known && (!strings.ContainsAny(value, "*?[]") || activeGlob) {
				// A parsed value has had its shell tilde expanded already;
				// a remaining "~/" was quoted, escaped or parameter-derived.
				if check(value, false, effectiveCWD) {
					return true
				}
				if _, target, attached := strings.Cut(value, "="); attached {
					return check(target, actionAttachedTildeExpands(word, command), effectiveCWD)
				}
				return false
			}
			return !stateOnly && actionUnknownWordMayNameKey(word, effectiveCWD, home)
		}
		syntax.Walk(file, func(node syntax.Node) bool {
			if found {
				return false
			}
			if iter, ok := node.(*syntax.WordIter); ok {
				for _, word := range iter.Items {
					if checkWord(word) {
						found = true
						return false
					}
				}
				return true
			}
			stmt, ok := node.(*syntax.Stmt)
			if !ok {
				return true
			}
			values["PWD"] = effectiveCWD
			actionUpdateValues(stmt, values, effectiveCWD, home)
			for _, redir := range stmt.Redirs {
				if redir.Word != nil && checkWord(redir.Word) {
					found = true
					return false
				}
			}
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
				for _, assign := range call.Assigns {
					if assign.Value != nil && checkWord(assign.Value) {
						found = true
						return false
					}
				}
				for _, word := range call.Args {
					if checkWord(word) {
						found = true
						return false
					}
				}
				actionPosixAdvanceDirectory(call, values, home, &effectiveCWD, &directoryStack)
			}
			return true
		})
		if found {
			return true
		}
	}
	text := actionMaskLiteralMetacharacters(command)
	if parsed && actionLiteralArgumentProgramsOnly(file, home) {
		text = actionMarkLiteralTildes(text)
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "${HOME}/", home+"/"), "$HOME/", home+"/")
	for _, token := range actionMentionToken.FindAllString(text, -1) {
		literalTilde := strings.HasPrefix(token, actionLiteralTilde)
		token = strings.ReplaceAll(token, actionLiteralTilde, "~")
		if strings.ContainsAny(token, "*?[]") && (parsed || !strings.ContainsAny(token, "/\\")) {
			continue // Shell case labels and patch text are not argv glob operands.
		}
		if check(token, !literalTilde, cwd) {
			return true
		}
	}
	return false
}

// The text scan finds paths in payloads another program interprets (inline
// interpreter code, nested shells), where a quoted "~/" may still expand.
// When every program in the command only reads, prints or writes its file
// operands as written and nothing is redirected to a file, a quoted or escaped "~/" is the literal
// name the shell passes. It is marked so the scan resolves it below the cwd,
// not the home. Writers and redirects keep the conservative home spelling.
const actionLiteralTilde = "\x1e"

var actionMentionToken = regexp.MustCompile(`[A-Za-z0-9_./~*?\[\]\x1e-]+`)

func actionLiteralArgumentProgramsOnly(file *syntax.File, home string) bool {
	literal := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !literal {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.ProcSubst, *syntax.CoprocClause:
			literal = false
			return false
		case *syntax.Redirect:
			// Writing the text keeps the 1.0.0 mention rule: an output
			// redirect of a key spelling is a protected-named write.
			switch node.Op {
			case syntax.RdrIn, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			default:
				literal = false
				return false
			}
		}
		if _, ok := node.(*syntax.DeclClause); ok {
			// export, declare, local, readonly: a value may reach a
			// program that runs it through a shell (GIT_PAGER, LESSOPEN).
			literal = false
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if !actionLiteralAssignments(call.Assigns) {
			literal = false
			return false
		}
		if len(call.Args) == 0 {
			return true
		}
		args, known := actionLiteralCommandWords(call.Args, home)
		if !known {
			literal = false
			return false
		}
		program, _ := staticProgramWord(args[0], home)
		switch programBase(program) {
		case "echo", "printf", "grep", "egrep", "fgrep", "rg", "cat", "head", "tail", "less", "more",
			"wc", "ls", "dir", "stat", "file", "sort", "uniq", "cut", "tr", "diff", "cmp", "cd",
			"pushd", "popd", "pwd", "true", "false", "test", "[", "basename", "dirname",
			// File writers take their operands as written: a quoted "~/" is
			// a directory named "~" below the cwd, not the home (round l).
			"cp", "mv", "touch", "mkdir", "rm", "ln", "install", "tee", "dd":
		case "git":
			literal = actionLiteralGitWords(args[1:], home)
		default:
			literal = false
		}
		return literal
	})
	return literal
}

// actionLiteralCommandWords strips the wrappers that pass the rest of argv
// on as written (command, builtin, nohup, exec, nice, env with plain
// assignments) and returns the wrapped program's words. known is false for
// a dynamic word or an option it does not know, such as env -S or -C.
func actionLiteralCommandWords(args []*syntax.Word, home string) (words []*syntax.Word, known bool) {
	for wrapper := 0; wrapper < 8 && len(args) > 0; wrapper++ {
		program, fixed := staticProgramWord(args[0], home)
		if !fixed {
			return nil, false
		}
		program = programBase(program)
		index := 1
		switch program {
		case "command", "builtin", "nohup", "exec", "nice", "env":
		default:
			return args, true
		}
		for index < len(args) {
			word, fixed := StaticWord(args[index], home)
			if !fixed {
				return nil, false
			}
			if word == "--" {
				index++
				break
			}
			if program == "env" && !strings.HasPrefix(word, "-") && strings.Contains(word, "=") {
				name, _, _ := strings.Cut(word, "=")
				if !actionLiteralEnvironmentName(name) {
					return nil, false
				}
				index++
				continue
			}
			if !strings.HasPrefix(word, "-") {
				break
			}
			switch {
			case program == "command" && word == "-p",
				program == "exec" && (word == "-c" || word == "-l"),
				program == "env" && (word == "-i" || word == "--ignore-environment"):
				index++
			case program == "nice" && index == 1 && (word == "-n" || word == "--adjustment"):
				if index+1 >= len(args) {
					return nil, false
				}
				value, fixed := StaticWord(args[index+1], home)
				if !fixed || !literalInteger(value) {
					return nil, false
				}
				index += 2
			case program == "nice" && index == 1 && strings.HasPrefix(word, "--adjustment=") &&
				literalInteger(strings.TrimPrefix(word, "--adjustment=")):
				index++
			case program == "nice" && index == 1 && strings.HasPrefix(word, "-n") && literalInteger(word[2:]):
				index++
			default:
				return nil, false
			}
		}
		if index >= len(args) {
			return nil, false
		}
		args = args[index:]
	}
	return nil, false
}

// actionLiteralAssignments reports whether every assignment of a command
// sets only a name no listed program hands to a shell. GIT_PAGER, PAGER,
// EDITOR, LESSOPEN and the like run their value, so they are not literal.
func actionLiteralAssignments(assigns []*syntax.Assign) bool {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil || assign.Append || assign.Naked || assign.Index != nil ||
			assign.Array != nil || !actionLiteralEnvironmentName(assign.Name.Value) {
			return false
		}
	}
	return true
}

// A lower-case name is a shell variable by convention; the programs above
// read only upper-case environment names, and of those only the locale and
// terminal ones are known not to run their value.
func actionLiteralEnvironmentName(name string) bool {
	if name != "" && strings.ToLower(name) == name {
		return true
	}
	switch name {
	case "LANG", "LANGUAGE", "TZ", "NO_COLOR", "TERM", "COLUMNS", "LINES":
		return true
	}
	return strings.HasPrefix(name, "LC_") && len(name) > len("LC_")
}

// actionLiteralGitWords reports whether a git command only reads or records
// its message text. Global options that only move or scope the repository
// are skipped; -c, --config-env, --exec-path and similar can install a
// command that runs later, and grep -O runs its value through a shell.
func actionLiteralGitWords(words []*syntax.Word, home string) bool {
	for len(words) > 0 {
		option, fixed := StaticWord(words[0], home)
		if !fixed {
			return false
		}
		switch option {
		case "-C":
			if len(words) < 2 {
				return false
			}
			words = words[2:]
			continue
		case "--no-pager", "-P", "--no-optional-locks", "--literal-pathspecs", "--glob-pathspecs",
			"--noglob-pathspecs", "--icase-pathspecs", "--no-replace-objects":
			words = words[1:]
			continue
		}
		switch option {
		case "commit", "log", "show", "diff", "status":
			return true
		case "grep":
			for _, word := range words[1:] {
				value, fixed := StaticWord(word, home)
				if !fixed || strings.HasPrefix(value, "--o") ||
					strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") && strings.Contains(value, "O") {
					return false
				}
			}
			return true
		}
		return false
	}
	return false
}

// actionMarkLiteralTildes marks each quoted or escaped tilde that starts a
// path token. The input keeps the command's quotes, so their state is exact.
func actionMarkLiteralTildes(text string) string {
	quoted := actionShellQuotedBytes(text)
	var out strings.Builder
	out.Grow(len(text))
	for i := 0; i < len(text); i++ {
		if text[i] == '~' && quoted[i] && i+1 < len(text) && text[i+1] == '/' &&
			(i == 0 || !actionMentionToken.MatchString(text[i-1:i])) {
			out.WriteString(actionLiteralTilde)
			continue
		}
		out.WriteByte(text[i])
	}
	return out.String()
}

// actionShellQuotedBytes reports, per byte, whether the outer shell quotes
// or escapes it.
func actionShellQuotedBytes(command string) []bool {
	quoted := make([]bool, len(command))
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		quoted[i] = escaped || quote != 0
		switch {
		case escaped:
			escaped = false
		case c == '\\' && quote != '\'':
			escaped = true
		case c == '\'' && quote == 0:
			quote = '\''
		case c == '\'' && quote == '\'':
			quote = 0
		case c == '"' && quote == 0:
			quote = '"'
		case c == '"' && quote == '"':
			quote = 0
		}
	}
	return quoted
}

// The shell expands a tilde right after the "=" of an assignment-shaped
// argument (of=~/x) only when that tilde is unquoted.
func actionAttachedTildeExpands(word *syntax.Word, command string) bool {
	start, end := int(word.Pos().Offset()), int(word.End().Offset())
	if start < 0 || end > len(command) || start >= end {
		return false
	}
	raw := command[start:end]
	equals := strings.IndexByte(raw, '=')
	return equals >= 0 && equals+1 < len(raw) && raw[equals+1] == '~' &&
		!actionShellQuotedBytes(raw)[equals+1]
}

// A Windows hook may receive a POSIX-dialect command from WSL or another
// shell with a POSIX active home. The host filesystem cannot resolve those
// names, so compare only their bounded lexical protected-target spelling.
func actionPosixWindowsHome(home string) bool {
	return runtime.GOOS == "windows" && strings.HasPrefix(home, "/") && !strings.HasPrefix(home, "//")
}

func actionPosixWindowsPath(value, cwd, home string) string {
	if value == "~" {
		value = home
	} else if strings.HasPrefix(value, "~/") {
		value = path.Join(home, value[2:])
	}
	if !path.IsAbs(value) {
		value = path.Join(cwd, value)
	}
	return path.Clean(value)
}

func actionPosixWindowsProtected(value, cwd, home string) bool {
	resolved := actionPosixWindowsPath(value, cwd, home)
	ssh := path.Join(home, ".ssh")
	if resolved == ssh {
		return true
	}
	for _, name := range AuthorizedKeysFiles {
		if resolved == path.Join(ssh, name) {
			return true
		}
	}
	return false
}

func actionPosixWindowsProtectedGlob(value, cwd, home string) bool {
	resolved := actionPosixWindowsPath(value, cwd, home)
	ssh := path.Join(home, ".ssh")
	if matched, _ := path.Match(resolved, ssh); matched {
		return true
	}
	for _, name := range AuthorizedKeysFiles {
		if matched, _ := path.Match(resolved, path.Join(ssh, name)); matched {
			return true
		}
	}
	return false
}

// Match known protected names first, then expand the pattern as the shell
// does, one component at a time, so a wildcard in any component that selects
// a directory alias of ~/.ssh or a key file is followed (GAP-1445). The walk
// is bounded; past the bound a final component that can select a key or
// the .ssh directory stays protected-named.
func actionProtectedFileGlobReach(pattern, cwd string, protected protectedFiles, ssh, home string) bool {
	literal := ""
	if !filepath.IsAbs(pattern) {
		literal = filepath.Clean(cwd)
	}
	pattern = OperandPath(pattern, cwd)
	for _, target := range append([]string{ssh}, ProtectedAuthorizedKeysPaths(home)...) {
		if matched, _ := filepath.Match(pattern, target); matched {
			return true
		}
	}
	if _, err := filepath.Match(pattern, ""); err != nil {
		return false
	}
	candidates, complete := actionExpandGlob(pattern, literal)
	for _, candidate := range candidates {
		if protectedReachPath(candidate, protected, ssh) {
			return true
		}
	}
	if !complete {
		base := filepath.Base(pattern)
		for _, name := range append([]string{".ssh"}, AuthorizedKeysFiles[:]...) {
			if actionGlobNameMatch(base, name) {
				return true
			}
		}
	}
	return false
}

// Bounds of actionExpandGlob: directories read and names kept per step.
const (
	actionGlobMaxReads = 64
	actionGlobMaxNames = 4096
)

// actionExpandGlob lists the existing names an absolute pattern selects. A
// literal component is joined without a lookup, so a final file that does
// not exist yet is still a candidate; literal is a prefix of pattern taken
// as written (the cwd of a relative word). complete is false when a bound
// is exceeded.
func actionExpandGlob(pattern, literal string) (candidates []string, complete bool) {
	separator := string(filepath.Separator)
	start := filepath.VolumeName(pattern) + separator
	rest := strings.TrimPrefix(pattern, start)
	if literal != "" && strings.HasPrefix(pattern, literal+separator) {
		start, rest = literal, pattern[len(literal)+1:]
	}
	paths := []string{start}
	reads := 0
	for _, component := range strings.Split(rest, separator) {
		if component == "" {
			continue
		}
		if !strings.ContainsAny(component, "*?[") {
			for i := range paths {
				paths[i] = filepath.Join(paths[i], component)
			}
			continue
		}
		var next []string
		for _, dir := range paths {
			if reads++; reads > actionGlobMaxReads {
				return nil, false
			}
			directory, err := os.Open(dir)
			if err != nil {
				continue
			}
			names, err := directory.Readdirnames(actionGlobMaxNames + 1)
			_ = directory.Close()
			if err != nil && err != io.EOF || len(names) > actionGlobMaxNames {
				return nil, false
			}
			for _, name := range names {
				if actionGlobNameMatch(component, name) {
					next = append(next, filepath.Join(dir, name))
				}
			}
			if len(next) > actionGlobMaxNames {
				return nil, false
			}
		}
		if len(next) == 0 {
			return nil, true
		}
		paths = next
	}
	return paths, true
}

// actionGlobNameMatch matches one name component; names compare without case
// on macOS and Windows, whose file systems usually ignore it.
func actionGlobNameMatch(pattern, name string) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	}
	matched, _ := filepath.Match(pattern, name)
	return matched
}

func actionPosixWindowsStatePath(value, cwd, home string) bool {
	resolved := actionPosixWindowsPath(value, cwd, home)
	return actionProtectedStateRelative(strings.TrimPrefix(resolved, path.Clean(home)+"/"))
}

// State protection is scoped to the active home and the security-state names
// owned by the semantic detector. Project-local .defenseclaw files and the
// product's diagnostic logs are ordinary work.
func actionProtectedStateRelative(relative string) bool {
	if !strings.HasPrefix(relative, ".defenseclaw/") {
		return false
	}
	state := strings.TrimPrefix(relative, ".defenseclaw/")
	switch state {
	case ".env", "config.yaml", "confidence_policy.yaml", "guardrail_runtime.json",
		"device.key", "picked_connector", "custom-providers.json", "audit.db",
		"audit.db-wal", "audit.db-shm", "judge.db", "judge.db-wal",
		"judge.db-shm", "judge_bodies.db", "judge_bodies.db-wal", "judge_bodies.db-shm":
		return true
	}
	for _, prefix := range []string{"cache/", "policies/", "quarantine/", "receipts/", "registries/"} {
		if strings.HasPrefix(state, prefix) && len(state) > len(prefix) {
			return true
		}
	}
	return false
}

func actionProtectedStatePath(value, home string) bool {
	resolved, ok := ResolveWriteTarget(value)
	if !ok {
		return false
	}
	activeHome, ok := ResolveWriteTarget(home)
	if !ok {
		return false
	}
	relative, err := filepath.Rel(activeHome, resolved)
	return err == nil && actionProtectedStateRelative(filepath.ToSlash(relative))
}

func actionPosixNestedShellMention(file *syntax.File, cwd, home string, depth int, stateOnly bool) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		for i, word := range call.Args {
			program, static := staticProgramWord(word, home)
			if !static {
				continue
			}
			base := programBase(program)
			if base == "env" {
				for j := i + 1; j+1 < len(call.Args); j++ {
					option, optionStatic := StaticWord(call.Args[j], home)
					if !optionStatic || option != "-S" && option != "--split-string" {
						continue
					}
					if child, childStatic := StaticWord(call.Args[j+1], home); childStatic &&
						actionProtectedTargetMentionDepth(child, cwd, home, depth+1, stateOnly) {
						found = true
						return false
					}
				}
			}
			if !posixShellProgram(base) && base != "ash" {
				continue
			}
			for j := i + 1; j+1 < len(call.Args); j++ {
				option, static := StaticWord(call.Args[j], home)
				if !static || !strings.HasPrefix(option, "-") {
					break
				}
				if option == "-o" {
					j++ // This option consumes the next shell setting.
					continue
				}
				if option == "-c" || len(option) > 2 && !strings.HasPrefix(option, "--") &&
					!strings.ContainsAny(option, "=/") && strings.Contains(option[1:], "c") {
					if child, static := StaticWord(call.Args[j+1], home); static &&
						actionProtectedTargetMentionDepth(child, cwd, home, depth+1, stateOnly) {
						found = true
					}
					break
				}
			}
		}
		return !found
	})
	return found
}

// Quoted or escaped dollar signs and glob characters do not expand in the
// outer shell. Nested shell bodies are checked separately above.
func actionMaskLiteralMetacharacters(command string) string {
	var masked strings.Builder
	masked.Grow(len(command))
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		escapedNow := escaped
		switch {
		case escaped:
			escaped = false
		case c == '\\' && quote != '\'':
			escaped = true
		case c == '\'' && quote == 0:
			quote = '\''
		case c == '\'' && quote == '\'':
			quote = 0
		case c == '"' && quote == 0:
			quote = '"'
		case c == '"' && quote == '"':
			quote = 0
		}
		if c == '$' && (escapedNow || quote == '\'') ||
			strings.ContainsRune("*?[]", rune(c)) && (escapedNow || quote != 0) {
			masked.WriteByte('@')
		} else {
			masked.WriteByte(c)
		}
	}
	return masked.String()
}

func actionWordHasUnquotedGlob(word *syntax.Word, command string) bool {
	start, end := int(word.Pos().Offset()), int(word.End().Offset())
	return start >= 0 && end <= len(command) && start < end &&
		strings.ContainsAny(actionMaskLiteralMetacharacters(command[start:end]), "*?[]")
}

func actionKnownReadOnlyShell(file *syntax.File, home string) bool {
	seen, safe := false, true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !safe {
			return false
		}
		switch node.(type) {
		case *syntax.Redirect, *syntax.FuncDecl, *syntax.DeclClause:
			safe = false
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if len(call.Args) == 0 || len(call.Assigns) != 0 {
			safe = false
			return false
		}
		program, known := staticProgramWord(call.Args[0], home)
		if !known {
			safe = false
			return false
		}
		seen = true
		for _, arg := range call.Args[1:] {
			if option, known := StaticWord(arg, home); known && actionReadOptionMayWrite(option) {
				safe = false
				return false
			}
		}
		switch programBase(program) {
		case "cat", "head", "tail", "ls", "dir", "stat":
		case "cd", "pushd", "popd":
			if len(call.Args) > 3 {
				safe = false
			}
		case "less":
			for _, arg := range call.Args[1:] {
				option, known := StaticWord(arg, home)
				if !known || actionLessWritesFile(option) {
					safe = false
					break
				}
			}
		default:
			safe = false
		}
		return safe
	})
	return seen && safe
}

func actionLessWritesFile(option string) bool {
	if option == "-o" || option == "-O" ||
		strings.HasPrefix(option, "-o") && !strings.HasPrefix(option, "--") ||
		strings.HasPrefix(option, "-O") && !strings.HasPrefix(option, "--") {
		return true
	}
	option, _, _ = strings.Cut(strings.ToLower(option), "=")
	return strings.HasPrefix(option, "--") && len(option) > 2 &&
		(strings.HasPrefix("--log-file", option) || strings.HasPrefix(option, "--log-file"))
}

func actionWindowsTargetMention(command, cwd, home string, depth int, stateOnly bool) bool {
	if depth >= 8 || len(command) > MaxPayloadBytes {
		return false
	}
	// The argument to PowerShell -Command is parsed again by the child shell.
	// Quotes that are literal in the outer command do not stop expansion there.
	rawWords, rawOK := actionWindowsWords(command)
	if rawOK {
		for i := 0; i+2 < len(rawWords); i++ {
			program := strings.TrimSuffix(strings.ToLower(programBase(rawWords[i])), ".exe")
			if program == "env" {
				for j := i + 1; j+1 < len(rawWords); j++ {
					if rawWords[j] == ";" || rawWords[j] == "|" || rawWords[j] == "&" {
						break
					}
					if (rawWords[j] == "-S" || rawWords[j] == "--split-string") &&
						actionWindowsTargetMention(rawWords[j+1], cwd, home, depth+1, stateOnly) {
						return true
					}
				}
			}
			if program != "pwsh" && program != "powershell" {
				continue
			}
			for j := i + 1; j+1 < len(rawWords); j++ {
				if rawWords[j] == ";" || rawWords[j] == "|" || rawWords[j] == "&" {
					break
				}
				if strings.EqualFold(rawWords[j], "-command") || strings.EqualFold(rawWords[j], "-c") {
					if actionWindowsTargetMention(rawWords[j+1], cwd, home, depth+1, stateOnly) {
						return true
					}
					break
				}
			}
		}
	}
	// PowerShell does not expand variables inside single quoted literals.
	// Preserve the literal pathname there while keeping its dollar sign from
	// being mistaken for a resolvable home variable.
	var normalized strings.Builder
	normalized.Grow(len(command))
	singleQuoted := false
	for i := 0; i < len(command); i++ {
		if command[i] == '\'' {
			singleQuoted = !singleQuoted
		}
		if singleQuoted && command[i] == '$' {
			normalized.WriteByte('@')
		} else {
			normalized.WriteByte(command[i])
		}
	}
	words, ok := actionWindowsWords(normalized.String())
	if !ok || len(words) == 0 || depth == 0 && actionKnownReadOnlyWindows(words) {
		return false
	}
	for i := 0; i+1 < len(words); i++ {
		if !strings.EqualFold(words[i], "-encodedcommand") && !strings.EqualFold(words[i], "-enc") {
			continue
		}
		encoded, err := base64.StdEncoding.DecodeString(words[i+1])
		if err != nil || len(encoded) == 0 || len(encoded)%2 != 0 {
			continue
		}
		letters := make([]uint16, len(encoded)/2)
		for j := range letters {
			letters[j] = uint16(encoded[2*j]) | uint16(encoded[2*j+1])<<8
		}
		if actionWindowsTargetMention(string(utf16.Decode(letters)), cwd, home, depth+1, stateOnly) {
			return true
		}
	}
	effectiveCWD := cwd
	var directoryStack []string
	for _, statement := range actionWindowsResolvedStatements(words, cwd, home) {
		for _, word := range statement {
			if actionWindowsWordMentionsTarget(word, effectiveCWD, home, stateOnly) {
				return true
			}
		}
		actionWindowsAdvanceDirectory(statement, home, &effectiveCWD, &directoryStack)
	}
	for _, word := range words {
		if actionWindowsWordMentionsTarget(word, cwd, home, stateOnly) {
			return true
		}
	}
	return false
}

func actionKnownReadOnlyWindows(words []string) bool {
	seen, start := false, 0
	for i, word := range words {
		if actionWindowsRedirectOperator(word) != "" {
			return false
		}
		if word != ";" && word != "|" && word != "||" && word != "&" && word != "&&" {
			continue
		}
		if !actionKnownReadOnlyWindowsStatement(words[start:i]) {
			return false
		}
		seen, start = true, i+1
	}
	return (seen || start < len(words)) && actionKnownReadOnlyWindowsStatement(words[start:])
}

func actionKnownReadOnlyWindowsStatement(words []string) bool {
	if len(words) == 0 {
		return false
	}
	for _, word := range words {
		if strings.ContainsAny(word, "(`") || strings.Contains(word, "@{") {
			return false // A nested command or escaped syntax is not a plain read.
		}
		for i := 0; i < len(word); i++ {
			if word[i] == '{' && (i == 0 || word[i-1] != '$') {
				return false // Scriptblocks and calculated properties execute commands.
			}
		}
	}
	program := strings.TrimSuffix(strings.ToLower(programBase(words[0])), ".exe")
	for _, option := range words[1:] {
		if actionReadOptionMayWrite(option) {
			return false
		}
	}
	switch program {
	case "cat", "get-content", "get-childitem", "resolve-path", "test-path", "head", "tail", "dir", "ls", "stat", "cd", "pushd", "popd", "set-location", "push-location", "pop-location":
		return true
	case "less":
		for _, option := range words[1:] {
			if actionLessWritesFile(option) {
				return false
			}
		}
		return true
	}
	return false
}

func actionWindowsWordMentionsTarget(word, cwd, home string, stateOnly bool) bool {
	check := func(candidate string) bool {
		candidate = strings.ReplaceAll(candidate, "`", "")
		if strings.ContainsAny(candidate, "*?[]") {
			return !stateOnly && (actionWindowsProtectedGlobReach(candidate, cwd, home) ||
				actionWindowsDynamicKeyPath(candidate))
		}
		resolved, ok := actionWindowsPath(candidate, cwd, home)
		if !ok {
			if stateOnly {
				return false
			}
			return actionWindowsUnresolvedUnderSSH(candidate, cwd, home) ||
				actionWindowsDynamicKeyPath(candidate)
		}
		root, ok := actionWindowsPath(home, cwd, home)
		if !ok {
			return false
		}
		if stateOnly {
			return strings.HasPrefix(resolved, root+"/") &&
				actionProtectedStateRelative(strings.TrimPrefix(resolved, root+"/"))
		}
		if resolved == root+"/.ssh" {
			return true
		}
		protected, _ := actionWindowsProtected(candidate, cwd, home, false)
		return protected
	}
	if check(word) {
		return true
	}
	for _, field := range strings.FieldsFunc(word, func(r rune) bool {
		return strings.ContainsRune(" \t\r\n'\"(),;|&<>{}=", r)
	}) {
		if check(field) {
			return true
		}
		if colon := strings.IndexByte(field, ':'); colon > 1 && field[0] == '-' && check(field[colon+1:]) {
			return true
		}
	}
	return false
}

// A dynamic Windows word names a key only when the component after a .ssh
// directory is a key file name or a pattern that can select one; a longer
// literal name such as authorized_keys.bak is another file.
func actionWindowsDynamicKeyPath(value string) bool {
	value = strings.ToLower(strings.ReplaceAll(value, `\`, "/"))
	if !strings.ContainsAny(value, "$%`") {
		return false
	}
	value = actionWindowsDynamicPart.ReplaceAllString(value, "\x00")
	for rest := value; ; {
		index := strings.Index(rest, "/.ssh/")
		if index < 0 {
			return false
		}
		rest = rest[index+len("/.ssh/"):]
		end := strings.IndexAny(rest, "/\"' ;|&,)")
		if end < 0 {
			end = len(rest)
		}
		var component actionKeyComponent
		for i := 0; i < end; i++ {
			switch rest[i] {
			case 0, '*':
				component.wildcard("*")
			case '?':
				component.wildcard("?")
			default:
				component.literal(rest[i])
			}
		}
		if component.selects(false) {
			return true
		}
	}
}

var actionWindowsDynamicPart = regexp.MustCompile(`\$\{[^}]*\}|\$\([^)]*\)|\$[a-z_][a-z0-9_]*(:[a-z_][a-z0-9_]*)?|%[^%/]*%`)

func actionWindowsProtectedGlobReach(pattern, cwd, home string) bool {
	pattern = strings.ReplaceAll(pattern, `\`, "/")
	lower := strings.ToLower(pattern)
	for _, prefix := range []string{"%userprofile%", "%homedrive%%homepath%", "$env:userprofile", "${env:userprofile}", "$home", "${home}", "~"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			pattern = strings.ReplaceAll(home, `\`, "/") + pattern[len(prefix):]
			break
		}
	}
	if !actionWindowsHome(pattern) {
		pattern = strings.TrimRight(strings.ReplaceAll(cwd, `\`, "/"), "/") + "/" + pattern
	}
	pattern = strings.ToLower(path.Clean(pattern))
	root, ok := actionWindowsPath(home, cwd, home)
	if !ok {
		return false
	}
	ssh := root + "/.ssh"
	if matched, _ := path.Match(pattern, ssh); matched {
		return true
	}
	for _, name := range AuthorizedKeysFiles {
		if matched, _ := path.Match(pattern, ssh+"/"+name); matched {
			return true
		}
	}
	parent, base := path.Split(pattern)
	if parent == "" {
		parent = "."
	}
	if _, err := path.Match(base, ""); err != nil {
		return false
	}
	// On the host, expand every component through junctions and links
	// (GAP-1445).
	if runtime.GOOS == "windows" && filepath.IsAbs(filepath.FromSlash(pattern)) && actionProtectedFileGlobReach(
		filepath.FromSlash(pattern), cwd, newProtectedFiles(home), filepath.Join(home, ".ssh"), home) {
		return true
	}
	if strings.ContainsAny(parent, "*?[") {
		return false
	}
	resolved, ok := actionWindowsPath(strings.TrimSuffix(parent, "/"), cwd, home)
	if !ok {
		return false
	}
	if resolved != ssh {
		return false
	}
	for _, name := range AuthorizedKeysFiles {
		if matched, _ := path.Match(strings.ToLower(base), name); matched {
			return true
		}
	}
	return false
}

// An unresolved leaf under .ssh is still a protected-directory use. Keep
// this lexical fallback scoped to that directory; other unknown paths audit.
func actionWindowsUnresolvedUnderSSH(value, cwd, home string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")
	lower := strings.ToLower(value)
	for _, prefix := range []string{"%userprofile%", "%homedrive%%homepath%", "$env:userprofile", "${env:userprofile}", "$home", "${home}", "~"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			value = strings.ReplaceAll(home, `\`, "/") + value[len(prefix):]
			break
		}
	}
	if !actionWindowsHome(value) {
		value = strings.TrimRight(strings.ReplaceAll(cwd, `\`, "/"), "/") + "/" + value
	}
	root := strings.ToLower(path.Clean(strings.ReplaceAll(home, `\`, "/"))) + "/.ssh/"
	return strings.HasPrefix(strings.ToLower(path.Clean(value)), root)
}
