// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"

	"mvdan.cc/sh/v3/syntax"
)

// ActionStateTargetMention applies the same independent target scan to the
// active DefenseClaw security state, without attributing it to SSH keys.
func ActionStateTargetMention(command, cwd, home string) bool {
	return actionProtectedTargetMentionDepth(command, cwd, home, 0, true, nil)
}

// actionProtectedTargetMentionDepth is independent of a program's operand
// roles. A resolved protected path in a writable command is enough for the
// action decision; commands with no such path continue through the existing
// proof. globs carries the hook client's pattern answers (actionGlobs).
func actionProtectedTargetMentionDepth(command, cwd, home string, depth int, stateOnly bool, globs *actionGlobs) bool {
	if command == "" || home == "" || len(command) > MaxPayloadBytes || depth >= 8 {
		return false
	}
	if depth == 0 {
		globs = globs.forCommand(command)
	}
	if actionWindowsHome(home) {
		return actionWindowsTargetMention(command, cwd, home, depth, stateOnly)
	}
	return actionPosixTargetMention(command, cwd, home, depth, stateOnly, globs)
}

// actionPosixTargetMention is the POSIX-grammar target scan. On a native
// Windows host it also reads a POSIX shell's command (Git Bash, MSYS) under
// a Windows home, on the Windows file system (ActionCommandDecisionInShell).
func actionPosixTargetMention(command, cwd, home string, depth int, stateOnly bool, globs *actionGlobs) bool {
	if !filepath.IsAbs(cwd) && (!actionPosixWindowsHome(home) || !path.IsAbs(cwd)) {
		return false
	}
	file, parsed := parseShell(command)
	if depth == 0 && parsed && actionKnownReadOnlyShell(file, home) {
		return false
	}
	// A function the command never calls never runs (GAP-1535).
	var uncalled map[*syntax.FuncDecl]bool
	if parsed {
		uncalled = actionUncalledFunctions(file, command)
		command = actionBlankFunctions(command, uncalled)
	}
	var nestedBodies []*syntax.Word
	if parsed {
		var nestedFound bool
		nestedBodies, nestedFound = actionPosixNestedShellMention(file, cwd, home, depth, stateOnly, globs)
		if nestedFound {
			return true
		}
		if !stateOnly && actionInterpreterBuildsKeyPath(file, home) {
			return true
		}
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	// base places a relative value: the effective cwd for a parsed word,
	// the request cwd for the text scan.
	checkValue := func(value string, tilde bool, base string) bool {
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
			return actionProtectedFileGlobReach(value, base, protected, ssh, home, globs)
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
	// The hook client records an answer for every pattern the scan checks,
	// so while recording it never stops at a match.
	check := func(value string, tilde bool, base string) bool {
		return checkValue(value, tilde, base) && !globs.recording()
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
			return !stateOnly && !globs.recording() && actionUnknownWordMayNameKey(word, effectiveCWD, home)
		}
		syntax.Walk(file, func(node syntax.Node) bool {
			if found {
				return false
			}
			if decl, ok := node.(*syntax.FuncDecl); ok && uncalled[decl] {
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
	text := actionBlankPatchBodies(command, actionMaskLiteralMetacharacters(command))
	if parsed && actionLiteralArgumentProgramsOnly(file, home) {
		text = actionMarkLiteralTildes(text)
	}
	// A static nested shell body was scanned above in its own quoting, so a
	// tilde quoted inside it is literal and an unquoted one is the home. The
	// outer quotes around the body say nothing about that (round m).
	text = actionBlankWords(text, nestedBodies)
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

// actionInterpreterKeyPath matches inline interpreter code that builds a
// path to an authorized-keys file from parts: an f-string or concatenation
// ({h}/.ssh/authorized_keys, h + "/.ssh/authorized_keys"), os.path.join(h,
// ".ssh", "authorized_keys") or Path(h) / ".ssh" / "authorized_keys". The
// .ssh and authorized_keys names are both in the code, a protected-named
// word whatever builds the prefix (GAP-1732, the GAP-0475 class).
var actionInterpreterKeyPath = regexp.MustCompile(`\.ssh(?:['"\s,/+)\\]|os\.sep|File::Spec|path\.sep){1,12}authorized_keys2?\b`)

// actionInterpreterHomeCall matches the home spellings the interpreter-path
// proof already judges with its binding rules (Path.home(), expanduser:
// GAP-0475, a path bound again before the write, GAP-1299).
var actionInterpreterHomeCall = regexp.MustCompile(`Path\.home\(\)|expanduser\(`)

// actionInterpreterCodeWrites reports a writer call (open, write_text,
// appendFileSync ...) in executable code, not inside a string or comment:
// a path built only inside inert text writes nothing (GAP-0475 row).
func actionInterpreterCodeWrites(code, language string) bool {
	for _, location := range unprovenWriter.FindAllStringIndex(code, -1) {
		if language == "python" || strings.HasPrefix(language, "python3") {
			if pythonExecutableCodePosition(code, location[0]) {
				return true
			}
		} else if literalCodePosition(code, location[0], language) {
			return true
		}
	}
	return false
}

// actionInterpreterBuildsKeyPath reports a python -c, perl/ruby/node -e call
// whose code builds a path to an authorized-keys file and has a write.
func actionInterpreterBuildsKeyPath(file *syntax.File, home string) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if found || !ok || len(call.Args) < 3 {
			return !found
		}
		program, known := staticProgramWord(call.Args[0], home)
		if !known {
			return true
		}
		language := programBase(program)
		if code, _, ok := interpreterCodeOperand(call, language, home); ok &&
			actionInterpreterKeyPath.MatchString(code) && actionInterpreterCodeWrites(code, language) &&
			!actionInterpreterHomeCall.MatchString(code) {
			found = true
		}
		return !found
	})
	return found
}

// actionUncalledFunctions lists the function definitions whose name the
// command never names outside the definition itself: no call, no export -f,
// trap, alias, eval or xargs argument. Such a body never runs. Names the
// shell calls on its own (command_not_found_handle, zsh hooks and TRAP*)
// always count as called.
func actionUncalledFunctions(file *syntax.File, command string) map[*syntax.FuncDecl]bool {
	var decls []*syntax.FuncDecl
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok && decl.Name != nil {
			decls = append(decls, decl)
		}
		return true
	})
	if len(decls) == 0 {
		return nil
	}
	uncalled := make(map[*syntax.FuncDecl]bool)
	for _, decl := range decls {
		name := decl.Name.Value
		switch {
		case name == "" || strings.HasPrefix(name, "TRAP") || strings.HasPrefix(name, "command_not_found_handl"):
			continue
		}
		switch name {
		case "precmd", "preexec", "chpwd", "periodic", "zshexit", "zshaddhistory", "zle-line-init":
			continue
		}
		start, end := int(decl.Pos().Offset()), int(decl.End().Offset())
		if start < 0 || end > len(command) || start >= end {
			continue
		}
		pattern := regexp.MustCompile(`(^|[^A-Za-z0-9_.:-])` + regexp.QuoteMeta(name) + `($|[^A-Za-z0-9_.:-])`)
		rest := command[:start] + strings.Repeat(" ", end-start) + command[end:]
		if !pattern.MatchString(rest) {
			uncalled[decl] = true
		}
	}
	return uncalled
}

// actionBlankFunctions blanks the uncalled function definitions in command,
// keeping every offset.
func actionBlankFunctions(command string, uncalled map[*syntax.FuncDecl]bool) string {
	if len(uncalled) == 0 {
		return command
	}
	out := []byte(command)
	for decl := range uncalled {
		start, end := int(decl.Pos().Offset()), int(decl.End().Offset())
		for i := start; i < end && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return string(out)
}

// actionBlankPatchBodies blanks, in the text scan, the content lines of the
// patch envelopes apply_patch calls read: those calls write only the files
// their headers name, which stay (GAP-0781, GAP-1106). text is command with
// its literal metacharacters masked, line for line.
func actionBlankPatchBodies(command, text string) string {
	if !strings.Contains(command, patchBeginMarker) {
		return text
	}
	fed := patchFedLines(command)
	lines := strings.Split(text, "\n")
	if fed == nil || len(lines) != len(fed) {
		return text
	}
	commandLines := strings.Split(command, "\n")
	for i, line := range commandLines {
		if !fed[i] && patchCommandResolutionChange(line) {
			// Another apply_patch may run and read the body as a script.
			return text
		}
	}
	for i, line := range commandLines {
		if fed[i] && !strings.HasPrefix(strings.TrimSpace(line), "***") {
			lines[i] = strings.Repeat(" ", len(lines[i]))
		}
	}
	return strings.Join(lines, "\n")
}

// patchResolutionChanges match shell text that may change the program an
// apply_patch word runs: a PATH (zsh path) assignment, export or unset, the
// PowerShell Env:PATH drive, or a sourced, evaluated or aliased definition.
// Envelope lines (headers such as "*** Add File: PATH.md") and text that only
// mentions or reads PATH change nothing (round n review).
var patchResolutionChanges = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|[^a-z0-9_-])path\s*(\+?=|\[)`),
	regexp.MustCompile(`(?i)(^|[^a-z0-9_-])(export|unset|declare|typeset|readonly|local|setenv|env)\b.*\bpath\b`),
	regexp.MustCompile(`(?i)env:\\?path\b|setenvironmentvariable|\b(iex|invoke-expression)\b`),
	regexp.MustCompile(`(^|[\s;&|(])(source|eval|\.)(\s|$)|\b(alias|functions|hash|enable)\b`),
}

func patchCommandResolutionChange(line string) bool {
	for _, change := range patchResolutionChanges {
		if change.MatchString(line) {
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
		case "command", "builtin", "nohup", "exec", "nice", "env", "sudo", "doas", "timeout",
			"stdbuf", "ionice", "setsid":
		default:
			return args, true
		}
		durationPending := program == "timeout"
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
				if durationPending {
					// timeout DURATION COMMAND: the duration is not the program.
					if !literalDuration(word) {
						return nil, false
					}
					durationPending = false
					index++
					continue
				}
				break
			}
			if consumed, ok := actionLiteralWrapperOption(program, word, args[index+1:], home); ok {
				index += consumed
				continue
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
		if index >= len(args) || durationPending {
			return nil, false
		}
		args = args[index:]
	}
	return nil, false
}

// actionLiteralWrapperOption reports how many words an option of sudo, doas,
// timeout, stdbuf, ionice, setsid or env takes when the wrapper still runs
// the next words as argv. Options that start a shell, edit a file, change
// the directory or list instead of running (sudo -s/-i/-e/-D/-l, doas -s,
// env -C/-S) are not listed, so the command stays on the home spelling.
func actionLiteralWrapperOption(program, word string, rest []*syntax.Word, home string) (int, bool) {
	value := func() bool {
		if len(rest) == 0 {
			return false
		}
		_, fixed := StaticWord(rest[0], home)
		return fixed
	}
	switch program {
	case "sudo":
		switch word {
		case "-n", "--non-interactive", "-E", "--preserve-env", "-H", "--set-home", "-S", "--stdin",
			"-k", "--reset-timestamp", "-b", "--background", "-P", "--preserve-groups":
			return 1, true
		case "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from",
			"-T", "--command-timeout", "-r", "--role", "-t", "--type", "-U", "--other-user":
			return 2, value()
		}
		for _, prefix := range []string{"--user=", "--group=", "--host=", "--prompt=", "--close-from=",
			"--command-timeout=", "--role=", "--type="} {
			if strings.HasPrefix(word, prefix) {
				return 1, true
			}
		}
		if len(word) > 2 && !strings.HasPrefix(word, "--") && strings.Trim(word[1:], "nEHSkbP") == "" {
			return 1, true // combined switches such as -nE
		}
	case "doas":
		switch word {
		case "-n":
			return 1, true
		case "-u":
			return 2, value()
		}
	case "timeout":
		switch word {
		case "--foreground", "--preserve-status", "-v", "--verbose":
			return 1, true
		case "-k", "--kill-after", "-s", "--signal":
			return 2, value()
		}
		if strings.HasPrefix(word, "--kill-after=") || strings.HasPrefix(word, "--signal=") ||
			strings.HasPrefix(word, "-k") || strings.HasPrefix(word, "-s") {
			return 1, true
		}
	case "stdbuf":
		switch word {
		case "-i", "-o", "-e", "--input", "--output", "--error":
			return 2, value()
		}
		if len(word) > 2 && (strings.HasPrefix(word, "-i") || strings.HasPrefix(word, "-o") ||
			strings.HasPrefix(word, "-e")) && !strings.HasPrefix(word, "--") ||
			strings.HasPrefix(word, "--input=") || strings.HasPrefix(word, "--output=") ||
			strings.HasPrefix(word, "--error=") {
			return 1, true
		}
	case "ionice":
		switch word {
		case "-c", "--class", "-n", "--classdata":
			return 2, value()
		case "-t", "--ignore":
			return 1, true
		}
		if len(word) > 2 && (strings.HasPrefix(word, "-c") || strings.HasPrefix(word, "-n")) &&
			!strings.HasPrefix(word, "--") {
			return 1, true
		}
	case "setsid":
		switch word {
		case "-f", "--fork", "-w", "--wait", "-c", "--ctty":
			return 1, true
		}
	case "env":
		switch word {
		case "-u", "--unset":
			return 2, value()
		case "-0", "--null":
			return 1, true
		}
		if strings.HasPrefix(word, "--unset=") {
			return 1, true
		}
	}
	return 0, false
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
//
// A gateway behind ProtectHome cannot read the user's directories, so its
// walk is incomplete. The managed hook client expands the same pattern as
// the user and sends its answer (GlobFactPrefix); that answer decides, as
// the walk of a gateway that can see the home would (GAP-1460 review). With
// no answer, the name fallback below keeps the pattern closed.
func actionProtectedFileGlobReach(pattern, cwd string, protected protectedFiles, ssh, home string, globs *actionGlobs) bool {
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
	if _, err := filepath.Match(pattern, ""); err != nil || globs.full() {
		return false
	}
	hidden := actionGlobViewHidden(cwd, home)
	dots := sync.OnceValue(func() bool { return globs.dotNames() || actionShellProfileMayDotglob(home) })
	userView := !hidden && actionProcessOwnsHome(home)
	candidates, complete, unseen := actionExpandGlob(pattern, literal, hidden, userView, dots)
	for _, candidate := range candidates {
		if protectedReachPath(candidate, protected, ssh) {
			globs.note(pattern, "1")
			return true
		}
	}
	if complete {
		globs.note(pattern, "0")
		return false
	}
	if hidden && unseen {
		if answer := globs.answer(pattern); answer != "" {
			// A walk this process could not see defers to the client,
			// which expanded the pattern as the user.
			return answer == "1"
		}
		if !globs.fromClient() {
			// No client evidence at all (an older hook client): the
			// name fallback of round m.
			base := filepath.Base(pattern)
			if !strings.ContainsAny(filepath.Dir(pattern), "*?[") && !actionGlobHasLiteral(base) {
				// Only the last component is a pattern, in a directory
				// this process cannot read, and it names nothing (git
				// add *): no directory alias can be selected.
				return false
			}
			for _, name := range append([]string{".ssh"}, AuthorizedKeysFiles[:]...) {
				if actionGlobNameMatch(base, name) {
					return true
				}
			}
			return false
		}
	}
	// The walk (this one, or the client's that sent no answer) stopped at
	// a bound or at a directory it could not read, so an alias of any name
	// may be among the names it did not see: the pattern is unproved,
	// never an allow (GAP-1481).
	return true
}

// actionGlobs carries the hook client's pathname-pattern answers through
// one target scan, keyed GlobFactPrefix plus the absolute pattern. A
// gateway reads facts; the hook client fills record. A plain scan has none.
type actionGlobs struct {
	facts  map[string]string
	record map[string]string
	// dots is set when the command may make * and ? match a leading dot
	// (actionCommandMayDotglob).
	dots bool
}

// forCommand returns the scan state of one command, sharing the client's
// facts and record.
func (g *actionGlobs) forCommand(command string) *actionGlobs {
	var scan actionGlobs
	if g != nil {
		scan = *g
	}
	scan.dots = actionCommandMayDotglob(command)
	return &scan
}

func (g *actionGlobs) dotNames() bool { return g != nil && g.dots }

// actionDotglobSetting matches, once lowercased without underscores, a
// shell setting that lets * and ? match a leading dot: bash dotglob or a
// GLOBIGNORE, zsh GLOB_DOTS or a (D) qualifier, or a startup file
// (BASH_ENV) that may set one.
var (
	actionDotglobSetting   = regexp.MustCompile(`dotglob|globdots|globignore|bashenv`)
	actionDotglobQualifier = regexp.MustCompile(`[*?\]]\([^()]*D[^()]*\)`)
)

func actionCommandMayDotglob(command string) bool {
	return actionDotglobSetting.MatchString(strings.ReplaceAll(strings.ToLower(command), "_", "")) ||
		actionDotglobQualifier.MatchString(command)
}

// actionShellProfileMayDotglob reports a startup file of the user's or the
// system's shell, or an inherited BASHOPTS or GLOBIGNORE, that may set
// dotglob, or a home this process cannot read.
func actionShellProfileMayDotglob(home string) bool {
	if _, err := os.Stat(home); err != nil || strings.Contains(os.Getenv("BASHOPTS"), "dotglob") || os.Getenv("GLOBIGNORE") != "" {
		return true
	}
	files := []string{"/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/zshenv", "/etc/zsh/zshenv",
		"/etc/zprofile", "/etc/zsh/zprofile", "/etc/zshrc", "/etc/zsh/zshrc", "/etc/zlogin", "/etc/zsh/zlogin"}
	if profiles, err := filepath.Glob("/etc/profile.d/*.sh"); err == nil {
		files = append(files, profiles...)
	}
	for _, name := range []string{".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile", ".zshenv", ".zprofile", ".zshrc", ".zlogin"} {
		files = append(files, filepath.Join(home, name))
	}
	for _, name := range files {
		file, err := os.Open(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return true
		}
		data, err := io.ReadAll(io.LimitReader(file, 1<<20))
		_ = file.Close()
		if err != nil || actionDotglobSetting.MatchString(strings.ReplaceAll(strings.ToLower(string(data)), "_", "")) {
			return true
		}
	}
	return false
}

// maxGlobFacts bounds the patterns the hook client expands for one call. A
// pattern past it has no answer, so the gateway keeps its fallback.
const maxGlobFacts = 32

func (g *actionGlobs) recording() bool { return g != nil && g.record != nil }

func (g *actionGlobs) full() bool { return g.recording() && len(g.record) >= maxGlobFacts }

// note records the client's answer: "1" when a match reaches a protected
// file, "0" when its walk was complete and no match does.
func (g *actionGlobs) note(pattern, answer string) {
	if !g.recording() || len(GlobFactPrefix)+len(pattern) > MaxWriteTargetPathBytes {
		return
	}
	if key := GlobFactPrefix + pattern; g.record[key] != "1" {
		g.record[key] = answer
	}
}

// fromClient reports a scan that carries the hook client's evidence, so a
// pattern it sent no answer for is one its own walk could not prove.
func (g *actionGlobs) fromClient() bool { return g != nil && g.facts != nil }

func (g *actionGlobs) answer(pattern string) string {
	if g == nil || g.facts == nil {
		return ""
	}
	return g.facts[GlobFactPrefix+pattern]
}

// actionGlobFacts expands, as the user, each pathname pattern the action
// target scan of command checks, and returns the answers for the gateway.
func actionGlobFacts(command, cwd, home string) map[string]string {
	globs := &actionGlobs{record: map[string]string{}}
	actionProtectedTargetMentionDepth(command, cwd, home, 0, false, globs)
	return globs.record
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
// is exceeded or a directory cannot be read; unseen tells the latter. The
// walk keeps every match it found before or beside a directory it could not
// read or past a bound, so such a directory never hides a match (GAP-1481).
//
// userView is set when the process runs as the home's owner (a per-user
// gateway or the hook client): a directory it may not list is one the
// user's shell may not list either, so it holds no match.
//
// hidden is set when the process cannot see the request's cwd or home
// (systemd ProtectHome on a managed gateway): a directory missing from
// that view is not proof the user's shell finds no match (GAP-1460).
//
// A component that starts with * or ? does not match a name with a leading
// dot, as in the shell, unless dots reports a setting that changes that.
func actionExpandGlob(pattern, literal string, hidden, userView bool, dots func() bool) (candidates []string, complete, unseen bool) {
	separator := string(filepath.Separator)
	start := filepath.VolumeName(pattern) + separator
	rest := strings.TrimPrefix(pattern, start)
	if literal != "" && strings.HasPrefix(pattern, literal+separator) {
		start, rest = literal, pattern[len(literal)+1:]
	}
	paths := []string{start}
	reads := 0
	complete = true
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
			if reads++; reads > actionGlobMaxReads || len(next) >= actionGlobMaxNames {
				complete = false
				break
			}
			directory, err := os.Open(dir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && !hidden || errors.Is(err, syscall.ENOTDIR) {
					continue
				}
				// A process that runs as the user cannot list what the
				// user's shell cannot list: the shell expands nothing there
				// (GAP-1739).
				if userView && errors.Is(err, fs.ErrPermission) {
					continue
				}
				// Permission denied, or a home this process cannot see:
				// the user's shell may still expand the pattern there.
				// The siblings are still read.
				complete, unseen = false, true
				continue
			}
			names, err := directory.Readdirnames(actionGlobMaxNames + 1)
			_ = directory.Close()
			if err != nil && err != io.EOF && actionGlobNotDirectory(dir, err) {
				// A file the previous component matched has no entries;
				// the shell skips it (*/* in a project with files).
				continue
			}
			if err != nil && err != io.EOF || len(names) > actionGlobMaxNames {
				complete = false
			}
			for _, name := range names {
				if actionGlobNameMatch(component, name) && !actionGlobSkipsDotName(component, name, dots) {
					next = append(next, filepath.Join(dir, name))
				}
			}
		}
		if len(next) == 0 {
			return nil, complete, unseen
		}
		paths = next
	}
	return paths, complete, unseen
}

// actionGlobNotDirectory reports that a listing failed because dir, or the
// file a link there names, is not a directory.
func actionGlobNotDirectory(dir string, err error) bool {
	if errors.Is(err, syscall.ENOTDIR) {
		return true
	}
	info, statErr := os.Stat(dir)
	return statErr == nil && !info.IsDir()
}

// actionGlobHasLiteral reports whether a pattern component keeps a literal
// character outside *, ? and bracket expressions.
func actionGlobHasLiteral(component string) bool {
	for i := 0; i < len(component); i++ {
		switch component[i] {
		case '*', '?':
		case '\\':
			return true
		case '[':
			if end := strings.IndexByte(component[i+1:], ']'); end >= 0 {
				i += end + 1
				continue
			}
			return true
		default:
			return true
		}
	}
	return false
}

// actionGlobViewHidden reports whether this process cannot see the cwd or
// the home the hook reported, as a managed gateway behind ProtectHome.
func actionGlobViewHidden(cwd, home string) bool {
	for _, dir := range []string{cwd, home} {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir); err != nil {
			return true
		}
	}
	return false
}

// actionGlobSkipsDotName reports a leading-dot name that the shell's * or ?
// does not match. A bracket stays a match: the walk keeps the doubt.
func actionGlobSkipsDotName(component, name string, dots func() bool) bool {
	return runtime.GOOS != "windows" && strings.HasPrefix(name, ".") &&
		(strings.HasPrefix(component, "*") || strings.HasPrefix(component, "?")) && !dots()
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
	if slices.Contains(activeStateFiles, state) {
		return true
	}
	for _, tree := range activeStateTrees {
		if strings.HasPrefix(state, tree+"/") && len(state) > len(tree)+1 {
			return true
		}
	}
	return false
}

// activeStateFiles and activeStateTrees are the active security state under
// .defenseclaw. The trees are listed in the order the identity index visits
// them: hooks and policies first, the large scan cache last. The saved
// installer and its previous copy are active state (GAP-1099, instr-protect).
var (
	activeStateFiles = []string{
		".env", "config.yaml", "confidence_policy.yaml", "guardrail_runtime.json",
		"device.key", "picked_connector", "custom-providers.json", "audit.db",
		"audit.db-wal", "audit.db-shm", "judge.db", "judge.db-wal",
		"judge.db-shm", "judge_bodies.db", "judge_bodies.db-wal", "judge_bodies.db-shm",
	}
	activeStateTrees = []string{"hooks", "policies", "installer", "previous/installer", "registries", "receipts", "quarantine", "cache"}
)

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
	if err == nil && actionProtectedStateRelative(filepath.ToSlash(relative)) {
		return true
	}
	_, same := ResolveActiveStateHardlinkTarget(resolved, home)
	return same
}

// ResolveActiveStateHardlinkTarget maps an existing write target back to an
// active DefenseClaw state file with the same file identity. Ordinary aliases
// have one link and avoid the index; a multiply linked target is compared
// with the bounded, shared index of the active state files.
func ResolveActiveStateHardlinkTarget(value, home string) (string, bool) {
	resolved, ok := ResolveWriteTarget(value)
	if !ok {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || linkCount(resolved, info) < 2 {
		return "", false
	}
	activeRoot, ok := ResolveWriteTarget(filepath.Join(home, ".defenseclaw"))
	if !ok {
		return "", false
	}
	for _, file := range activeStateIdentities(activeRoot) {
		if !os.SameFile(info, file.info) {
			continue
		}
		// The index can be up to activeStateIndexTTL old: confirm the name
		// still holds this file before mapping the alias to it.
		path := filepath.Join(activeRoot, filepath.FromSlash(file.relative))
		if current, err := os.Stat(path); err == nil && os.SameFile(info, current) {
			return filepath.Join(home, ".defenseclaw", filepath.FromSlash(file.relative)), true
		}
	}
	return "", false
}

// The identity index of one active state tree is built at most once per
// activeStateIndexTTL and shared by every operand and request in that time,
// so a command naming many ordinary hard links costs one bounded walk. The
// walk stops after activeStateIndexEntries entries or activeStateIndexBudget,
// well inside every hook deadline; a file it did not reach is not mapped (no
// block), which never refuses ordinary work.
var (
	activeStateIndexEntries = 4096
	activeStateIndexBudget  = 250 * time.Millisecond
	activeStateIndexTTL     = 2 * time.Second
	activeStateIndexWalks   atomic.Int64
	activeStateIndex        struct {
		sync.Mutex
		byRoot map[string]activeStateIdentityIndex
	}
)

type activeStateIdentity struct {
	relative string
	info     os.FileInfo
}

type activeStateIdentityIndex struct {
	built time.Time
	files []activeStateIdentity
}

func activeStateIdentities(activeRoot string) []activeStateIdentity {
	activeStateIndex.Lock()
	defer activeStateIndex.Unlock()
	now := time.Now()
	if index, ok := activeStateIndex.byRoot[activeRoot]; ok && now.Sub(index.built) < activeStateIndexTTL {
		return index.files
	}
	for root, index := range activeStateIndex.byRoot {
		if now.Sub(index.built) >= activeStateIndexTTL {
			delete(activeStateIndex.byRoot, root)
		}
	}
	if activeStateIndex.byRoot == nil {
		activeStateIndex.byRoot = make(map[string]activeStateIdentityIndex)
	}
	files := walkActiveStateIdentities(activeRoot, now.Add(activeStateIndexBudget))
	activeStateIndex.byRoot[activeRoot] = activeStateIdentityIndex{built: now, files: files}
	return files
}

func walkActiveStateIdentities(activeRoot string, deadline time.Time) []activeStateIdentity {
	activeStateIndexWalks.Add(1)
	var files []activeStateIdentity
	visited := 0
	exhausted := func() bool {
		visited++
		return visited > activeStateIndexEntries || time.Now().After(deadline)
	}
	add := func(path, relative string) {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			files = append(files, activeStateIdentity{relative: relative, info: info})
		}
	}
	for _, name := range activeStateFiles {
		if exhausted() {
			return files
		}
		add(filepath.Join(activeRoot, name), name)
	}
	for _, tree := range activeStateTrees {
		stopped := false
		_ = filepath.WalkDir(filepath.Join(activeRoot, tree), func(path string, entry fs.DirEntry, walkErr error) error {
			if exhausted() {
				stopped = true
				return fs.SkipAll
			}
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			if relative, err := filepath.Rel(activeRoot, path); err == nil {
				add(path, filepath.ToSlash(relative))
			}
			return nil
		})
		if stopped {
			break
		}
	}
	return files
}

// actionPosixNestedShellMention scans each static shell -c or env -S body as
// its own command. bodies are the words it scanned without a match.
func actionPosixNestedShellMention(file *syntax.File, cwd, home string, depth int, stateOnly bool, globs *actionGlobs) (bodies []*syntax.Word, found bool) {
	if depth+1 >= 8 {
		return nil, false
	}
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
					if child, childStatic := StaticWord(call.Args[j+1], home); childStatic {
						if actionProtectedTargetMentionDepth(child, cwd, home, depth+1, stateOnly, globs) {
							found = true
							return false
						}
						bodies = append(bodies, call.Args[j+1])
					}
				}
			}
			if !posixShellProgram(base) && base != "ash" {
				continue
			}
			for j := i + 1; j+1 < len(call.Args); j++ {
				option, static := StaticWord(call.Args[j], home)
				if !static || !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
					break
				}
				switch option {
				case "-o", "+o", "-O", "+O", "--rcfile", "--init-file":
					j++ // This option consumes the next word (bash -O dotglob -c).
					continue
				}
				if option == "-c" || len(option) > 2 && !strings.HasPrefix(option, "--") &&
					!strings.ContainsAny(option, "=/") && strings.Contains(option[1:], "c") {
					if child, static := StaticWord(call.Args[j+1], home); static {
						if actionProtectedTargetMentionDepth(child, cwd, home, depth+1, stateOnly, globs) {
							found = true
						} else {
							bodies = append(bodies, call.Args[j+1])
						}
					}
					break
				}
			}
		}
		return !found
	})
	return bodies, found
}

// actionBlankWords replaces the bytes of each word with spaces.
func actionBlankWords(text string, words []*syntax.Word) string {
	if len(words) == 0 {
		return text
	}
	out := []byte(text)
	for _, word := range words {
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start < 0 || end > len(out) || start >= end {
			continue
		}
		for i := start; i < end; i++ {
			out[i] = ' '
		}
	}
	return string(out)
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

// actionWindowsTargetMention holds when the PowerShell reading or the plain
// reading of the command (actionWindowsPlainGrammar: Git Bash and cmd do not
// read PowerShell comments, smart quotes or the backtick) names a protected
// target (GAP-1500 refix 2).
func actionWindowsTargetMention(command, cwd, home string, depth int, stateOnly bool) bool {
	return actionWindowsTargetMentionAs(command, cwd, home, depth, stateOnly, 0) ||
		actionWindowsTargetMentionAs(command, cwd, home, depth, stateOnly, actionWindowsPlainGrammar)
}

func actionWindowsTargetMentionAs(command, cwd, home string, depth int, stateOnly bool, grammar actionWindowsGrammar) bool {
	if depth >= 8 || len(command) > MaxPayloadBytes {
		return false
	}
	command = actionWindowsBlankPatchText(command)
	// The argument to PowerShell -Command is parsed again by the child shell.
	// Quotes that are literal in the outer command do not stop expansion there.
	raw := actionWindowsScan(command, grammar)
	rawWords, rawOK := raw.words, raw.ok
	if rawOK && actionWindowsInvokedTextMention(rawWords, cwd, home, depth, stateOnly) {
		return true
	}
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
	// PowerShell does not expand variables inside single quoted literals:
	// the scanner keeps their $ from reading as a home variable, by the
	// quotes it reads (a quote in a comment or a smart quote no longer flips
	// the state, GAP-1779).
	scan := actionWindowsScan(command, grammar|actionWindowsLiteralDollar)
	words, ok := scan.words, scan.ok
	if !ok {
		// A command the scanner cannot read may still be read differently by
		// the shell that runs it (GAP-1500). Keep the class rule there, as the
		// POSIX text scan does, on the command as written (GAP-1779).
		return actionWindowsUnreadTargetMention(command, cwd, home, stateOnly)
	}
	if len(words) == 0 || depth == 0 && actionKnownReadOnlyWindows(words) {
		return false
	}
	skip := actionWindowsTextWords(scan, depth, strings.ContainsAny(command, "\r\n"))
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
	for _, span := range actionWindowsResolvedSpans(words, cwd, home) {
		for j, word := range span.words {
			if !skip[span.start+j] && actionWindowsWordMentionsTarget(word, effectiveCWD, home, stateOnly) {
				return true
			}
		}
		actionWindowsAdvanceDirectory(span.words, home, &effectiveCWD, &directoryStack)
	}
	for i, word := range words {
		if !skip[i] && actionWindowsWordMentionsTarget(word, cwd, home, stateOnly) {
			return true
		}
	}
	return false
}

// actionWindowsInvokedTextMention runs the scan on the text that
// Invoke-Expression (iex) runs, given as its argument or piped into it: the
// text is parsed again when it runs, so a $HOME that a single-quoted string
// or an @'...'@ here-string kept literal is expanded there (GAP-1523).
func actionWindowsInvokedTextMention(words []string, cwd, home string, depth int, stateOnly bool) bool {
	invoke := func(word string) bool {
		program := strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(word, `\`, "/"))), ".exe")
		return program == "iex" || program == "invoke-expression"
	}
	body := func(word string) string {
		if len(word) >= 2 && word[0] == '@' && word[len(word)-1] == '@' && strings.ContainsAny(word, "\r\n") {
			return word[1 : len(word)-1]
		}
		return word
	}
	for i, word := range words {
		if invoke(word) {
			for j := i + 1; j < len(words); j++ {
				if words[j] == ";" || words[j] == "|" || words[j] == "&" || words[j] == "&&" || words[j] == "||" {
					break
				}
				if strings.HasPrefix(words[j], "-") {
					continue
				}
				if actionWindowsTargetMention(body(words[j]), cwd, home, depth+1, stateOnly) {
					return true
				}
				break
			}
		}
		if i+2 < len(words) && words[i+1] == "|" && invoke(words[i+2]) &&
			actionWindowsTargetMention(body(word), cwd, home, depth+1, stateOnly) {
			return true
		}
	}
	return false
}

// actionWindowsTextWords marks the words the mention scan does not read as
// targets: every word of a top-level list element (between ;, &, && and
// ||) that is a known read pipeline with no redirect, because each
// statement is judged on its own targets (GAP-1799); a location change (cd,
// Push-Location ...) still counts, since it places the writes after it.
// It also rewrites the ~ of a quoted word (no $( subexpression) that is
// printed (Write-Output, echo, Write-Host ...) or given to git, in a
// command with no writer statement: PowerShell passes that text as written,
// and only a cmdlet path parameter or a redirect reads its ~ as the home
// (GAP-1473). An absolute or $HOME path in the same word still counts.
func actionWindowsTextWords(scan actionWindowsScanResult, depth int, multiline bool) []bool {
	words := scan.words
	skip := make([]bool, len(words))
	// The printed ~ is text only in a command whose statements all print,
	// read or run git: a writer elsewhere keeps the TGT-0194 mention rule.
	// The scanner does not split statements at a line end, so a command of
	// several lines is not text only.
	textOnly := !multiline
	for start, i := 0, 0; i <= len(words); i++ {
		if i < len(words) && words[i] != ";" && words[i] != "|" && words[i] != "||" && words[i] != "&" && words[i] != "&&" {
			continue
		}
		if i > start && !actionWindowsTextProgram(words[start]) && !actionKnownReadOnlyWindowsStatement(words[start:i]) {
			textOnly = false
		}
		start = i + 1
	}
	start := 0
	for i := 0; i <= len(words); i++ {
		if i < len(words) && words[i] != ";" && words[i] != "&" && words[i] != "&&" && words[i] != "||" {
			continue
		}
		if depth == 0 && i > start && actionKnownReadOnlyWindows(words[start:i]) && !actionWindowsLocationProgram(words[start]) {
			for j := start; j < i; j++ {
				skip[j] = true
			}
		}
		start = i + 1
	}
	start = 0
	for i := 0; i <= len(words); i++ {
		if i < len(words) && words[i] != ";" && words[i] != "|" && words[i] != "||" && words[i] != "&" && words[i] != "&&" {
			continue
		}
		if i > start && (actionWindowsTextProgram(words[start]) || actionWindowsNativeProgram(words[start])) {
			for j := start + 1; j < i; j++ {
				if !scan.quoted[j] || strings.Contains(words[j], "$(") || actionWindowsRedirectOperator(words[j-1]) != "" {
					continue
				}
				if actionWindowsTextProgram(words[start]) && textOnly {
					words[j] = strings.ReplaceAll(words[j], "~", "tilde-text")
				}
				// A quoted pattern given to a native program or printed is
				// the program's text: neither PowerShell nor Git Bash
				// expands it (GAP-1717: echo "*" and grep -rn "*** Begin
				// Patch" . from the home folder).
				words[j] = actionWindowsLiteralPattern.Replace(words[j])
			}
		}
		start = i + 1
	}
	return skip
}

func actionWindowsLocationProgram(word string) bool {
	switch strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(word, `\`, "/"))), ".exe") {
	case "cd", "chdir", "sl", "set-location", "pushd", "popd", "push-location", "pop-location":
		return true
	}
	return false
}

// actionWindowsBlankPatchText blanks, for the Windows target scan, the
// envelope text that apply_patch calls read (the POSIX scan does the same,
// actionBlankPatchBodies): content lines, the Begin and End markers and the
// "*** ... File:" directive words, whose *** is no path pattern. The
// directive paths stay and are scanned (GAP-1717: a Git Bash apply_patch
// heredoc from the home folder read *** as a glob that selects .ssh).
func actionWindowsBlankPatchText(command string) string {
	if !strings.Contains(command, patchBeginMarker) ||
		strings.Count(command, "\r") != strings.Count(command, "\r\n") {
		// PowerShell also ends a line at a lone CR, where the line-based
		// feed reading does not (GAP-1500): keep the text.
		return command
	}
	fed := patchFedLines(command)
	lines := strings.Split(command, "\n")
	if fed == nil || len(fed) != len(lines) {
		return command
	}
	for i, line := range lines {
		if fed[i] {
			trimmed := strings.TrimSpace(line)
			blanked := false
			for _, directive := range patchTargetDirectives {
				if strings.HasPrefix(trimmed, directive) {
					lines[i] = strings.Repeat(" ", len(line)-len(trimmed)+len(directive)) + trimmed[len(directive):]
					blanked = true
					break
				}
			}
			if !blanked {
				lines[i] = strings.Repeat(" ", len(line))
			}
			continue
		}
		for _, marker := range []string{patchBeginMarker, patchEndMarker} {
			lines[i] = strings.ReplaceAll(lines[i], marker, strings.Repeat(" ", len(marker)))
		}
	}
	return strings.Join(lines, "\n")
}

var actionWindowsLiteralPattern = strings.NewReplacer("*", "_", "?", "_", "[", "_", "]", "_")

// actionWindowsNativeProgram reports a program PowerShell runs as a native
// executable that is neither a shell nor an alias of a cmdlet: it receives a
// quoted word as text (grep, rg, git, python ...). Cmdlets and their aliases
// (cp, rm, ls, cat ...) expand a wildcard path themselves.
func actionWindowsNativeProgram(word string) bool {
	program := strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(word, `\`, "/"))), ".exe")
	if program == "" || strings.Contains(program, "-") || strings.ContainsAny(program, "$%&.@({") {
		return false
	}
	switch program {
	case "cp", "copy", "cpi", "mv", "move", "mi", "rm", "del", "erase", "ri", "rd", "rmdir", "ni", "mkdir", "md",
		"sc", "ac", "tee", "cat", "gc", "type", "ls", "dir", "gci", "cd", "sl", "chdir", "pushd", "popd", "ren", "rni",
		"iex", "icm", "start", "saps", "sajb", "select", "where", "foreach", "%", "?", "echo", "write", "set", "sv",
		"ft", "fl", "out", "sort", "measure", "compare", "diff", "curl", "wget", "iwr", "irm", "ii", "clc", "cli", "cpp", "gp", "sp",
		"bash", "sh", "zsh", "dash", "ksh", "wsl", "pwsh", "powershell", "cmd", "busybox", "env", "sudo", "xargs",
		"find", "nohup", "nice", "time", "timeout", "watch", "parallel", "apply_patch", "applypatch":
		return false
	}
	return true
}

func actionWindowsTextProgram(word string) bool {
	switch strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(word, `\`, "/"))), ".exe") {
	case "write-output", "echo", "write", "write-host", "write-information", "write-verbose",
		"write-warning", "write-debug", "write-error", "git":
		return true
	}
	return false
}

// actionWindowsUnreadTargetMention is the text scan of a command the Windows
// scanner cannot read. The text is cut at every separator character, quoted
// or not, so a statement that a misread quote hides is still checked. A
// protected-named word counts only in a piece that is not a plain read
// (a known read-only program with no redirect, as on the parsed path), and
// the bare .ssh directory alone does not count: reads and cd/ls/Test-Path of
// ~/.ssh stay allowed (GAP-1500 refix).
func actionWindowsUnreadTargetMention(command, cwd, home string, stateOnly bool) bool {
	effectiveCWD := cwd
	var directoryStack []string
	for _, piece := range strings.FieldsFunc(command, func(r rune) bool {
		return strings.ContainsRune(";|&\r\n", r)
	}) {
		fields := strings.Fields(piece)
		if len(fields) == 0 {
			continue
		}
		if strings.ContainsAny(piece, "<>") || !actionKnownReadOnlyWindowsStatement(fields) {
			for _, field := range fields {
				if actionWindowsWordNamesTarget(field, effectiveCWD, home, stateOnly, false) ||
					actionWindowsWordNamesTarget(field, cwd, home, stateOnly, false) {
					return true
				}
			}
		}
		actionWindowsAdvanceDirectory(fields, home, &effectiveCWD, &directoryStack)
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
	return actionWindowsWordNamesTarget(word, cwd, home, stateOnly, true)
}

// actionWindowsWordNamesTarget reports a protected-named word; sshDirectory
// also counts the bare .ssh directory.
func actionWindowsWordNamesTarget(word, cwd, home string, stateOnly, sshDirectory bool) bool {
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
			if strings.HasPrefix(resolved, root+"/") &&
				actionProtectedStateRelative(strings.TrimPrefix(resolved, root+"/")) {
				return true
			}
			if runtime.GOOS == "windows" {
				_, same := ResolveActiveStateHardlinkTarget(filepath.FromSlash(resolved), home)
				return same
			}
			return false
		}
		if resolved == root+"/.ssh" {
			return sshDirectory
		}
		protected, _ := actionWindowsProtected(candidate, cwd, home, false)
		return protected || actionWindowsLinkReachesKeyFile(resolved, home)
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

// actionWindowsLinkReachesKeyFile follows, on a native Windows host, the
// symbolic links and junctions of a resolved word (an alias in the cwd of
// authorized_keys, or a junction to ~\.ssh): the write lands in the file the
// links name (GAP-1515). Elsewhere the Windows file system is not there to
// read.
func actionWindowsLinkReachesKeyFile(resolved, home string) bool {
	if runtime.GOOS != "windows" || resolved == "" {
		return false
	}
	physical, ok := ResolveWriteTarget(filepath.FromSlash(resolved))
	if !ok || samePathName(physical, filepath.FromSlash(resolved)) {
		return false
	}
	for _, key := range ProtectedAuthorizedKeysPaths(home) {
		if samePathName(physical, key) {
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
		filepath.FromSlash(pattern), cwd, newProtectedFiles(home), filepath.Join(home, ".ssh"), home, nil) {
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
