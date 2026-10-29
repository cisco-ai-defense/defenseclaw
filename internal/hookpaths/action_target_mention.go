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
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
	return actionProtectedTargetMentionIn(command, cwd, home, depth, stateOnly, globs, "")
}

// actionProtectedTargetMentionIn is actionProtectedTargetMentionDepth with
// the gateway's shell dialect hint (actionWindowsTargetMention).
func actionProtectedTargetMentionIn(command, cwd, home string, depth int, stateOnly bool, globs *actionGlobs, dialect actionfacts.Dialect) bool {
	if command == "" || home == "" || len(command) > MaxPayloadBytes || depth >= 8 {
		return false
	}
	if depth == 0 {
		globs = globs.forCommand(command)
	}
	if actionWindowsHome(home) {
		return actionWindowsTargetMention(command, cwd, home, depth, stateOnly, dialect)
	}
	return actionPosixTargetMention(command, cwd, home, depth, stateOnly, globs)
}

// actionPosixTargetMention is the POSIX-grammar target scan. On a native
// Windows host it also reads a POSIX shell's command (Git Bash, MSYS) under
// a Windows home, on the Windows file system (ActionCommandDecisionWithDialectAndGlobFacts).
func actionPosixTargetMention(command, cwd, home string, depth int, stateOnly bool, globs *actionGlobs) bool {
	// spelledWindows: a Windows home this host cannot open (the gateway is
	// not on Windows). Its paths are judged by their spelling
	// (actionWindowsPath), as the Windows reading judges them (GAP-1504).
	spelledWindows := runtime.GOOS != "windows" && actionWindowsHome(home)
	if !spelledWindows && !filepath.IsAbs(cwd) && (!actionPosixWindowsHome(home) || !path.IsAbs(cwd)) {
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
		if !stateOnly && actionInterpreterBuildsKeyPath(file, cwd, home) {
			return true
		}
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	// base places a relative value: the effective cwd for a parsed word,
	// the request cwd for the text scan.
	// Git Bash spells a Windows drive /c/... (GAP-0781 RV8-1).
	windowsHost := runtime.GOOS == "windows" && actionWindowsHome(home)
	checkValue := func(value string, tilde bool, base string) bool {
		if len(value) == 0 || len(value) > MaxWriteTargetPathBytes {
			return false
		}
		if windowsHost {
			value = actionMSYSDrivePath(value)
		}
		if spelledWindows {
			return actionSpelledWindowsTarget(value, tilde, base, home, stateOnly)
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
		// $USER and $LOGNAME name the home's own directory, as
		// actionfacts reads /home/$USER/... (GAP-2269).
		user := filepath.Base(home)
		values := actionValues{"HOME": home, "PWD": cwd, "USER": user, "LOGNAME": user}
		found := false
		effectiveCWD := cwd
		var directoryStack []string
		var movedOntoLinks []*syntax.Word
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
				var moved *syntax.Word
				var movedEntry string
				if !stateOnly {
					// A plain mv onto a link replaces the link: judge its
					// entry, not the file it names (GAP-2559).
					if word, entry, ok := actionPlainMoveOntoLink(call, values, effectiveCWD, home); ok {
						moved, movedEntry = word, entry
						movedOntoLinks = append(movedOntoLinks, word)
					}
				}
				for _, word := range call.Args {
					if moved != nil && word == moved {
						if protectedEntry(movedEntry, protected, ssh) {
							found = true
							return false
						}
						continue
					}
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
		// The text scan below would follow the link the move replaces.
		nestedBodies = append(nestedBodies, movedOntoLinks...)
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

// actionInterpreterSSHName and actionInterpreterKeysName match the two
// protected names of an authorized-keys path in inline interpreter code.
// Code that names both and has an executable writer is a protected target
// in action mode however it joins them: an f-string, +, os.path.join,
// pathlib, str.format, % formatting, Perl's . operator or a .ssh directory
// variable joined later (GAP-1732, GAP-2005, the GAP-0475 class).
var (
	actionInterpreterSSHName  = regexp.MustCompile(`\.ssh\b`)
	actionInterpreterKeysName = regexp.MustCompile(`\bauthorized_keys2?\b`)
)

// actionInterpreterHomeCall matches the home spellings that the
// interpreter-path proof judges with its binding rules (Path.home(),
// expanduser: GAP-0475, a path bound again before the write, GAP-1299).
// Such code is allowed only when that proof places every write on an
// ordinary path; a home call elsewhere in the code proves nothing (GAP-2005).
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
// whose code names an authorized-keys path and has a write. The interpreter
// may be run through a wrapper program (env, command, nice, timeout, ...)
// and may have other options before its code option (GAP-2005 RV9-1).
func actionInterpreterBuildsKeyPath(file *syntax.File, cwd, home string) bool {
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
		// A word the hook cannot spell stays "": never an option, never code.
		words := []string{program}
		for _, word := range call.Args[1:] {
			value, _ := StaticWord(word, home)
			words = append(words, value)
		}
		at := actionInterpreterProgramIndex(words)
		if at < 0 {
			return true
		}
		if code, ok := actionInterpreterInlineCode(words, at); ok &&
			actionInterpreterKeyPathCode(code, actionInterpreterKind(words[at]), cwd, home) {
			found = true
		}
		return !found
	})
	return found
}

// actionInterpreterKeyPathCode reports inline code that names both
// authorized-keys path parts and has an executable writer, unless the
// binding rules place every write of home-call code on an ordinary path.
func actionInterpreterKeyPathCode(code, language, cwd, home string) bool {
	return actionInterpreterSSHName.MatchString(code) && actionInterpreterKeysName.MatchString(code) &&
		actionInterpreterCodeWrites(code, language) && !actionInterpreterHomeWriteProved(code, language, cwd, home)
}

// actionInterpreterKind names the interpreter family of a program word:
// python (python, python3*, py), node (node, nodejs), perl or ruby; ""
// for any other program.
func actionInterpreterKind(word string) string {
	switch base := programBase(strings.ReplaceAll(word, `\`, "/")); {
	case base == "py" || base == "python" || strings.HasPrefix(base, "python3"):
		return "python"
	case base == "node" || base == "nodejs":
		return "node"
	case base == "perl" || base == "ruby":
		return base
	}
	return ""
}

// actionInterpreterWrappers run their operand words as a command.
var actionInterpreterWrappers = map[string]bool{
	"env": true, "command": true, "exec": true, "builtin": true, "nice": true, "timeout": true,
	"nohup": true, "stdbuf": true, "xargs": true, "time": true, "ionice": true, "setsid": true,
	"chrt": true, "taskset": true, "unbuffer": true, "sudo": true, "doas": true, "caffeinate": true,
}

// actionInterpreterProgramIndex returns the index of the interpreter a POSIX
// call runs: the program word itself, or the first interpreter word after a
// wrapper program and its options, NAME=value words and option values; -1
// when the call runs no interpreter.
func actionInterpreterProgramIndex(words []string) int {
	if actionInterpreterKind(words[0]) != "" {
		return 0
	}
	if !actionInterpreterWrappers[programBase(words[0])] {
		return -1
	}
	for i := 1; i < len(words); i++ {
		if actionInterpreterKind(words[i]) != "" {
			return i
		}
	}
	return -1
}

// actionInterpreterInlineCode returns the inline code of the interpreter at
// words[at]: the word after its code option, past the interpreter's other
// options and the values of the options that take one (python -X/-W, node
// -r/--require/--import/--loader, perl -I/-M/-m, ruby -I/-r), so an extra
// option before the code does not hide it (GAP-2005 RV9-1).
func actionInterpreterInlineCode(words []string, at int) (string, bool) {
	kind := actionInterpreterKind(words[at])
	for j := at + 1; j+1 < len(words); j++ {
		option := words[j]
		if !strings.HasPrefix(option, "-") || option == "-" || option == "--" || kind == "python" && option == "-m" {
			return "", false
		}
		if actionWindowsInterpreterCodeOption(kind, option) {
			return words[j+1], true
		}
		if actionInterpreterOptionTakesValue(kind, option) {
			j++
		}
	}
	return "", false
}

// actionInterpreterOptionTakesValue reports an interpreter option whose
// value is the next word.
func actionInterpreterOptionTakesValue(kind, option string) bool {
	switch kind {
	case "python":
		// --check-hash-based-pycs is the one long python option with a value.
		return option == "-X" || option == "-W" || option == "-Q" || option == "--check-hash-based-pycs"
	case "node":
		switch option {
		case "-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions",
			"--input-type", "--env-file", "--title":
			return true
		}
	case "perl":
		return option == "-I" || option == "-M" || option == "-m"
	case "ruby":
		return option == "-I" || option == "-r" || option == "-C" || option == "-E"
	}
	return false
}

// actionInterpreterHomeWriteProved reports home-call code whose every write
// the interpreter-path binding rules place on an ordinary path.
func actionInterpreterHomeWriteProved(code, language, cwd, home string) bool {
	if !actionInterpreterHomeCall.MatchString(code) {
		return false
	}
	class, _ := unprovenInterpreterCode(code, language, cwd, home, true)
	return class == ""
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
	staticNames, static := actionStaticCallWords(file)
	if !static {
		// A program word the hook cannot spell (an expansion, a command
		// substitution, an indirect name), eval, source or a quoted handler
		// can call any function: every body is scanned (classifier RV3-2).
		return nil
	}
	uncalled := make(map[*syntax.FuncDecl]bool)
	for _, decl := range decls {
		name := decl.Name.Value
		if staticNames[name] {
			continue // called through another spelling, such as f\oo or fo""o
		}
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
	if len(uncalled) > 0 && actionEvaluatesRuntimeNames(file, uncalled) {
		// bash evaluates a string as code or arithmetic here, and a
		// subscript such as a[$(f""oo)] runs a command substitution that
		// can call any function: every body is scanned (GAP-2089).
		return nil
	}
	return uncalled
}

// actionEvaluatesRuntimeNames reports whether the command, outside its
// uncalled function bodies, has a construct in which bash evaluates a string
// that the command does not spell as a call: an arithmetic expansion,
// command or loop, let, a [[ ]] arithmetic or -v test, an indirect,
// subscripted, sliced or @-transformed parameter expansion, an assignment
// with a subscript or to a prompt variable, a declaration with options, and
// the builtins that take a variable name or a callback (mapfile -C, read,
// printf -v, test -v ...). Plain $name expansions only expand (GAP-2089).
func actionEvaluatesRuntimeNames(file *syntax.File, uncalled map[*syntax.FuncDecl]bool) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if uncalled[node] {
				return false // never runs
			}
		case *syntax.ArithmExp, *syntax.ArithmCmd, *syntax.LetClause, *syntax.CStyleLoop:
			found = true
		case *syntax.BinaryTest:
			switch node.Op {
			case syntax.TsEql, syntax.TsNeq, syntax.TsLeq, syntax.TsGeq, syntax.TsLss, syntax.TsGtr:
				found = true
			}
		case *syntax.UnaryTest:
			found = node.Op == syntax.TsVarSet || node.Op == syntax.TsRefVar
		case *syntax.ParamExp:
			found = node.Excl || node.Slice != nil || node.NestedParam != nil || !actionPlainSubscript(node.Index) ||
				(node.Exp != nil && node.Exp.Op == syntax.OtherParamOps)
		case *syntax.Assign:
			if !actionPlainSubscript(node.Index) {
				found = true
			} else if node.Name != nil {
				switch node.Name.Value {
				case "PS0", "PS1", "PS2", "PS3", "PS4", "PROMPT_COMMAND",
					"PROMPT", "PROMPT2", "PROMPT3", "PROMPT4", "RPROMPT", "RPROMPT2", "RPS1", "RPS2", "SPROMPT":
					found = true
				}
			} else if node.Value != nil {
				// declare -i, local -n, typeset -a ...: an option word.
				value, fixed := StaticWord(node.Value, "")
				found = !fixed || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "+")
			}
		case *syntax.ArrayElem:
			found = !actionPlainSubscript(node.Index)
		case *syntax.ExtGlob:
			// zsh reads *(e:code:) and *(+name) as glob qualifiers that
			// run code for every file (RV5-1).
			found = true
		case *syntax.Word:
			// A static word that holds a command substitution is code
			// for whatever evaluates it: zsh print -P with promptsubst,
			// ${(e)...}, zstyle -e, a later eval (RV5-1).
			if value, fixed := StaticWord(node, ""); fixed && (strings.Contains(value, "$(") || strings.Contains(value, "`") ||
				actionZshQualifierText.MatchString(value)) {
				found = true
			}
			// zsh $~name, ${~name} and ${(~)name} glob a value at run
			// time, and a qualifier in it can run any function (RV6-1).
			if actionZshGlobSubstWord(node) {
				found = true
			}
		case *syntax.DeclClause:
			found = node.Variant != nil && node.Variant.Value == "nameref"
		case *syntax.CallExpr:
			found = actionCallEvaluatesNames(node.Args)
		}
		return !found
	})
	return found
}

// actionZshQualifierText matches a string that holds a zsh glob qualifier
// that runs code for every file: a pattern followed by (e:code:),
// (e'code'), (+name) or a longer qualifier list such as (.e:code:)
// (RV6-1). Prose such as "see (e.g. x)" has a space before the paren.
var actionZshQualifierText = regexp.MustCompile(`[^\s(]\([^()\s]*(?:e[^A-Za-z0-9_\s()]|\+[A-Za-z_])`)

// actionZshGlobSubstWord reports a word with a zsh glob-subst expansion:
// $~name, ${~name} or a ${(...~...)name} flag list. The bash parser reads
// $~ as literal text, so the raw literal is checked as well (RV6-1).
func actionZshGlobSubstWord(word *syntax.Word) bool {
	found := false
	syntax.Walk(word, func(node syntax.Node) bool {
		if found {
			return false
		}
		if lit, ok := node.(*syntax.Lit); ok && (strings.Contains(lit.Value, "$~") || strings.Contains(lit.Value, "${~") ||
			strings.Contains(lit.Value, "${(")) {
			found = true
		}
		return !found
	})
	return found
}

// actionPlainSubscript reports a missing subscript or one bash does not
// evaluate as an expression: a number, @ or *.
func actionPlainSubscript(index syntax.ArithmExpr) bool {
	if index == nil {
		return true
	}
	word, ok := index.(*syntax.Word)
	if !ok {
		return false
	}
	value, fixed := StaticWord(word, "")
	if !fixed || value == "" {
		return false
	}
	if value == "@" || value == "*" {
		return true
	}
	return strings.Trim(value, "0123456789") == ""
}

// actionCallEvaluatesNames reports a call of a builtin that evaluates a
// variable name (with its subscript) or runs a callback it is given.
func actionCallEvaluatesNames(args []*syntax.Word) bool {
	for i := 0; i < len(args); i++ {
		program, fixed := StaticWord(args[i], "")
		if !fixed {
			return false // a run-time program word is actionStaticCallWords' case
		}
		switch programBase(program) {
		case "builtin", "command":
			for i+1 < len(args) {
				option, fixed := StaticWord(args[i+1], "")
				if !fixed || !strings.HasPrefix(option, "-") {
					break
				}
				i++
			}
			continue
		case "mapfile", "readarray", "let", "read", "unset", "getopts", "wait", "fc", "sched", "zstyle", "zle",
			"declare", "typeset", "local", "export", "readonly":
			return true
		case "printf":
			if i+1 < len(args) {
				option, fixed := StaticWord(args[i+1], "")
				return !fixed || strings.HasPrefix(option, "-v")
			}
		case "print":
			// zsh print -P expands prompt escapes (with promptsubst, a
			// command substitution) and print -v assigns a name (RV5-1).
			for _, arg := range args[i+1:] {
				option, fixed := StaticWord(arg, "")
				if !fixed {
					return true
				}
				if option == "--" || option == "-" || !strings.HasPrefix(option, "-") {
					break
				}
				if strings.ContainsAny(option, "Pv") {
					return true
				}
			}
		case "test", "[":
			for _, arg := range args[i+1:] {
				value, fixed := StaticWord(arg, "")
				if !fixed || value == "-v" || value == "-R" {
					return true
				}
			}
		}
		return false
	}
	return false
}

// actionStaticCallWords lists the static values of the words of every call
// and declaration in file. It reports false when a function could run under
// a name the command does not spell: a program word that is not static, an
// eval, source or . call, or a trap, alias, bind or complete argument that is
// not static or carries shell quoting, escapes or expansions.
func actionStaticCallWords(file *syntax.File) (map[string]bool, bool) {
	names := make(map[string]bool)
	static := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !static {
			return false
		}
		switch node := node.(type) {
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				return true
			}
			program, fixed := StaticWord(node.Args[0], "")
			if !fixed {
				static = false
				return false
			}
			switch programBase(program) {
			case "eval", "source", ".":
				static = false
				return false
			}
			names[program] = true
			code := false
			switch programBase(program) {
			case "trap", "alias", "bind", "complete", "compgen":
				code = true
			}
			for _, arg := range node.Args[1:] {
				value, fixed := StaticWord(arg, "")
				if code && (!fixed || strings.ContainsAny(value, "'\"\\$`")) {
					static = false
					return false
				}
				if fixed {
					names[value] = true
				}
			}
		case *syntax.DeclClause:
			for _, assign := range node.Args {
				if assign.Name != nil {
					names[assign.Name.Value] = true
				}
				if assign.Value == nil {
					continue
				}
				value, fixed := StaticWord(assign.Value, "")
				if !fixed && assign.Name == nil {
					static = false // export -f "$name" exports any function
					return false
				}
				if fixed {
					names[value] = true
				}
			}
		}
		return true
	})
	return names, static
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
			"pushd", "popd", "dirs", "pwd", "true", "false", "test", "[", "basename", "dirname",
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
			directory, err := actionGlobOpenDir(dir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && !hidden || errors.Is(err, syscall.ENOTDIR) || actionGlobInvalidName(err) {
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

// actionGlobOpenDir opens a directory the walk lists. Windows refuses a
// name that holds a character its file names cannot hold (", <, >, |, :
// past the volume, a control character) with ERROR_INVALID_NAME. Git Bash
// (MSYS/Cygwin) stores such a character as U+F000 plus its code, so the
// shell's own expansion reads that spelling: it is tried before the walk
// concludes that the name names no directory (GAP-0781 RV7-1).
func actionGlobOpenDir(dir string) (*os.File, error) {
	directory, err := os.Open(dir)
	if err == nil || !actionGlobInvalidName(err) {
		return directory, err
	}
	if mapped := actionMSYSMappedPath(dir); mapped != dir {
		if alias, mappedErr := os.Open(mapped); mappedErr == nil || !errors.Is(mappedErr, fs.ErrNotExist) && !actionGlobInvalidName(mappedErr) {
			return alias, mappedErr
		}
	}
	return nil, err
}

// actionGlobInvalidName reports a Windows refusal of the name itself
// (ERROR_INVALID_NAME): no file or directory can have it, so the user's
// shell expands nothing there either. Such a word is program text that a
// mention scan split at a slash (glob.glob("data/*.csv"), "src"/*.py),
// not a directory that this process failed to see.
func actionGlobInvalidName(err error) bool {
	const errorInvalidName = syscall.Errno(123)
	return runtime.GOOS == "windows" && errors.Is(err, errorInvalidName)
}

// actionMSYSMappedPath spells the components after the volume the way
// Cygwin and MSYS store the characters Windows names cannot hold.
func actionMSYSMappedPath(dir string) string {
	volume := filepath.VolumeName(dir)
	var b strings.Builder
	b.WriteString(volume)
	for _, r := range dir[len(volume):] {
		if r < 0x20 || strings.ContainsRune(`"*:<>?|`, r) {
			r += 0xF000
		}
		b.WriteRune(r)
	}
	return b.String()
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
	// The entry itself is state even when it is a link the user made to a
	// file elsewhere: a move or rename onto it replaces the state entry.
	// Its directory is followed and its name kept, so mv a.txt /ext/y/
	// config.yaml with y -> ~/.defenseclaw names the entry when config.yaml
	// links out of the tree, as it does when config.yaml is a file (GAP-2560).
	if actionStateEntryMayDiffer(value) {
		if name := filepath.Base(value); name != "." && name != ".." && name != string(filepath.Separator) {
			if parent, ok := ResolveWriteTarget(filepath.Dir(value)); ok {
				relative, err := filepath.Rel(activeHome, filepath.Join(parent, name))
				if err == nil && actionProtectedStateRelative(filepath.ToSlash(relative)) {
					return true
				}
			}
		}
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
	status := map[string]bool{"?": true}
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
		if len(call.Args) == 0 && actionExitStatusAssignment(call) {
			// status=$? of an agent's exit-status wrapper (GAP-2168).
			for _, assign := range call.Assigns {
				status[assign.Name.Value] = true
			}
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
		switch programBase(program) {
		case "echo", "printf", "exit":
			// An agent's exit-status report (Codex: cmd; status=$?; printf
			// '\n[exit status] %s\n' "$status"; exit "$status") prints the
			// status to the terminal only: no redirect (checked above), a $?
			// or status word and no protected name in its text. Any other
			// echo stays outside the read-only list.
			if actionStatusReport(call.Args[1:], status) {
				return true
			}
		}
		seen = true
		for _, arg := range call.Args[1:] {
			if option, known := StaticWord(arg, home); known && actionReadOptionMayWrite(option) {
				safe = false
				return false
			}
		}
		switch programBase(program) {
		case "cat", "head", "tail", "ls", "dir", "stat",
			// Search and count programs only read their operands (owner
			// decision 2, TGT-0194; GAP-2168).
			"grep", "egrep", "fgrep", "wc":
		case "ssh-keygen":
			if !actionSSHKeygenListsOnly(call.Args[1:], home) {
				safe = false
			}
		case "cd", "pushd", "popd":
			if len(call.Args) > 3 {
				safe = false
			}
		case "dirs":
			// dirs prints or clears the directory stack (GAP-2552).
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

// actionExitStatusAssignment reports a bare NAME=$? assignment: it keeps the
// previous command's exit status and changes no file or program lookup.
func actionExitStatusAssignment(call *syntax.CallExpr) bool {
	if len(call.Assigns) == 0 {
		return false
	}
	for _, assign := range call.Assigns {
		if assign.Name == nil || assign.Append || assign.Naked || assign.Index != nil || assign.Array != nil ||
			assign.Value == nil || len(assign.Value.Parts) != 1 {
			return false
		}
		switch strings.ToUpper(assign.Name.Value) {
		case "PATH", "IFS", "HOME", "ENV", "BASH_ENV", "CDPATH", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND":
			return false
		}
		param, ok := assign.Value.Parts[0].(*syntax.ParamExp)
		if !ok || param.Param == nil || param.Param.Value != "?" || param.Excl || param.Length || param.Index != nil ||
			param.Slice != nil || param.Repl != nil || param.Exp != nil || len(param.Modifiers) != 0 {
			return false
		}
	}
	return true
}

// actionStatusReport reports echo, printf or exit words that report an exit
// status: at least one word expands $? or a NAME=$? variable, every
// expansion is such a plain parameter (no command substitution), and the
// literal text names no protected place (.ssh, authorized_keys,
// .defenseclaw) and no home spelling, so printing it is not a mention.
func actionStatusReport(args []*syntax.Word, status map[string]bool) bool {
	if len(args) == 0 || len(args) > 4 {
		return false
	}
	reports, clean := false, true
	for _, arg := range args {
		var text strings.Builder
		syntax.Walk(arg, func(node syntax.Node) bool {
			switch node := node.(type) {
			case nil, *syntax.Word, *syntax.DblQuoted:
				// syntax.Walk calls f(nil) after a node's children.
			case *syntax.Lit:
				text.WriteString(node.Value)
			case *syntax.SglQuoted:
				text.WriteString(node.Value)
			case *syntax.ParamExp:
				if node.Param == nil || !status[node.Param.Value] || node.Exp != nil || node.Repl != nil ||
					node.Slice != nil || node.Index != nil || node.Excl || node.Length {
					clean = false
					return false
				}
				reports = true
				return false
			default:
				clean = false
				return false
			}
			return true
		})
		lower := strings.ToLower(text.String())
		if strings.Contains(lower, ".ssh") || strings.Contains(lower, "authorized_keys") ||
			strings.Contains(lower, ".defenseclaw") || strings.Contains(lower, "~") {
			clean = false
		}
	}
	return reports && clean
}

// actionSSHKeygenListsOnly reports an ssh-keygen call that only lists key
// fingerprints (-l, with -f FILE, -E HASH, -v, -q): it reads the file and
// writes nothing. Any other mode (-R, -t, -p, -y, -s, ...) is not a plain
// read (GAP-2168).
func actionSSHKeygenListsOnly(args []*syntax.Word, home string) bool {
	list := false
	for index := 0; index < len(args); index++ {
		word, known := StaticWord(args[index], home)
		if !known || len(word) < 2 || word[0] != '-' || word[1] == '-' {
			return false
		}
		flags := word[1:]
		for at := 0; at < len(flags); at++ {
			switch flags[at] {
			case 'l':
				list = true
			case 'v', 'q':
			case 'f', 'E':
				if at == len(flags)-1 {
					index++
					if index >= len(args) {
						return false
					}
				}
				at = len(flags)
			default:
				return false
			}
		}
	}
	return list
}

// actionSSHKeygenListsOnlyWords is actionSSHKeygenListsOnly for the words of
// a Windows reading: -l with only -v, -q, -f FILE and -E HASH lists keys.
func actionSSHKeygenListsOnlyWords(args []string) bool {
	list := false
	for index := 0; index < len(args); index++ {
		word := args[index]
		if len(word) < 2 || word[0] != '-' || word[1] == '-' {
			return false
		}
		flags := word[1:]
		for at := 0; at < len(flags); at++ {
			switch flags[at] {
			case 'l':
				list = true
			case 'v', 'q':
			case 'f', 'E':
				if at == len(flags)-1 {
					index++
					if index >= len(args) {
						return false
					}
				}
				at = len(flags)
			default:
				return false
			}
		}
	}
	return list
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
//
// A dialect hint never drops a reading that may write a protected target
// (lead decision on GAP-1504). It names the reading the shell makes: the
// PowerShell grammar for a PowerShell hint, the POSIX grammar for a POSIX
// hint (ActionCommandDecisionWithDialectAndGlobFacts), whose mention rules
// (TGT-0194) hold as they are. Another reading counts unless it only prints
// or reads and redirects into no protected target
// (actionWindowsReadingWritesNothing): a path that is only printed there is
// not a write, so Git Bash echo \$HOME/.ssh/authorized_keys and a PowerShell
// comment are not blocked by the reading of a shell that does not run them.
func actionWindowsTargetMention(command, cwd, home string, depth int, stateOnly bool, dialect actionfacts.Dialect) bool {
	for _, grammar := range []actionWindowsGrammar{0, actionWindowsPlainGrammar} {
		if !actionWindowsTargetMentionAs(command, cwd, home, depth, stateOnly, grammar) {
			continue
		}
		hinted := dialect == actionfacts.DialectPOSIX || dialect == actionfacts.DialectPowerShell && grammar != 0
		if !hinted || !actionWindowsReadingWritesNothing(command, cwd, home, grammar, dialect) {
			return true
		}
	}
	return false
}

// actionWindowsReadingWritesNothing holds when, in this reading, every
// statement prints or reads (actionWindowsTextStatement,
// actionKnownReadOnlyWindowsStatement) with no nested command or script
// block, and every output redirect names no protected target.
func actionWindowsReadingWritesNothing(command, cwd, home string, grammar actionWindowsGrammar, dialect actionfacts.Dialect) bool {
	scan := actionWindowsScan(actionWindowsBlankPatchText(command), grammar|actionWindowsLiteralDollar)
	if !scan.ok || len(scan.words) == 0 {
		// A POSIX-hinted command that the POSIX grammar reads completely
		// runs in that shell; a Windows reading the scanner cannot read is
		// then not a shell that runs it (the GAP-1500 fallback is for
		// commands PowerShell runs).
		if dialect != actionfacts.DialectPOSIX {
			return false
		}
		_, parsed := parseShell(command)
		return parsed
	}
	words := scan.words
	var statement []string
	end := func() bool {
		if len(statement) == 0 {
			return true
		}
		for _, word := range statement {
			// ( and { open a subexpression, subshell or script block. A
			// PowerShell backtick only escapes; in the plain reading a pair
			// of backticks is a Git Bash command substitution.
			if strings.ContainsAny(word, "({") || grammar&actionWindowsPlainGrammar != 0 && strings.Count(word, "`") >= 2 {
				return false
			}
		}
		ok := actionWindowsTextStatement(statement) || actionKnownReadOnlyWindowsStatement(statement)
		statement = statement[:0]
		return ok
	}
	for i := 0; i < len(words); i++ {
		word := words[i]
		switch word {
		case ";", "|", "||", "&", "&&":
			if !end() {
				return false
			}
			continue
		}
		if operator := actionWindowsRedirectOperator(word); operator != "" {
			if i+1 >= len(words) {
				break // A redirect with no target writes no file.
			}
			i++
			if operator[0] == '>' && actionWindowsWordMentionsTarget(words[i], cwd, home, false) {
				return false
			}
			continue
		}
		statement = append(statement, word)
	}
	return end()
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
						actionWindowsTargetMention(rawWords[j+1], cwd, home, depth+1, stateOnly, "") {
						return true
					}
				}
			}
			if posixShellProgram(program) || program == "ash" {
				if actionWindowsPOSIXShellMention(rawWords[i+1:], cwd, home, depth, stateOnly) {
					return true
				}
				continue
			}
			if program != "pwsh" && program != "powershell" {
				continue
			}
			for j := i + 1; j+1 < len(rawWords); j++ {
				if rawWords[j] == ";" || rawWords[j] == "|" || rawWords[j] == "&" {
					break
				}
				if strings.EqualFold(rawWords[j], "-command") || strings.EqualFold(rawWords[j], "-c") {
					if actionWindowsTargetMention(rawWords[j+1], cwd, home, depth+1, stateOnly, actionfacts.DialectPowerShell) {
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
		if actionWindowsTargetMention(string(utf16.Decode(letters)), cwd, home, depth+1, stateOnly, actionfacts.DialectPowerShell) {
			return true
		}
	}
	if !stateOnly && actionWindowsInterpreterBuildsKeyPath(words, cwd, home) {
		return true
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

// actionWindowsPOSIXShellMention reads the script that a POSIX shell (Git
// Bash, MSYS sh) runs with -c as that shell reads it, on the Windows file
// system (ActionCommandDecisionWithDialectAndGlobFacts): quote removal, ~, $HOME and
// ${HOME}, cd tracking and the MSYS /c/ drive spelling. The Windows reading
// keeps the script's own quotes and operators inside its words, so a key
// target spelled "$HOME"/.ssh/authorized_k*, k>/c/Users/u/.ssh/... or
// cd ~ && cp k .ssh/authorized_k* named no file there (GAP-0781 RV8-1).
// words are the words after the shell program.
func actionWindowsPOSIXShellMention(words []string, cwd, home string, depth int, stateOnly bool) bool {
	if depth+1 >= 8 {
		return false
	}
	for j := 0; j+1 < len(words); j++ {
		option := words[j]
		if !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
			return false
		}
		switch option {
		case "-o", "+o", "-O", "+O", "--rcfile", "--init-file":
			j++ // This option consumes the next word (bash -O dotglob -c).
			continue
		}
		if option == "-c" || len(option) > 2 && !strings.HasPrefix(option, "--") &&
			!strings.ContainsAny(option, "=/") && strings.Contains(option[1:], "c") {
			script := actionWindowsHereStringBody(words[j+1])
			return actionPosixTargetMention(script, cwd, home, depth+1, stateOnly, (*actionGlobs)(nil).forCommand(script)) ||
				!stateOnly && actionConcreteProtectedWriteOn(script, cwd, home, true)
		}
	}
	return false
}

// actionWindowsInterpreterBuildsKeyPath is actionInterpreterBuildsKeyPath
// for the Windows readings: python -c, node -e/-p, perl -e/-E and ruby -e
// code that names both key-path parts and has an executable writer is a
// protected target however it joins them, unless the binding rules place
// every write of home-call code on an ordinary path. The class rule ran
// only in the POSIX grammar, so PowerShell python -c/node -e key writes
// were allowed (GAP-2005 RV8-2).
func actionWindowsInterpreterBuildsKeyPath(words []string, cwd, home string) bool {
	for i := 0; i+2 < len(words); i++ {
		language := actionInterpreterKind(words[i])
		if language == "" {
			continue
		}
		if code, ok := actionInterpreterInlineCode(words, i); ok &&
			actionInterpreterKeyPathCode(code, language, cwd, home) {
			return true
		}
	}
	return false
}

// actionWindowsInterpreterCodeOption reports the option whose next word is
// the inline code: python -c (or a flag cluster ending in c), node -e,
// --eval, -p, --print, perl -e/-E (or a cluster ending in e/E), ruby -e.
func actionWindowsInterpreterCodeOption(language, option string) bool {
	// A flag cluster (-Ic, -we, -ne) ends in the code option; a cluster that
	// starts with a value option (-Wstatic, -Iinclude, -rjson) does not.
	cluster := len(option) > 2 && !strings.HasPrefix(option, "--") && strings.Trim(option[1:],
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") == ""
	switch language {
	case "python":
		return option == "-c" || cluster && strings.HasSuffix(option, "c") && !strings.ContainsAny(option[1:2], "XWQ")
	case "node", "nodejs":
		return option == "-e" || option == "--eval" || option == "-p" || option == "--print" || option == "-pe"
	case "perl":
		return option == "-e" || option == "-E" || cluster && (strings.HasSuffix(option, "e") || strings.HasSuffix(option, "E")) &&
			!strings.ContainsAny(option[1:2], "IMmxCdD")
	case "ruby":
		return option == "-e" || cluster && strings.HasSuffix(option, "e") && !strings.ContainsAny(option[1:2], "IrCExFK")
	}
	return false
}

// actionWindowsHereStringBody returns the text of an @'...'@ or @"..."@
// word as the scanner keeps it (the @ marks around the body).
func actionWindowsHereStringBody(word string) string {
	if len(word) >= 2 && word[0] == '@' && word[len(word)-1] == '@' && strings.ContainsAny(word, "\r\n") {
		return word[1 : len(word)-1]
	}
	return word
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
	body := actionWindowsHereStringBody
	for i, word := range words {
		if invoke(word) {
			for j := i + 1; j < len(words); j++ {
				if words[j] == ";" || words[j] == "|" || words[j] == "&" || words[j] == "&&" || words[j] == "||" {
					break
				}
				if strings.HasPrefix(words[j], "-") {
					continue
				}
				if actionWindowsTargetMention(body(words[j]), cwd, home, depth+1, stateOnly, actionfacts.DialectPowerShell) {
					return true
				}
				break
			}
		}
		if i+2 < len(words) && words[i+1] == "|" && invoke(words[i+2]) &&
			actionWindowsTargetMention(body(word), cwd, home, depth+1, stateOnly, actionfacts.DialectPowerShell) {
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
		if i > start && !actionWindowsTextStatement(words[start:i]) && !actionKnownReadOnlyWindowsStatement(words[start:i]) {
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
			pattern := start + actionWindowsSearchPatternWord(words[start:i])
			for j := start + 1; j < i; j++ {
				if !scan.quoted[j] || strings.Contains(words[j], "$(") || actionWindowsRedirectOperator(words[j-1]) != "" {
					continue
				}
				if actionWindowsTextProgram(words[start]) && textOnly {
					words[j] = strings.ReplaceAll(words[j], "~", "tilde-text")
				}
				// A quoted pattern that is printed, given to a git command
				// that keeps it as text (not a -c or config value, RV5-2)
				// or is the pattern of a search tool is text: nothing expands it
				// (GAP-1717: echo "*" and grep -rn "*** Begin Patch" . from
				// the home folder). Other native programs (the MSYS tools
				// of Git for Windows) expand a quoted word of their own
				// argv, so it stays a path pattern (GAP-1984).
				if (actionWindowsTextStatement(words[start:i]) && !actionWindowsGitPathspecWord(words[start:i], j-start)) || j == pattern {
					words[j] = actionWindowsLiteralPattern.Replace(words[j])
				}
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

// actionWindowsSearchPatternWord returns the index in words of the pattern
// argument of a search tool (grep, rg, findstr ...): the word after -e or
// --regexp, else the first word that is not an option. It returns -1 for
// any other program (GAP-1984).
func actionWindowsSearchPatternWord(words []string) int {
	if len(words) == 0 {
		return -1
	}
	tool := strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(words[0], `\`, "/"))), ".exe")
	switch tool {
	case "grep", "egrep", "fgrep", "rg", "ag", "ack", "findstr":
	default:
		return -1
	}
	for k := 1; k < len(words); k++ {
		switch word := words[k]; {
		case word == "--":
			if k+1 < len(words) {
				return k + 1
			}
			return -1
		case word == "-e" || word == "--regexp":
			if k+1 < len(words) {
				return k + 1
			}
			return -1
		case strings.HasPrefix(word, "--regexp="):
			return k
		case actionSearchOptionTakesValue(tool, word):
			k++ // the option's value (-A 2, -m 5, -g '*.md') is not the pattern (RV5-3)
		case strings.HasPrefix(word, "-") || strings.HasPrefix(word, "/"):
			continue
		default:
			return k
		}
	}
	return -1
}

// actionSearchOptionTakesValue reports an option of a search tool whose
// value is the next word (RV5-3); an attached value (-A2, --glob=x) is one
// word. The short options differ per tool: grep -r and -E take no value,
// rg -r and -E do.
func actionSearchOptionTakesValue(tool, word string) bool {
	switch word {
	case "-A", "-B", "-C", "-m", "-f",
		"--after-context", "--before-context", "--context", "--max-count", "--file":
		return true
	}
	switch tool {
	case "grep", "egrep", "fgrep":
		switch word {
		case "-D", "-d", "--devices", "--directories", "--include", "--exclude", "--exclude-from",
			"--exclude-dir", "--label", "--binary-files", "--group-separator":
			return true
		}
	case "rg":
		switch word {
		case "-E", "-M", "-T", "-d", "-g", "-j", "-r", "-t",
			"--glob", "--iglob", "--type", "--type-not", "--type-add", "--type-clear", "--max-columns",
			"--max-depth", "--max-filesize", "--threads", "--encoding", "--replace", "--sort", "--sortr",
			"--pre", "--pre-glob", "--ignore-file", "--engine", "--context-separator",
			"--field-match-separator", "--path-separator", "--colors", "--dfa-size-limit",
			"--regex-size-limit":
			return true
		}
	case "ag":
		switch word {
		case "-G", "-g", "-p", "--ignore", "--ignore-dir", "--depth", "--path-to-ignore",
			"--file-search-regex":
			return true
		}
	case "ack":
		switch word {
		case "--type", "--ignore-dir", "--ignore-file", "--output":
			return true
		}
	}
	return false
}

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

// actionWindowsGitSubcommand returns the index of the subcommand of a git
// statement. It reports false for a statement with no subcommand or with a
// global option that changes what git runs.
func actionWindowsGitSubcommand(words []string) (int, bool) {
	// Global options that only place the command (-C dir, --git-dir,
	// --work-tree) or change its output do not change what git runs; -c,
	// --config-env, --exec-path and any other option do (RV5-4).
	sub := 1
	for sub < len(words) && strings.HasPrefix(words[sub], "-") {
		option := words[sub]
		switch {
		case option == "-C" || option == "--git-dir" || option == "--work-tree" || option == "--namespace":
			sub += 2
			continue
		case strings.HasPrefix(option, "--git-dir=") || strings.HasPrefix(option, "--work-tree=") ||
			strings.HasPrefix(option, "--namespace="):
		case option == "--no-pager" || option == "-P" || option == "--no-optional-locks" || option == "--bare" ||
			option == "--literal-pathspecs" || option == "--glob-pathspecs" || option == "--noglob-pathspecs" ||
			option == "--icase-pathspecs" || option == "--no-replace-objects" || option == "--no-advice":
		default:
			return 0, false
		}
		sub++
	}
	if sub >= len(words) {
		return 0, false
	}
	return sub, true
}

// actionWindowsGitPathspecWord reports a word of a git text statement that
// git reads as a pathspec of files it rewrites: git stash push (and its
// short form git stash -- ...) saves and then REVERTS the working-tree files
// a pathspec selects, and git expands a pathspec glob itself. Such a word
// stays a path pattern; the -m message stays text (RV6-2).
func actionWindowsGitPathspecWord(words []string, k int) bool {
	sub, ok := actionWindowsGitSubcommand(words)
	if !ok || k <= sub || strings.ToLower(words[sub]) != "stash" {
		return false
	}
	i := sub + 1
	if i < len(words) {
		switch strings.ToLower(words[i]) {
		case "push":
			i++
		case "list", "show", "drop", "pop", "apply", "branch", "clear", "save", "create", "store":
			return false
		}
	}
	for ; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			return k > i
		case word == "-m" || word == "--message" || word == "--pathspec-from-file":
			if i+1 == k {
				return word == "--pathspec-from-file"
			}
			i++
		case strings.HasPrefix(word, "--pathspec-from-file="):
			if i == k {
				return true
			}
		case strings.HasPrefix(word, "-"):
		default:
			if i == k {
				return true // a pathspec without --
			}
		}
	}
	return false
}

// actionWindowsTextStatement reports a statement that only prints its words
// or gives them to a git command that keeps them as text (a message, a
// pathspec, a search pattern). git runs a configuration value as shell code
// (an alias, the pager, the editor, a hook path), so a git statement with an
// option before its subcommand (-c, --config-env, --exec-path ...), the
// config subcommand, an alias or a subcommand that runs a command it is
// given (rebase --exec, bisect run, submodule foreach ...) is not text
// (GAP-2090).
func actionWindowsTextStatement(words []string) bool {
	if len(words) == 0 || !actionWindowsTextProgram(words[0]) {
		return false
	}
	if strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(words[0], `\`, "/"))), ".exe") != "git" {
		return true
	}
	sub, ok := actionWindowsGitSubcommand(words)
	if !ok {
		return false
	}
	switch strings.ToLower(words[sub]) {
	case "commit", "tag", "notes", "stash", "log", "show", "status", "diff", "blame", "add":
		return true
	case "grep":
		for _, word := range words[sub+1:] {
			if strings.HasPrefix(word, "-O") || strings.HasPrefix(word, "--open-files-in-pager") {
				return false
			}
		}
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
	case "cat", "get-content", "get-childitem", "resolve-path", "test-path", "head", "tail", "dir", "ls", "stat", "cd", "pushd", "popd", "set-location", "push-location", "pop-location",
		// cmd type, and the search and select filters, only read (GAP-2168).
		"type", "findstr", "select-string", "sls", "select-object", "select",
		// Git Bash search and count programs read their operands as on a
		// POSIX home (actionKnownReadOnlyShell, GAP-2168 Windows leg).
		"grep", "egrep", "fgrep", "wc":
		return true
	case "ssh-keygen":
		return actionSSHKeygenListsOnlyWords(words[1:])
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
	var check func(candidate string) bool
	check = func(candidate string) bool {
		candidate = strings.ReplaceAll(candidate, "`", "")
		if strings.ContainsAny(candidate, "\r\n") {
			// A word of several lines (a here-string body, such as the
			// script of bash -lc @'...'@) is no single path: Windows names
			// hold no line break. Each line is read as a candidate. As one
			// glob pattern, the whole body named a directory that does not
			// exist, which counts as a possibly protected expansion, so any
			// body with a / and a * was a protected target (GAP-0781).
			for _, line := range strings.FieldsFunc(candidate, func(r rune) bool { return r == '\r' || r == '\n' }) {
				if line = strings.TrimSpace(line); line != "" && check(line) {
					return true
				}
			}
			return false
		}
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

// actionWindowsLiteralHereDocumentTarget reads the literal body of a POSIX
// here-document under a Windows home. Git Bash passes that body through
// unchanged, backslashes of an absolute Windows path included, while the
// POSIX text scan reads those backslashes as escapes (GAP-1504).
func actionWindowsLiteralHereDocumentTarget(command, home string) bool {
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	var targets []string
	for _, target := range ProtectedAuthorizedKeysPaths(home) {
		targets = append(targets, strings.ToLower(strings.ReplaceAll(target, "\\", "/")))
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		redirect, ok := node.(*syntax.Redirect)
		if !ok || redirect.Hdoc == nil || redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc {
			return true
		}
		for _, part := range redirect.Hdoc.Parts {
			literal, ok := part.(*syntax.Lit)
			if !ok {
				continue
			}
			body := strings.ToLower(strings.ReplaceAll(literal.Value, "\\", "/"))
			for _, target := range targets {
				for start := 0; start < len(body); {
					index := strings.Index(body[start:], target)
					if index < 0 {
						break
					}
					index += start
					end := index + len(target)
					before, _ := utf8.DecodeLastRuneInString(body[:index])
					after, _ := utf8.DecodeRuneInString(body[end:])
					singleQuoted := before == '\'' && after == '\''
					if (index == 0 || actionWindowsHereDocDelimiter(before) || singleQuoted) &&
						(end == len(body) || actionWindowsHereDocDelimiter(after) || singleQuoted) {
						found = true
						return false
					}
					start = index + 1
				}
			}
		}
		return true
	})
	return found
}

// actionWindowsHereDocDelimiter: a Windows file name may hold punctuation and
// Unicode, so only white space and the characters a name cannot hold end an
// unquoted path in a here-document body.
func actionWindowsHereDocDelimiter(value rune) bool {
	return unicode.IsSpace(value) || strings.ContainsRune("\"<>|?*", value)
}

// actionSpelledWindowsTarget judges a POSIX-reading value under a Windows
// home by its spelling. The POSIX parser has already expanded HOME and the
// unquoted tildes: a value that still holds $, % or a backtick, or a quoted
// ~, is literal text in the POSIX shell, and the Windows expansion of it
// would name a protected path the shell never reaches (GAP-1504).
func actionSpelledWindowsTarget(value string, tilde bool, base, home string, stateOnly bool) bool {
	if strings.ContainsAny(value, "$%`") || !tilde && (value == "~" || strings.HasPrefix(value, "~/")) {
		return false
	}
	if strings.ContainsAny(value, "*?[]") {
		return !stateOnly && actionWindowsProtectedGlobReach(value, base, home)
	}
	resolved, ok := actionWindowsPath(value, base, home)
	if !ok {
		return false
	}
	root, ok := actionWindowsPath(home, base, home)
	if !ok {
		return false
	}
	if stateOnly {
		return strings.HasPrefix(resolved, root+"/") &&
			actionProtectedStateRelative(strings.TrimPrefix(resolved, root+"/"))
	}
	protected, _ := actionWindowsProtected(value, base, home, false)
	return resolved == root+"/.ssh" || protected
}

// actionStateEntryMayDiffer reports that the entry reading of value (its
// directory followed, its name kept) can name another file than its full
// walk: only when the last name is itself a link. An absolute value whose
// last name is missing or not a link costs one Lstat, not a second walk
// (GAP-2279 answer budget); a relative value is always read.
func actionStateEntryMayDiffer(value string) bool {
	if !filepath.IsAbs(value) {
		return true
	}
	info, err := os.Lstat(value)
	if err != nil {
		return !os.IsNotExist(err)
	}
	return info.Mode()&os.ModeSymlink != 0
}
