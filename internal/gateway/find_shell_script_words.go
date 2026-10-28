// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// findShellScriptLimit bounds the -c script a find command hands a shell
// before it is parsed; a longer script does not stay off the state.
const findShellScriptLimit = 8192

// findScriptRefusedPrograms run code, change the positional parameters or
// variables, or start a new command line from their own words, so a
// script that runs one of them is not read as staying off the state
// (pod check12 S6, S7, S10).
var findScriptRefusedPrograms = map[string]struct{}{
	"find": {}, "eval": {}, "source": {}, ".": {}, "exec": {}, "command": {}, "builtin": {},
	"set": {}, "read": {}, "mapfile": {}, "readarray": {}, "declare": {}, "typeset": {},
	"local": {}, "export": {}, "alias": {}, "trap": {}, "let": {}, "shift": {}, "getopts": {},
	"env": {}, "nice": {}, "nohup": {}, "sudo": {}, "doas": {}, "su": {}, "runuser": {},
	"timeout": {}, "stdbuf": {}, "ionice": {}, "time": {}, "chroot": {}, "xargs": {}, "parallel": {},
	"flock": {}, "script": {}, "watch": {}, "setsid": {}, "unshare": {}, "systemd-run": {}, "sg": {},
	"taskset": {}, "chrt": {}, "prlimit": {}, "numactl": {}, "setpriv": {}, "nsenter": {}, "strace": {},
	"ltrace": {}, "cgexec": {}, "firejail": {}, "bwrap": {}, "sandbox-exec": {}, "caffeinate": {}, "arch": {},
}

// findProgramRunners start their other words as a program: a wrapper with
// its options and their values (`nice -n 5`, `timeout -s KILL 60`,
// `taskset 1`) may stand before the program it runs (pod check14 30(c)).
var findProgramRunners = map[string]struct{}{
	"env": {}, "nice": {}, "nohup": {}, "sudo": {}, "doas": {}, "su": {}, "runuser": {},
	"timeout": {}, "stdbuf": {}, "ionice": {}, "time": {}, "chroot": {}, "xargs": {}, "parallel": {},
	"exec": {}, "command": {}, "builtin": {},
	"flock": {}, "script": {}, "watch": {}, "setsid": {}, "unshare": {}, "systemd-run": {}, "sg": {},
	"taskset": {}, "chrt": {}, "prlimit": {}, "numactl": {}, "setpriv": {}, "nsenter": {}, "strace": {},
	"ltrace": {}, "cgexec": {}, "firejail": {}, "bwrap": {}, "sandbox-exec": {}, "caffeinate": {}, "arch": {},
}

// findWordMayRunAsProgram reports a word of an -exec command that the
// command may run as a program: the first word, a word after an
// environment assignment, or any word after a program runner, whatever
// options and values stand between them (`-execdir nice -n 5 flock L -c
// SCRIPT`, pod check14 30(c)). A word of a program that only reads its
// words (`grep -l su {}`) is not one.
func findWordMayRunAsProgram(words []string, index int) bool {
	if index == 0 || strings.Contains(words[index-1], "=") {
		return true
	}
	for _, word := range words[:index] {
		if _, runner := findProgramRunners[findProgramName(word)]; runner {
			return true
		}
	}
	return false
}

// findStripMark follows the "$1" a %/%% suffix strip renders as, until
// findSuffixStripsStayInName checks the text after it.
const findStripMark = "\x00"

// findSuffixStripsStayInName reports that every %/%% suffix strip of a
// rendered word is followed by literal text that keeps it a sibling name
// in the entry's directory (`${1%.wav}.mp3`). A strip at the end of the
// word may remove the whole name (`find ~ -name h.txt` with `${1%h.txt}`
// is the home directory, a dotfile named `.wav` makes `${1%.wav}` its
// directory), and text with '/', a glob, an expansion or only dots after
// it leaves the entry's name (`${1%a.log}../hooks`), so those are not
// read here (pod check14 row 29).
func findSuffixStripsStayInName(text string) bool {
	for {
		index := strings.Index(text, findStripMark)
		if index < 0 {
			return true
		}
		rest := text[index+len(findStripMark):]
		if rest == "" || strings.Trim(rest, ".") == "" || strings.ContainsAny(rest, "/*?[$`\\") ||
			strings.Contains(rest, findStripMark) {
			return false
		}
		text = rest
	}
}

// findCommandStringPrograms run a command line given as one of their own
// words (`flock LOCK -c SCRIPT`, `script -c SCRIPT`, `su -c SCRIPT`,
// `watch CMD`) or start the rest of their words as a new command, so a
// find command that runs one of them is not read as staying off the state
// (pod check13 R9).
var findCommandStringPrograms = map[string]struct{}{
	"flock": {}, "script": {}, "su": {}, "runuser": {}, "watch": {}, "setsid": {}, "unshare": {},
	"systemd-run": {}, "sg": {},
}

// findPOSIXGrammarShells are the shells whose -c script the hook shell
// grammar reads as they run it. zsh, fish, csh and tcsh expand words the
// grammar does not model (zsh `$1:h:h`, pod check13 R7), so their scripts
// never stay off the state here.
var findPOSIXGrammarShells = map[string]struct{}{
	"sh": {}, "bash": {}, "dash": {}, "ksh": {}, "mksh": {}, "ash": {},
}

// findShellInvocationStaysOff judges `sh [options] -c SCRIPT [name [args...]]`
// that find hands its entries: the script stays off the state when every
// word the shell will run, after its quotes and escapes are removed, stays
// off it (pod check12: `cd .\.`, `.defense""claw` and `.defense\claw`
// spell the state for the shell, not for a raw-text check). The words
// after the script are plain argv words. A shell with no -c script reads
// a file or stdin, which is not read here, so it does not stay off.
func findShellInvocationStaysOff(words []string, home, root string, inEntryDir bool) bool {
	if _, posix := findPOSIXGrammarShells[findProgramName(words[0])]; !posix {
		return false
	}
	index := 1
	for ; index < len(words); index++ {
		word := words[index]
		if word == "-c" {
			break
		}
		// A single-dash option bundle that holds c (`-ec`, `-xc`) takes
		// the script next; any other word is not a plain shell option.
		if !findPlainOption(word) || strings.HasPrefix(word, "--") {
			return false
		}
		if strings.ContainsRune(word, 'c') {
			break
		}
	}
	if index+1 >= len(words) {
		return false
	}
	for _, word := range words[index+2:] {
		if findWordReachesState(word, home, root, inEntryDir) {
			return false
		}
	}
	return findShellScriptStaysOff(words[index+1], home, root, inEntryDir)
}

// findShellScriptStaysOff parses a -c script with the hook shell grammar
// and judges the words of every simple command and redirect as the shell
// will run them. A positional parameter, a loop variable bound only to
// the positionals (`for f; do`, `for f in "$@"`), a %/%% suffix strip
// without '/' or a #/## prefix strip of one, and `$(basename ...)` of
// those name the entry the script is handed (pod check12 N1, N2, N5, N6,
// N10), and so does a variable assigned one positional (`f="$1"`, pod
// check13 B7). Any other expansion, a here-document, any other
// assignment, a function,
// a case/arithmetic/test clause and the programs in
// findScriptRefusedPrograms, findShellPrograms and findInlineInterpreters
// do not stay off (fail closed).
func findShellScriptStaysOff(script, home, root string, inEntryDir bool) bool {
	if len(script) > findShellScriptLimit {
		return false
	}
	file, ok := shellparse.Parse(script)
	if !ok {
		return false
	}
	bound := map[string]bool{}
	staysOff := true
	judge := func(word *syntax.Word) bool {
		text, glob, rendered := findRenderScriptWord(word, bound)
		if !rendered || glob && findGlobReachesState(text) {
			return false
		}
		return !findWordReachesState(text, home, root, inEntryDir)
	}
	var visit func(node syntax.Node) bool
	visit = func(node syntax.Node) bool {
		if !staysOff || node == nil {
			return false
		}
		switch node := node.(type) {
		case *syntax.File, *syntax.Stmt, *syntax.BinaryCmd, *syntax.Block, *syntax.Subshell,
			*syntax.IfClause, *syntax.WhileClause, *syntax.Comment:
			return true
		case *syntax.Redirect:
			if node.Hdoc != nil || node.Word == nil || !judge(node.Word) {
				staysOff = false
			}
			return false
		case *syntax.ForClause:
			iter, ok := node.Loop.(*syntax.WordIter)
			if !ok || iter.Name == nil || node.Select {
				staysOff = false
				return false
			}
			for _, item := range iter.Items {
				if !findScriptWordIsPositionals(item) {
					staysOff = false
					return false
				}
			}
			bound[iter.Name.Value] = true
			for _, stmt := range node.Do {
				syntax.Walk(stmt, visit)
			}
			return false
		case *syntax.CallExpr:
			staysOff = findScriptCallStaysOff(node, bound, judge, &inEntryDir)
			return false
		default:
			// A function, case, arithmetic, test or declaration clause is
			// not read here.
			staysOff = false
			return false
		}
	}
	syntax.Walk(file, visit)
	return staysOff
}

// findScriptCallStaysOff judges one simple command of a find -c script.
func findScriptCallStaysOff(
	call *syntax.CallExpr,
	bound map[string]bool,
	judge func(*syntax.Word) bool,
	inEntryDir *bool,
) bool {
	if len(call.Assigns) > 0 {
		// Only `name="$N"` with no command binds name to the entry (pod
		// check13 B7); any other assignment is not read here.
		if len(call.Args) > 0 {
			return false
		}
		for _, assign := range call.Assigns {
			if assign.Append || assign.Naked || assign.Index != nil || assign.Array != nil ||
				assign.Name == nil || !findScriptWordIsPositionals(assign.Value) {
				return false
			}
		}
		for _, assign := range call.Assigns {
			bound[assign.Name.Value] = true
		}
		return true
	}
	if len(call.Args) == 0 {
		return true
	}
	program, _, rendered := findRenderScriptWord(call.Args[0], bound)
	if !rendered {
		return false
	}
	name := findProgramName(program)
	_, refused := findScriptRefusedPrograms[name]
	_, shell := findShellPrograms[name]
	_, inline := findInlineInterpreters[name]
	if refused || shell || inline {
		return false
	}
	args := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		if !judge(word) {
			return false
		}
		text, _, _ := findRenderScriptWord(word, bound)
		args = append(args, text)
	}
	if findSedRunsOrWrites(args) {
		return false
	}
	// After a cd the script no longer runs in the entry's directory, so
	// a relative word that starts with a state name is judged as one.
	if name == "cd" || name == "pushd" {
		*inEntryDir = false
	}
	return true
}

// findScriptWordIsPositionals is "$@", "$*" or one positional parameter:
// a for loop over it binds its variable to the entries.
func findScriptWordIsPositionals(word *syntax.Word) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	part := word.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok && !quoted.Dollar && len(quoted.Parts) == 1 {
		part = quoted.Parts[0]
	}
	param, ok := part.(*syntax.ParamExp)
	return ok && findPlainParam(param) && param.Exp == nil && findPositionalName(param.Param.Value)
}

// findPlainParam is $name or ${name} with an optional expansion only: no
// indirection, length, index, slice, replacement or zsh form.
func findPlainParam(param *syntax.ParamExp) bool {
	return param.Param != nil && param.Flags == nil && !param.Excl && !param.Length && !param.Width &&
		!param.IsSet && param.NestedParam == nil && param.Index == nil && len(param.Modifiers) == 0 &&
		param.Slice == nil && param.Repl == nil && param.Names == 0
}

func findPositionalName(name string) bool {
	if name == "@" || name == "*" {
		return true
	}
	if name == "" {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// findRenderScriptWord gives the text the shell runs for a script word,
// with an entry expansion written as "$1", and whether an unquoted glob
// is in it. ok is false for a word that is not read here.
func findRenderScriptWord(word *syntax.Word, bound map[string]bool) (text string, glob bool, ok bool) {
	if word == nil {
		return "", false, false
	}
	var out strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			// The grammar keeps brace expansion in the literal: {.,}./hooks
			// runs as ../hooks ./hooks (pod check13 R8).
			if findLitHasBraceExpansion(part.Value) {
				return "", false, false
			}
			value, hasGlob := findUnescapeUnquoted(part.Value)
			glob = glob || hasGlob
			out.WriteString(value)
		case *syntax.SglQuoted:
			if part.Dollar {
				return "", false, false
			}
			out.WriteString(part.Value)
		case *syntax.DblQuoted:
			if part.Dollar {
				return "", false, false
			}
			for _, inner := range part.Parts {
				switch inner := inner.(type) {
				case *syntax.Lit:
					out.WriteString(findUnescapeDoubleQuoted(inner.Value))
				default:
					value, ok := findRenderEntryExpansion(inner, bound)
					if !ok {
						return "", false, false
					}
					out.WriteString(value)
				}
			}
		default:
			value, ok := findRenderEntryExpansion(part, bound)
			if !ok {
				return "", false, false
			}
			out.WriteString(value)
		}
	}
	text = out.String()
	if !findSuffixStripsStayInName(text) {
		return "", false, false
	}
	return strings.ReplaceAll(text, findStripMark, ""), glob, true
}

// findRenderEntryExpansion renders a parameter or command substitution
// that names the handed entry as "$1", and $HOME as "$HOME".
func findRenderEntryExpansion(part syntax.WordPart, bound map[string]bool) (string, bool) {
	switch part := part.(type) {
	case *syntax.ParamExp:
		if !findPlainParam(part) {
			return "", false
		}
		name := part.Param.Value
		if name == "HOME" && part.Exp == nil {
			return "$HOME", true
		}
		if !findPositionalName(name) && !bound[name] {
			return "", false
		}
		if part.Exp == nil {
			return "$1", true
		}
		pattern, glob, ok := findRenderScriptWord(part.Exp.Word, bound)
		if !ok || strings.Contains(pattern, "..") {
			return "", false
		}
		switch part.Exp.Op {
		case syntax.RemSmallSuffix, syntax.RemLargeSuffix:
			// ${1%/*} is the entry's directory; a literal suffix strip
			// without '/' (${1%.wav}) stays in the entry's own name. A glob
			// matches across '/', so ${1%logs*} or ${1%%.*} can cut the
			// entry back to its directory, the state root or home (pod
			// check13 R1-R6).
			if glob || strings.ContainsAny(pattern, "/$") {
				return "", false
			}
			// A literal strip may still remove the whole name, so the
			// text after it is checked (findSuffixStripsStayInName).
			return "$1" + findStripMark, true
		case syntax.RemSmallPrefix, syntax.RemLargePrefix:
		default:
			return "", false
		}
		return "$1", true
	case *syntax.CmdSubst:
		if len(part.Stmts) != 1 {
			return "", false
		}
		stmt := part.Stmts[0]
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(stmt.Redirs) > 0 || stmt.Negated || stmt.Background || len(call.Assigns) > 0 ||
			len(call.Args) < 2 || len(call.Args) > 3 {
			return "", false
		}
		program, _, ok := findRenderScriptWord(call.Args[0], bound)
		if !ok || program != "basename" {
			return "", false
		}
		entry, _, ok := findRenderScriptWord(call.Args[1], bound)
		if !ok || entry != "$1" {
			return "", false
		}
		if len(call.Args) == 3 {
			suffix, glob, ok := findRenderScriptWord(call.Args[2], bound)
			if !ok || glob || strings.ContainsAny(suffix, "/$") {
				return "", false
			}
		}
		return "$1", true
	default:
		return "", false
	}
}

// findUnescapeUnquoted removes the shell's backslash escapes from an
// unquoted literal and reports an unescaped glob character in it.
func findUnescapeUnquoted(value string) (string, bool) {
	var out strings.Builder
	glob := false
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\\':
			if index+1 < len(value) {
				index++
				if value[index] != '\n' {
					out.WriteByte(value[index])
				}
			}
		case '*', '?', '[':
			glob = true
			out.WriteByte(value[index])
		default:
			out.WriteByte(value[index])
		}
	}
	return out.String(), glob
}

// findLitHasBraceExpansion reports an unescaped {a,b} or {x..y} in an
// unquoted literal, which the shell expands into other words.
func findLitHasBraceExpansion(value string) bool {
	open := -1
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\\':
			index++
		case '{':
			open = index
		case '}':
			if open >= 0 {
				inner := value[open+1 : index]
				if strings.Contains(inner, ",") || strings.Contains(inner, "..") {
					return true
				}
			}
			open = -1
		}
	}
	return false
}

// findUnescapeDoubleQuoted removes the escapes a double-quoted literal
// keeps: \$, \`, \", \\ and a backslash-newline.
func findUnescapeDoubleQuoted(value string) string {
	var out strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+1 < len(value) && strings.ContainsRune("$`\"\\\n", rune(value[index+1])) {
			index++
			if value[index] != '\n' {
				out.WriteByte(value[index])
			}
			continue
		}
		out.WriteByte(value[index])
	}
	return out.String()
}

// findGlobReachesState reports a globbed script word that may expand to a
// path in the state: a glob with a directory part that is not the
// entry's own ("$1/*.tmp"), or one that starts with '~' or '.'.
func findGlobReachesState(text string) bool {
	if strings.HasPrefix(text, "$1") && !strings.Contains(text, "..") {
		return false
	}
	return strings.Contains(text, "/") || strings.HasPrefix(text, "~") || strings.HasPrefix(text, ".")
}

// findSedRunsOrWrites reports a sed command line whose script runs a
// command (e, or the e flag of s) or writes a file (w, W, or the w flag
// of s), or that reads its script from a file: such a sed is inline code
// that can reach the state on its own (pod check12).
func findSedRunsOrWrites(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch findProgramName(args[0]) {
	case "sed", "gsed":
	default:
		return false
	}
	var scripts []string
	explicit := false
	for index := 1; index < len(args); index++ {
		word := args[index]
		switch {
		case word == "--":
			if !explicit && index+1 < len(args) {
				scripts = append(scripts, args[index+1])
			}
			index = len(args)
		case strings.HasPrefix(word, "--expression="):
			explicit = true
			scripts = append(scripts, strings.TrimPrefix(word, "--expression="))
		case word == "--expression":
			explicit = true
			if index+1 < len(args) {
				index++
				scripts = append(scripts, args[index])
			}
		case word == "--file" || strings.HasPrefix(word, "--file="):
			return true
		case strings.HasPrefix(word, "--"):
		case strings.HasPrefix(word, "-i") || strings.HasPrefix(word, "-I"):
			// -i[SUFFIX] (GNU) or -i SUFFIX (BSD): the suffix is not a script.
		case len(word) > 1 && word[0] == '-':
			letters := word[1:]
			if strings.ContainsRune(letters, 'f') {
				return true
			}
			if position := strings.IndexByte(letters, 'e'); position >= 0 {
				explicit = true
				if rest := letters[position+1:]; rest != "" {
					scripts = append(scripts, rest)
				} else if index+1 < len(args) {
					index++
					scripts = append(scripts, args[index])
				}
			}
		default:
			if !explicit && len(scripts) == 0 {
				scripts = append(scripts, word)
			}
		}
	}
	for _, script := range scripts {
		if sedScriptRunsOrWrites(script) {
			return true
		}
	}
	return false
}

// sedScriptRunsOrWrites scans a sed script for the e, w and W commands and
// the e and w flags of s.
func sedScriptRunsOrWrites(script string) bool {
	length := len(script)
	for index := 0; index < length; {
		switch c := script[index]; {
		case strings.IndexByte(" \t\n;{}!,$~+0123456789IM", c) >= 0:
			index++
		case c == '#':
			index = sedSkipLine(script, index)
		case c == '/':
			index = sedSkipDelimited(script, index+1, '/')
		case c == '\\':
			if index+1 >= length {
				return true
			}
			index = sedSkipDelimited(script, index+2, script[index+1])
		case c == 'e' || c == 'w' || c == 'W':
			return true
		case c == 's':
			if index+1 >= length {
				return true
			}
			delimiter := script[index+1]
			index = sedSkipDelimited(script, sedSkipDelimited(script, index+2, delimiter), delimiter)
			for index < length && strings.IndexByte(" \t\n;}", script[index]) < 0 {
				if script[index] == 'e' || script[index] == 'w' || script[index] == 'W' {
					return true
				}
				index++
			}
		case c == 'y':
			if index+1 >= length {
				return true
			}
			delimiter := script[index+1]
			index = sedSkipDelimited(script, sedSkipDelimited(script, index+2, delimiter), delimiter)
		case c == 'a' || c == 'i' || c == 'c':
			index = sedSkipLine(script, index)
		case strings.IndexByte("rRbtT:qQlL", c) >= 0:
			for index < length && script[index] != ';' && script[index] != '\n' {
				index++
			}
		default:
			index++
		}
	}
	return false
}

// sedSkipDelimited returns the index after the next unescaped delimiter.
func sedSkipDelimited(script string, index int, delimiter byte) int {
	for index < len(script) {
		switch script[index] {
		case '\\':
			index += 2
		case delimiter:
			return index + 1
		default:
			index++
		}
	}
	return len(script)
}

// sedSkipLine returns the index after the next unescaped newline.
func sedSkipLine(script string, index int) int {
	for index < len(script) {
		switch script[index] {
		case '\\':
			index += 2
		case '\n':
			return index + 1
		default:
			index++
		}
	}
	return len(script)
}
