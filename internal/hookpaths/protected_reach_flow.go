// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A registered hook or configuration file that a command names is judged by
// the precise reading only while the command is one simple command with
// literal words. Any shell construct that can carry a value, change what runs
// or reorder the statements (a list, a pipe, a group, a branch, a loop, a
// function, eval, a declaration, a here-document, a substitution ...) makes
// the exact value tracking a guess about the shell, so a write-capable
// command that contains one and names the file is read as reaching it. This
// is a syntax and text test, not a model of the shell, so a construct the
// reader does not know cannot defeat it.

// registrationFlowBuiltins are the call words that change shell state, run
// text, or change how a later word is looked up.
var registrationFlowBuiltins = map[string]bool{
	"eval": true, "source": true, ".": true, "shopt": true, "set": true,
	"read": true, "declare": true, "typeset": true, "local": true,
	"export": true, "readonly": true, "mapfile": true, "readarray": true,
	"alias": true, "unset": true, "command": true, "builtin": true,
	"enable": true, "trap": true, "exec": true,
}

// registrationWriteWords are programs that write their operands, or run text
// of their own (the interpreters and shells). sed and perl count only when
// they edit in place or write (registrationEditsInPlace).
var registrationWriteWords = []string{
	"rm", "rmdir", "unlink", "shred", "mv", "cp", "gcp", "ln", "gln", "patch",
	"chmod", "chown", "chgrp", "setfacl", "chattr", "truncate", "touch",
	"install", "rsync", "tar", "unzip", "dd", "tee", "sponge", "python", "node",
	"ruby", "bash", "zsh", "dash", "ksh", "sh",
}

// registrationInPlaceFlag matches the sed and perl options that edit a file
// in place (sed -i, -ni, --in-place; perl -i, -pi, -nie).
var registrationInPlaceFlag = regexp.MustCompile(`^(--in-place(=.*)?|-[nEersuzpwWxX0-9]*i.*)$`)

// registrationSedWrites matches a sed w / W / e command in a script word.
var registrationSedWrites = regexp.MustCompile(`(^|[\s;{}0-9$,/])[wWe]\s*\S`)

// registrationFlowMembers returns, for each member of the registration set,
// whether the command is a write-capable command that contains a flow
// construct and names the member. A member that is a folder is never named
// this way: working in a folder that holds a hook is ordinary work.
func registrationFlowMembers(file *syntax.File, command, cwd, home string, protected protectedFiles) []bool {
	named := make([]bool, len(protected))
	if !registrationWriteCapable(file, home) || !registrationHasFlow(file, home) {
		return named
	}
	text := registrationHomeText(command, home)
	words := registrationStaticWords(file, home)
	for index, entry := range protected {
		if registrationIsFolder(entry, protected) {
			continue
		}
		path := entry.path
		base, parent := filepath.Base(path), filepath.Dir(path)
		switch {
		case registrationMentions(text, path, false):
			named[index] = true
		case registrationMentions(text, base, true) &&
			(cwd == parent || registrationMentions(text, parent, false)):
			named[index] = true
		default:
			// A word that is a link the hook resolves.
			single := protectedFiles{entry}
			for _, word := range words {
				if protectedReachPath(OperandPath(word, cwd), single, "") {
					named[index] = true
					break
				}
			}
		}
	}
	return named
}

// registrationIsFolder reports whether the member is a folder: it is one on
// disk, or another member lies below it (a registered folder that does not
// exist yet).
func registrationIsFolder(entry protectedFile, set protectedFiles) bool {
	if entry.info != nil {
		return entry.info.IsDir()
	}
	prefix := entry.path + string(filepath.Separator)
	for _, other := range set {
		if strings.HasPrefix(other.path, prefix) {
			return true
		}
	}
	return false
}

// registrationHomeText spells ~ and $HOME with the home folder.
func registrationHomeText(command, home string) string {
	if home == "" {
		return command
	}
	text := strings.NewReplacer("${HOME}", home, "$HOME", home).Replace(command)
	var out strings.Builder
	for index := 0; index < len(text); index++ {
		if text[index] == '~' && (index == 0 || !registrationPathChar(text[index-1]) && text[index-1] != '/') &&
			(index+1 == len(text) || text[index+1] == '/') {
			out.WriteString(home)
			continue
		}
		out.WriteByte(text[index])
	}
	return out.String()
}

func registrationPathChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == '-' || c == '~'
}

// registrationMentions reports whether text spells name as a whole path (or,
// for a base name, a whole path component): not as part of a longer name.
func registrationMentions(text, name string, component bool) bool {
	if name == "" || name == "." || name == string(filepath.Separator) {
		return false
	}
	for from := 0; from < len(text); {
		at := strings.Index(text[from:], name)
		if at < 0 {
			return false
		}
		start, end := from+at, from+at+len(name)
		from = start + 1
		if start > 0 && (registrationPathChar(text[start-1]) || !component && text[start-1] == '/') {
			continue
		}
		if end < len(text) && registrationPathChar(text[end]) {
			continue
		}
		return true
	}
	return false
}

// registrationStaticWords lists the literal words of the command.
func registrationStaticWords(file *syntax.File, home string) []string {
	var out []string
	syntax.Walk(file, func(node syntax.Node) bool {
		if word, ok := node.(*syntax.Word); ok {
			if value, fixed := StaticWord(word, home); fixed && value != "" && !strings.HasPrefix(value, "-") {
				out = append(out, value)
			}
		}
		return true
	})
	return out
}

// registrationWriteCapable reports whether any part of the command can write:
// a redirection to a file, a program that writes its operands, text it runs,
// or a call word it does not spell out.
func registrationWriteCapable(file *syntax.File, home string) bool {
	capable := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Redirect:
			switch node.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob, syntax.RdrInOut:
				value, fixed := StaticWord(node.Word, home)
				capable = capable || !fixed || value != "/dev/null"
			}
		case *syntax.CallExpr:
			capable = capable || registrationEditsInPlace(node, home) || registrationCallWrites(node, home)
		}
		return !capable
	})
	return capable
}

// registrationRunner describes how a program that runs another program names
// it: the options it reads before the program (short letters that take a
// value, short letters that do not, long names and whether they take a value)
// and the operands it reads first (flock reads the lock file, chroot the new
// root). A program the reader cannot place after these is not narrowed.
type registrationRunner struct {
	operands int
	short    string
	flag     string
	long     map[string]bool
}

// registrationRunners are the dispatchers whose own grammar is known: the
// program they run is the first word after their options and operands, and
// only that program is judged. Text further along belongs to that program.
var registrationRunners = map[string]registrationRunner{
	"xargs": {short: "adEILnPsJ", flag: "0eiloprtx", long: map[string]bool{
		"arg-file": true, "delimiter": true, "eof": true, "replace": true, "max-lines": true,
		"max-args": true, "max-procs": true, "max-chars": true, "null": false, "no-run-if-empty": false,
		"verbose": false, "interactive": false, "open-tty": false, "exit": false, "show-limits": false,
	}},
	"flock": {operands: 1, short: "wE", flag: "sxenouF", long: map[string]bool{
		"timeout": true, "conflict-exit-code": true, "shared": false, "exclusive": false,
		"nonblock": false, "nb": false, "close": false, "no-fork": false, "unlock": false,
	}},
	"chroot": {operands: 1, long: map[string]bool{"userspec": true, "groups": true, "skip-chdir": false}},
	"git": {short: "Cc", flag: "p", long: map[string]bool{
		"git-dir": true, "work-tree": true, "namespace": true, "exec-path": false, "no-pager": false,
		"paginate": false, "bare": false, "no-replace-objects": false,
	}},
	"busybox":  {},
	"toybox":   {},
	"fakeroot": {},
	"chronic":  {},
	"time":     {flag: "p"},
}

// registrationScanRunners are programs that run what their arguments name in
// a grammar the reader does not model (containers, remote and multiplexer
// shells, build tools, privilege switches, tracers): every later word stays
// in play, so a writer named there is read as a writer.
var registrationScanRunners = map[string]bool{
	"make": true, "gmake": true, "docker": true, "podman": true, "nerdctl": true, "kubectl": true,
	"watch": true, "parallel": true, "strace": true, "ltrace": true, "nsenter": true, "unshare": true,
	"su": true, "runuser": true, "pkexec": true, "setpriv": true, "script": true, "screen": true,
	"tmux": true, "at": true, "ssh": true, "chrt": true, "taskset": true, "unbuffer": true,
	"caffeinate": true,
}

// registrationRunWords returns the words a runner runs: what follows its
// options and operands. ok is false when an option is not one the runner is
// known to have, so the caller keeps every word in play.
func registrationRunWords(spec registrationRunner, args []*syntax.Word, home string) (run []*syntax.Word, ok bool) {
	index := 0
	for ; index < len(args); index++ {
		word, fixed := StaticWord(args[index], home)
		if !fixed {
			return nil, false
		}
		if word == "--" {
			index++
			break
		}
		if !strings.HasPrefix(word, "-") || word == "-" {
			break
		}
		if strings.HasPrefix(word, "--") {
			name, _, attached := strings.Cut(word[2:], "=")
			takes, known := spec.long[name]
			if !known {
				return nil, false
			}
			if takes && !attached {
				index++
			}
			continue
		}
		for at := 1; at < len(word); at++ {
			if strings.IndexByte(spec.short, word[at]) >= 0 {
				if at+1 == len(word) {
					index++
				}
				break
			}
			if strings.IndexByte(spec.flag, word[at]) < 0 {
				return nil, false
			}
		}
	}
	index += spec.operands
	if index > len(args) {
		return nil, true
	}
	return args[index:], true
}

// registrationFindWrites reports whether a find call can write: it deletes
// or prints into a file, runs a program that writes, or has a word that is
// not spelled out.
func registrationFindWrites(args []*syntax.Word, home string) bool {
	for index, word := range args {
		value, fixed := StaticWord(word, home)
		if !fixed {
			return true
		}
		switch value {
		case "-delete", "-fprint", "-fprint0", "-fprintf", "-fls":
			return true
		case "-exec", "-execdir", "-ok", "-okdir":
			run := args[index+1:]
			for end, next := range run {
				if text, _ := StaticWord(next, home); text == ";" || text == "+" {
					run = run[:end]
					break
				}
			}
			if len(run) > 0 && registrationCallWrites(&syntax.CallExpr{Args: run}, home) {
				return true
			}
		}
	}
	return false
}

// registrationCallWrites reports whether the program a call runs writes its
// operands or runs text of its own. A writer is recognised where a program is
// named: the command word, after the wrappers that pass argv on. As an
// operand of another program its name is text (echo cp && sha256sum FILE
// reads; so does git grep cp). A dispatcher runs another program: the
// program it runs is judged, in the position its grammar gives it (xargs,
// flock, chroot, busybox, git ...), and find by its actions. A wrapper or
// dispatcher whose options the reader does not know, a runner it does not
// model, and a command word that is not spelled out keep every later word in
// play.
func registrationCallWrites(call *syntax.CallExpr, home string) bool {
	if len(call.Args) == 0 {
		return false
	}
	words, known := actionLiteralCommandWords(call.Args, home)
	if !known {
		return registrationNamesWriter(call.Args, home, true)
	}
	if first, _ := StaticWord(call.Args[0], home); programBase(first) == "exec" {
		return true
	}
	program, fixed := StaticWord(words[0], home)
	if !fixed {
		return true
	}
	base := programBase(program)
	if base == "find" {
		return registrationFindWrites(words[1:], home)
	}
	if spec, runner := registrationRunners[base]; runner {
		if run, ok := registrationRunWords(spec, words[1:], home); ok {
			return len(run) > 0 && registrationCallWrites(&syntax.CallExpr{Args: run}, home)
		}
		return registrationNamesWriter(words[1:], home, false)
	}
	return registrationNamesWriter(words[:1], home, true) ||
		registrationScanRunners[base] && registrationNamesWriter(words[1:], home, false)
}

// registrationNamesWriter reports whether a static word names a program that
// writes its operands or runs text; with command, the first word is the
// program, so eval, source and dot count there and a word that is not
// spelled out does too.
func registrationNamesWriter(words []*syntax.Word, home string, command bool) bool {
	for index, word := range words {
		value, fixed := StaticWord(word, home)
		if !fixed {
			if command && index == 0 {
				return true
			}
			continue
		}
		base := programBase(value)
		if command && index == 0 && (base == "eval" || base == "source" || base == "." || base == "exec") {
			return true
		}
		for _, name := range registrationWriteWords {
			if base == name || strings.HasPrefix(base, name) && strings.Trim(base[len(name):], "0123456789.") == "" {
				return true
			}
		}
	}
	return false
}

// registrationEditsInPlace reports whether a sed or perl call edits a file in
// place (or sed runs a w / e command): without that the two only read.
func registrationEditsInPlace(call *syntax.CallExpr, home string) bool {
	if len(call.Args) == 0 {
		return false
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed || programBase(program) != "sed" && programBase(program) != "perl" {
		return false
	}
	for _, word := range call.Args[1:] {
		value, fixed := StaticWord(word, home)
		if !fixed {
			continue
		}
		if registrationInPlaceFlag.MatchString(value) ||
			programBase(program) == "sed" && !strings.HasPrefix(value, "-") && registrationSedWrites.MatchString(value) {
			return true
		}
	}
	return false
}

// registrationHasFlow reports whether the command contains a construct that
// makes it more than one simple command with literal words.
func registrationHasFlow(file *syntax.File, home string) bool {
	if len(file.Stmts) > 1 {
		return true
	}
	flow := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.BinaryCmd, *syntax.Subshell, *syntax.Block, *syntax.IfClause,
			*syntax.CaseClause, *syntax.ForClause, *syntax.WhileClause, *syntax.FuncDecl,
			*syntax.DeclClause, *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmCmd,
			*syntax.LetClause, *syntax.CoprocClause, *syntax.ArithmExp:
			flow = true
		case *syntax.Stmt:
			flow = flow || node.Background
		case *syntax.Redirect:
			flow = flow || node.Op == syntax.Hdoc || node.Op == syntax.DashHdoc || node.Op == syntax.WordHdoc
		case *syntax.ParamExp:
			flow = flow || node.Param == nil || node.Param.Value != "HOME"
		case *syntax.CallExpr:
			flow = flow || registrationCallIsFlow(node, home)
		}
		return !flow
	})
	return flow
}

// registrationCallIsFlow reports whether a call word is not spelled out, is a
// builtin that changes the shell, or is printf storing into a variable.
func registrationCallIsFlow(call *syntax.CallExpr, home string) bool {
	if len(call.Args) == 0 {
		return false
	}
	first, fixed := StaticWord(call.Args[0], home)
	if !fixed || registrationFlowBuiltins[programBase(first)] || registrationFlowBuiltins[registrationCommandWord(call)] {
		return true
	}
	if programBase(first) != "printf" {
		return false
	}
	for _, word := range call.Args[1:] {
		value, fixed := StaticWord(word, home)
		if !fixed || !strings.HasPrefix(value, "-") || value == "--" {
			return false
		}
		if strings.HasPrefix(value, "-v") {
			return true
		}
	}
	return false
}
