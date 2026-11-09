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
	"chmod", "chown", "chgrp", "setfacl", "chattr", "find", "truncate", "touch",
	"install", "rsync", "tar", "unzip", "dd", "tee", "sponge", "python", "node",
	"ruby", "bash", "zsh", "dash", "ksh", "sh", "xargs",
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
			capable = capable || registrationEditsInPlace(node, home)
			for index, word := range node.Args {
				value, fixed := StaticWord(word, home)
				if !fixed {
					capable = capable || index == 0
					continue
				}
				base := programBase(value)
				if index == 0 && (base == "eval" || base == "source" || base == "." || base == "exec") {
					capable = true
				}
				for _, name := range registrationWriteWords {
					if base == name || strings.HasPrefix(base, name) && strings.Trim(base[len(name):], "0123456789.") == "" {
						capable = true
					}
				}
			}
		}
		return !capable
	})
	return capable
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
