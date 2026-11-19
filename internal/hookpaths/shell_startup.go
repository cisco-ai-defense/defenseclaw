// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shellStartupCodeRunners are the programs that run code text the walk
// does not read as calls (a string, a file, a trap action or a child shell,
// which imports every exported function): when a statement names one, any
// exported function may run.
var shellStartupCodeRunners = map[string]bool{
	"eval": true, "source": true, ".": true, "trap": true, "fc": true,
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true,
}

// shellStartupUnknown reports a shell startup that can change what a
// statement runs: a startup file (BASH_ENV, ENV), an exported function for
// which calls reports true (bash runs a function instead of the program or
// builtin of that name; it accepts slashes in a function name, so
// /usr/bin/touch can be one), or command_not_found_handle, which runs for a
// missing program. An export spelled neither name%% (bash 4.3+) nor name()
// (older patched bash) is unknown. A function no statement calls changes
// nothing, so an unrelated export (environment-modules' module, an
// account's own helpers) leaves a proof intact (rel-1-0-10:GAP-0276, the
// GAP-0293 touch reading).
func shellStartupUnknown(calls func(function string) bool) bool {
	if os.Getenv("BASH_ENV") != "" || os.Getenv("ENV") != "" {
		return true
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		function, exported := strings.CutPrefix(name, "BASH_FUNC_")
		if !exported {
			continue
		}
		function, modern := strings.CutSuffix(function, "%%")
		if !modern {
			var patched bool
			if function, patched = strings.CutSuffix(function, "()"); !patched {
				return true
			}
		}
		if function == "command_not_found_handle" || calls(function) {
			return true
		}
	}
	return false
}

// shellStartupUnknownForCommand is shellStartupUnknown for the statements
// of command: an exported function counts when a call of command is named
// for it (its spelling or its last path element), and every exported
// function counts when a call's program word is not a fixed name, when a
// word of a call names a program that runs code text
// (shellStartupCodeRunners), or when command does not parse. The command is
// parsed only when a function is exported.
func shellStartupUnknownForCommand(command string) bool {
	var names map[string]bool
	var any, read bool
	return shellStartupUnknown(func(function string) bool {
		if !read {
			read = true
			file, ok := parseShell(command)
			if !ok {
				file = nil
			}
			names, any = shellStartupCallNames(file)
		}
		return any || names[function] || names[function[strings.LastIndexByte(function, '/')+1:]]
	})
}

// shellStartupCallNames are the names the calls of file run (each program
// word, and its last path element), and any when one may run a function
// the walk cannot name.
func shellStartupCallNames(file *syntax.File) (names map[string]bool, any bool) {
	if file == nil {
		return nil, true
	}
	names = map[string]bool{}
	add := func(name string) {
		names[name] = true
		names[name[strings.LastIndexByte(name, '/')+1:]] = true
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if any {
			return false
		}
		switch node := node.(type) {
		case *syntax.CallExpr:
			for index, word := range node.Args {
				text := word.Lit()
				if text == "" {
					if index == 0 {
						any = true
					}
					continue
				}
				if index == 0 {
					add(text)
				}
				if shellStartupCodeRunners[text[strings.LastIndexByte(text, '/')+1:]] {
					any = true
				}
			}
		case *syntax.DeclClause:
			if node.Variant != nil {
				add(node.Variant.Value)
			}
		case *syntax.LetClause:
			add("let")
		}
		return true
	})
	return names, any
}
