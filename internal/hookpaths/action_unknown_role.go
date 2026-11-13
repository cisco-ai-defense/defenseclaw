// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A word that names a protected file as an argument of a program the scan has
// no model of is data of unknown role, not a proven write: ./send.sh "run echo
// x >> ~/.ssh/authorized_keys" hands text to a script, and a script named by a
// variable ($T send ...) is no better known. Only a program the scan models
// can be said to write its operand: the copy, link, move, archive, editor,
// download and shell writers, the interpreters and wrappers that run code, and
// the readers. Everything else is unknown, and its operands are not write
// targets (rel-1-0-10:GAP-0018; S7 lead 2026-11-13: unknown asks or alerts in
// the free default, and strict and managed installs keep the block).

// actionRoleKnownWriters are the programs, besides the lists of this package,
// that write, remove, change or run what they are given.
var actionRoleKnownWriters = strings.Fields(`rm rmdir unlink shred mkdir mkfifo mknod touch tee dd truncate
	sed gsed awk gawk mawk nawk perl ruby node deno bun php lua tclsh expect python python3 pwsh powershell cmd
	bash sh zsh dash ksh fish csh tcsh eval source exec env sudo doas su nohup timeout nice ionice setsid stdbuf command
	xargs find gfind ssh scp sftp rsync git curl wget aria2c patch install chmod chown chgrp chattr setfacl
	sort uniq tr gzip gunzip bzip2 xz zip unzip tar make cmake sqlite3 mysql psql openssl gpg ssh-keygen ssh-add
	vi vim nano emacs ed ex code open xdg-open sendmail mail`)

// actionRoleKnownProgram reports a program the scan models: one of its own
// lists or one of actionRoleKnownWriters.
func actionRoleKnownProgram(base string) bool {
	return slices.Contains(actionRoleKnownWriters, base) ||
		slices.Contains(linkPrograms, base) || slices.Contains(copyPrograms, base) ||
		slices.Contains(renamePrograms, base) || slices.Contains(cdPrograms, base) ||
		slices.Contains(multicallPrograms, base) || slices.Contains(archivePrograms, base) ||
		slices.Contains(dataPrograms, base) || slices.Contains(readerPrograms, base) ||
		slices.Contains(knownWordPrograms, base) || slices.Contains(readOnlyLinkWordPrograms, base) ||
		slices.Contains(hiddenDirectoryPrograms, base) || slices.Contains(lateTextPrograms, base)
}

// actionScriptInterpreters run a script file; actionInterpreterCodeFlags are the
// options after which the next word is program text (or a module), not a script.
var (
	actionScriptInterpreters   = strings.Fields("python python3 ruby node perl php lua deno bun")
	actionInterpreterCodeFlags = strings.Fields("-c -e -m -r -E -p")
)

// actionInterpreterScriptArguments reports a call of an interpreter that runs a
// script file (python3 run.py send "text"): the words after the script are
// that script's arguments, whose role the scan cannot know. An interpreter with
// -c, -e or a program text of its own is not that.
func actionInterpreterScriptArguments(words []*syntax.Word, home string) bool {
	if len(words) < 3 {
		return false
	}
	program, known := staticProgramWord(words[0], home)
	if !known {
		return false
	}
	if !slices.Contains(actionScriptInterpreters, programBase(program)) {
		return false
	}
	script := false
	for _, word := range words[1:] {
		value, known := StaticWord(word, home)
		if !known {
			return false
		}
		if strings.HasPrefix(value, "-") {
			if value == "-" || slices.ContainsFunc(actionInterpreterCodeFlags, func(flag string) bool { return strings.HasPrefix(value, flag) }) {
				return false
			}
			continue
		}
		script = true
		break
	}
	return script
}

// actionCallRoleUnknown reports a call whose program the scan does not model,
// or an interpreter's script call: the operands of such a call are data of
// unknown role. A wrapper (sudo, env, timeout) is looked through to the program
// it runs.
func actionCallRoleUnknown(call *syntax.CallExpr, home string) bool {
	if len(call.Args) < 2 {
		return false
	}
	words := call.Args
	if wrapped, ok := actionLiteralCommandWords(call.Args, home); ok && len(wrapped) != 0 {
		words = wrapped
	}
	program, known := staticProgramWord(words[0], home)
	if !known {
		return true
	}
	if actionInterpreterScriptArguments(words, home) {
		return true
	}
	base := programBase(program)
	// A program the scan does not list is unknown, bare name or path alike;
	// the GNU g prefix of a listed coreutil (gtee, gtruncate) is that coreutil.
	return !actionRoleKnownProgram(base) && !actionRoleKnownProgram(strings.TrimPrefix(base, "g"))
}
