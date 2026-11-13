// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"
)

// actionClientShellWordSyntax is the cheap test for a command with a word
// the shell expands into file names: a glob character, a backslash escape or
// an ANSI-C string. Plain commands skip the client's second decision.
func actionClientShellWordSyntax(command string) bool {
	return strings.ContainsAny(command, "*?[\\") || strings.Contains(command, "$'")
}

// ReplaceVerbShape reports the bounded mv, install or sed -i statement the
// replace-verb proof reads (rel-1-0-10 GAP-0293 review F7). It reads no
// file: a managed gateway checks it against the client's safe key.
func ReplaceVerbShape(command, cwd, home string) bool {
	if !filepath.IsAbs(cwd) || home == "" || actionWindowsHome(home) ||
		!strings.Contains(command, "mv") && !strings.Contains(command, "install") && !strings.Contains(command, "sed") {
		return false
	}
	call, _, ok := entryOnlyStatement(command, cwd, home)
	if !ok || len(call.Args) < 3 {
		return false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed {
		return false
	}
	words, ok := replaceVerbOperandWords(programBase(program), call.Args[1:], home)
	if !ok {
		return false
	}
	for _, word := range words {
		if !noDereferenceTouchLiteralWord(word) && (len(word.Parts) != 1 || actionSoleParameter(word) == "") {
			return false
		}
	}
	return true
}

// ReplaceVerbSafe is the replace-verb proof for a per-user gateway, which
// reads the same files as the hook client.
func ReplaceVerbSafe(command, cwd, home string) bool {
	return ReplaceVerbShape(command, cwd, home) && replaceVerbSafe(command, cwd, home)
}
