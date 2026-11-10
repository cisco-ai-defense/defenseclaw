// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// A shell call that a native Windows host runs (Git Bash runs the Claude Code
// Bash tool) names files in spellings the POSIX word reader does not read as
// the Windows file system does. The late reader reads each of them as that
// host does (GAP-1022-b):
//   - A drive path with a backslash separator (C:\dir\file) is a path to
//     Windows, but the POSIX reading of an unquoted word drops the backslash
//     and leaves a drive-relative name that no file has. It is read as the
//     path it spells (lateWindowsPathWord).
//   - A Git Bash drive mount (/c/dir, /cygdrive/c/dir) is the drive path.
//   - A /proc/self or /dev/fd link is read by the process that opens it,
//     which this reader cannot be (lateWindowsAlias).
//
// Linux and macOS read a backslash as an escape and have none of the others;
// the readers there are unchanged.

// lateHasPathBackslash reports an unquoted literal with a backslash that is a
// path separator: one before a letter, a digit, a dot, an underscore, a dash
// or a non-ASCII byte, and not half of an escaped backslash. A backslash
// before a space, a quote, a dollar, a backquote, a glob or an operator is a
// shell escape and stays one.
func lateHasPathBackslash(literal string) bool {
	for i := 0; i < len(literal); i++ {
		if literal[i] != 92 {
			continue
		}
		if i+1 >= len(literal) {
			return false
		}
		next := literal[i+1]
		if next == 92 {
			i++
			continue
		}
		if next >= 'a' && next <= 'z' || next >= 'A' && next <= 'Z' || next >= '0' && next <= '9' ||
			next == '.' || next == '_' || next == '-' || next >= 0x80 {
			return true
		}
	}
	return false
}

// lateWindowsPathWord returns word with every unquoted literal that spells a
// Windows path (lateHasPathBackslash) keeping its backslashes when the word
// is expanded; any other word is returned as it is.
func lateWindowsPathWord(word *syntax.Word) *syntax.Word {
	var parts []syntax.WordPart
	for i, item := range word.Parts {
		literal, ok := item.(*syntax.Lit)
		if !ok || !lateHasPathBackslash(literal.Value) {
			continue
		}
		if parts == nil {
			parts = slices.Clone(word.Parts)
		}
		clone := *literal
		clone.Value = strings.ReplaceAll(literal.Value, "\\", "\\\\")
		parts[i] = &clone
	}
	if parts == nil {
		return word
	}
	return &syntax.Word{Parts: parts}
}

// lateWindowsAlias reports a rooted word the process that opens it reads
// differently from the hook: the process-relative links of processRelativeLink
// (a /proc/self or /proc/thread-self cwd, root, exe, fd or map_files entry,
// and the /dev descriptor aliases) in any separator spelling. Git Bash
// provides them on a Windows host; the hook cannot read them for that
// process, so they stay unproved. A plain /proc/self entry such as status is
// an ordinary file.
func lateWindowsAlias(word string) bool {
	return processRelativeLink(strings.ReplaceAll(word, "\\", "/"))
}

// lateWindowsDrivePath is the drive path of a Git Bash drive mount, and word
// unchanged otherwise.
func lateWindowsDrivePath(word string) string {
	return actionfacts.MSYSDrivePath(word)
}
