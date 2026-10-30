// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// activeUserTildeName is a login name bash can read as a tilde-prefix:
// passwd-legal characters, '@' included for directory (AD/sssd) logins
// such as user@domain (GAP-2378).
var activeUserTildeName = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._@+-]*$`)

var assignmentLikePrefix = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// ActiveUserTildeTwin returns command with every tilde-prefix that names
// the active user (~<user> or ~<user>/..., <user> the base name of
// activeHome, a POSIX or Git Bash drive home, or one of logins, the
// active account's login names from the OS identity) spelled as
// activeHome. bash expands such a prefix from the password database, not
// from HOME, at the start of a word and after the first = of an
// assignment-shaped word (x=~u/f, dd of=~u/f), but not inside quotes,
// after a backslash or in a here-document body; a prefix with a quoted
// character is no tilde-prefix. A login can differ from the home's base
// name (sssd /home/%d/%u) and carry '@' (user@domain); directory logins
// resolve case-insensitively, so the name is matched without case. As for
// /home/$USER (userHomeRewriteWord, GAP-2269), the user named by the
// home's base name is taken to be the active user: if it is another user,
// the word names that user's home, so the twin errs only toward a path
// under the active home. The twin is exact for every other word, so a
// check that holds on it holds for the command (GAP-2378). An
// assignment-shaped argument (dd of=~/f) has its ~ spelled as the home too
// when nothing in the command mentions HOME: bash expands it from HOME
// like a leading ~/, which the other readings already resolve. prefixes
// are the ~<user> spellings that were respelled. ok is false when there is
// no such prefix, the home is not a literal POSIX or drive path or the
// command does not parse.
func ActiveUserTildeTwin(command, activeHome string, logins ...string) (twin string, prefixes []string, ok bool) {
	home, valid := normalizeActiveHome(activeHome)
	home = strings.TrimRight(home, "/")
	if !valid || !posixShellHome(home) || !trustedPOSIXHomeLiteral.MatchString(home) ||
		!strings.Contains(command, "~") {
		return "", nil, false
	}
	var names []string
	for _, name := range append([]string{path.Base(home)}, logins...) {
		if activeUserTildeName.MatchString(name) {
			names = append(names, name)
		}
	}
	activeName := func(name string) bool {
		for _, candidate := range names {
			if strings.EqualFold(name, candidate) {
				return true
			}
		}
		return false
	}
	homeFree := !strings.Contains(withoutShellComments(command, syntax.LangBash), "HOME")
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(command), "")
	if err != nil {
		return "", nil, false
	}
	type span struct{ offset, length int }
	var spans []span
	at := func(word *syntax.Word, lit *syntax.Lit, index int, assignment bool) {
		rest := lit.Value[index:]
		if !strings.HasPrefix(rest, "~") {
			return
		}
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			if len(word.Parts) != 1 {
				return
			}
			end = len(rest)
		}
		name := rest[1:end]
		switch {
		case name == "":
			if !assignment || !homeFree {
				return
			}
		case activeName(name):
			if !slices.Contains(prefixes, rest[:end]) {
				prefixes = append(prefixes, rest[:end])
			}
		default:
			return
		}
		spans = append(spans, span{int(lit.Pos().Offset()) + index, end})
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.Redirect:
			// A here-document body is data: its tilde is not expanded.
			if typed.Hdoc != nil {
				return false
			}
		case *syntax.Word:
			if len(typed.Parts) == 0 {
				return true
			}
			lit, isLit := typed.Parts[0].(*syntax.Lit)
			if !isLit {
				return true
			}
			at(typed, lit, 0, false)
			if match := assignmentLikePrefix.FindString(lit.Value); match != "" {
				at(typed, lit, len(match), true)
			}
		}
		return true
	})
	if len(spans) == 0 {
		return "", nil, false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].offset < spans[j].offset })
	var out strings.Builder
	last := 0
	for _, item := range spans {
		end := item.offset + item.length
		if item.offset < last || end > len(command) || command[item.offset] != '~' {
			return "", nil, false
		}
		out.WriteString(command[last:item.offset])
		out.WriteString(home)
		last = end
	}
	out.WriteString(command[last:])
	return out.String(), prefixes, true
}

var msysDrivePrefix = regexp.MustCompile(`^/(?:cygdrive/)?([A-Za-z])(?:/|$)`)

// msysOptionKeyPrefix is a literal option or operand key ending at "="
// (of=, --output=) before an MSYS drive mount path in the same word.
var msysOptionKeyPrefix = regexp.MustCompile(`^-{0,2}[A-Za-z_][A-Za-z0-9_-]*=`)

// MSYSDrivePath returns the drive spelling (C:/x) of an MSYS or Cygwin
// drive mount path (/c/x, /cygdrive/c/x), and value unchanged otherwise.
func MSYSDrivePath(value string) string {
	match := msysDrivePrefix.FindStringSubmatchIndex(value)
	if match == nil {
		return value
	}
	drive := strings.ToUpper(value[match[2]:match[3]])
	rest := value[match[3]:]
	if rest == "" {
		rest = "/"
	}
	return drive + ":" + rest
}

// MSYSDrivePathTwin returns command with every word that starts with an
// MSYS or Cygwin drive mount (/c/..., /cygdrive/c/...) spelled as the drive
// path (C:/...), when activeHome is a Windows drive home: Git Bash, the
// shell Claude Code and other agents run there, maps those mounts to the
// drive for every program, so the twin names the same files (GAP-2375).
// The mount is read from the literal text of the word, quotes removed
// (/c/x, '/c/x', "/c/x", '/c'/x), at its start or right after a literal
// key ending at "=" (of=/c/..., 'of='/c/..., "of=/c/...", GAP-2468); the
// literal text ends at the first expansion. The same twin spells
// $USERPROFILE as $HOME (windowsProfileHomeTwin). ok is false when there
// is nothing to respell, the home is not a drive home or the command does
// not parse.
func MSYSDrivePathTwin(command, activeHome string) (string, bool) {
	home, valid := normalizeActiveHome(activeHome)
	if !valid || !posixShellHome(strings.TrimRight(home, "/")) || strings.HasPrefix(home, "/") {
		return "", false
	}
	command, profiled := windowsProfileHomeTwin(command)
	unchanged := func() (string, bool) {
		if profiled {
			return command, true
		}
		return "", false
	}
	if !strings.Contains(command, "/") {
		return unchanged()
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(command), "")
	if err != nil {
		return "", false
	}
	type span struct {
		start, end    int
		prefix, value string
	}
	var spans []span
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.Redirect:
			if typed.Hdoc != nil {
				return false
			}
		case *syntax.Word:
			pieces := msysWordLiteralPieces(typed)
			if len(pieces) == 0 {
				return true
			}
			var joined strings.Builder
			for _, piece := range pieces {
				joined.WriteString(piece.text)
			}
			value, skip := joined.String(), 0
			// A key ending at "=" may precede the mount in the same word
			// (dd of=/c/..., --output=/c/...): Git Bash maps that value to
			// the drive too (GAP-2399).
			if key := msysOptionKeyPrefix.FindStringIndex(value); key != nil && msysDrivePrefix.MatchString(value[key[1]:]) {
				value, skip = value[key[1]:], key[1]
			}
			match := msysDrivePrefix.FindStringIndex(value)
			if match == nil {
				return true
			}
			prefix := strings.TrimSuffix(value[:match[1]], "/")
			// The respelled prefix must sit inside one literal piece, so its
			// source bytes are the prefix itself.
			for _, piece := range pieces {
				if skip < len(piece.text) {
					if skip+len(prefix) <= len(piece.text) {
						start := piece.start + skip
						spans = append(spans, span{start, start + len(prefix), prefix, strings.TrimSuffix(MSYSDrivePath(prefix+"/"), "/")})
					}
					break
				}
				skip -= len(piece.text)
			}
		}
		return true
	})
	if len(spans) == 0 {
		return unchanged()
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var out strings.Builder
	last := 0
	for _, item := range spans {
		if item.start < last || item.end > len(command) || command[item.start:item.end] != item.prefix {
			return "", false
		}
		out.WriteString(command[last:item.start])
		out.WriteString(item.value)
		last = item.end
	}
	out.WriteString(command[last:])
	return out.String(), true
}

// msysLiteralPiece is a run of literal word text and the source offset of
// its first byte.
type msysLiteralPiece struct {
	text  string
	start int
}

// msysWordLiteralPieces returns the literal text of word up to its first
// expansion: unquoted literals, single-quoted strings and the literals of
// double-quoted strings, with their source offsets. A $'...' or $"..."
// string ends the literal text.
func msysWordLiteralPieces(word *syntax.Word) []msysLiteralPiece {
	var pieces []msysLiteralPiece
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			pieces = append(pieces, msysLiteralPiece{typed.Value, int(typed.Pos().Offset())})
		case *syntax.SglQuoted:
			if typed.Dollar {
				return pieces
			}
			pieces = append(pieces, msysLiteralPiece{typed.Value, int(typed.Pos().Offset()) + 1})
		case *syntax.DblQuoted:
			if typed.Dollar {
				return pieces
			}
			for _, inner := range typed.Parts {
				lit, isLit := inner.(*syntax.Lit)
				if !isLit {
					return pieces
				}
				pieces = append(pieces, msysLiteralPiece{lit.Value, int(lit.Pos().Offset())})
			}
		default:
			return pieces
		}
	}
	return pieces
}

// windowsProfileHomeTwin returns command with every plain $USERPROFILE or
// ${USERPROFILE} expansion spelled as $HOME, and whether it changed. Under
// Git Bash on a Windows home USERPROFILE is the profile directory that
// HOME names (C:\Users\<u> and /c/Users/<u>), so the twin names the same
// files, which the $HOME readings resolve (GAP-2468). It applies only when
// nothing in the command mentions HOME and every USERPROFILE in the text
// is such an expansion (no assignment, export, read or quoted name).
func windowsProfileHomeTwin(command string) (string, bool) {
	const name = "USERPROFILE"
	// A comment never runs, so its HOME or USERPROFILE text is not counted
	// (GAP-2473).
	scan := withoutShellComments(command, syntax.LangBash)
	if !strings.Contains(scan, name) || strings.Contains(scan, "HOME") {
		return command, false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(command), "")
	if err != nil {
		return command, false
	}
	var offsets []int
	syntax.Walk(file, func(node syntax.Node) bool {
		param, isParam := node.(*syntax.ParamExp)
		if !isParam || param.Param == nil || param.Param.Value != name {
			return true
		}
		if param.Excl || param.Length || param.Width || param.Index != nil || param.Slice != nil ||
			param.Repl != nil || param.Names != 0 || param.Exp != nil {
			return true
		}
		offsets = append(offsets, int(param.Param.Pos().Offset()))
		return true
	})
	if len(offsets) == 0 || len(offsets) != strings.Count(scan, name) {
		return command, false
	}
	sort.Ints(offsets)
	var out strings.Builder
	last := 0
	for _, offset := range offsets {
		if offset < last || offset+len(name) > len(command) || command[offset:offset+len(name)] != name {
			return command, false
		}
		out.WriteString(command[last:offset])
		out.WriteString("HOME")
		last = offset + len(name)
	}
	out.WriteString(command[last:])
	return out.String(), true
}
