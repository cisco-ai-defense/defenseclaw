// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var activeUserTildeName = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]*$`)

var assignmentLikePrefix = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// ActiveUserTildeTwin returns command with every tilde-prefix that names
// the active user (~<user> or ~<user>/..., <user> the base name of
// activeHome, a POSIX or Git Bash drive home) spelled as activeHome. bash expands such a prefix from
// the password database, not from HOME, at the start of a word and after
// the first = of an assignment-shaped word (x=~u/f, dd of=~u/f), but not
// inside quotes, after a backslash or in a here-document body; a prefix
// with a quoted character is no tilde-prefix. As for /home/$USER
// (userHomeRewriteWord, GAP-2269), the user named by the home's base name
// is taken to be the active user: if it is another user, the word names
// that user's home, so the twin errs only toward a path under the active
// home. The twin is exact for every other word, so a check that holds on
// it holds for the command (GAP-2378). An assignment-shaped argument
// (dd of=~/f) has its ~ spelled as the home too when nothing in the
// command mentions HOME: bash expands it from HOME like a leading ~/,
// which the other readings already resolve. ok is false when there is no such
// prefix, the home is not a literal POSIX or drive path or the command
// does not parse.
func ActiveUserTildeTwin(command, activeHome string) (twin string, user string, ok bool) {
	home, valid := normalizeActiveHome(activeHome)
	home = strings.TrimRight(home, "/")
	if !valid || !posixShellHome(home) || !trustedPOSIXHomeLiteral.MatchString(home) {
		return "", "", false
	}
	user = path.Base(home)
	prefix := "~" + user
	if !activeUserTildeName.MatchString(user) || !strings.Contains(command, "~") {
		return "", "", false
	}
	homeFree := !strings.Contains(command, "HOME")
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return "", "", false
	}
	type span struct{ offset, length int }
	var spans []span
	at := func(word *syntax.Word, lit *syntax.Lit, index int, tilde string) {
		rest := lit.Value[index:]
		if !strings.HasPrefix(rest, tilde) {
			return
		}
		after := rest[len(tilde):]
		if after == "" && len(word.Parts) != 1 || after != "" && after[0] != '/' {
			return
		}
		spans = append(spans, span{int(lit.Pos().Offset()) + index, len(tilde)})
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
			at(typed, lit, 0, prefix)
			if match := assignmentLikePrefix.FindString(lit.Value); match != "" {
				at(typed, lit, len(match), prefix)
				if homeFree {
					at(typed, lit, len(match), "~")
				}
			}
		}
		return true
	})
	if len(spans) == 0 {
		return "", "", false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].offset < spans[j].offset })
	var out strings.Builder
	last := 0
	for _, item := range spans {
		end := item.offset + item.length
		if item.offset < last || end > len(command) || command[item.offset] != '~' {
			return "", "", false
		}
		out.WriteString(command[last:item.offset])
		out.WriteString(home)
		last = end
	}
	out.WriteString(command[last:])
	return out.String(), user, true
}

var msysDrivePrefix = regexp.MustCompile(`^/(?:cygdrive/)?([A-Za-z])(?:/|$)`)

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
// Only an unquoted or single-quoted literal at the start of a word is
// respelled. ok is false when there is no such word, the home is not a
// drive home or the command does not parse.
func MSYSDrivePathTwin(command, activeHome string) (string, bool) {
	home, valid := normalizeActiveHome(activeHome)
	if !valid || !posixShellHome(strings.TrimRight(home, "/")) || strings.HasPrefix(home, "/") ||
		!strings.Contains(command, "/") {
		return "", false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return "", false
	}
	type span struct {
		start, end int
		value      string
	}
	var spans []span
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.Redirect:
			if typed.Hdoc != nil {
				return false
			}
		case *syntax.Word:
			if len(typed.Parts) == 0 {
				return true
			}
			var value string
			start := 0
			switch part := typed.Parts[0].(type) {
			case *syntax.Lit:
				value, start = part.Value, int(part.Pos().Offset())
			case *syntax.SglQuoted:
				if part.Dollar {
					return true
				}
				value, start = part.Value, int(part.Pos().Offset())+1
			default:
				return true
			}
			match := msysDrivePrefix.FindStringIndex(value)
			if match == nil {
				return true
			}
			prefix := strings.TrimSuffix(value[:match[1]], "/")
			spans = append(spans, span{start, start + len(prefix), strings.TrimSuffix(MSYSDrivePath(prefix+"/"), "/")})
		}
		return true
	})
	if len(spans) == 0 {
		return "", false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var out strings.Builder
	last := 0
	for _, item := range spans {
		if item.start < last || item.end > len(command) || command[item.start] != '/' {
			return "", false
		}
		out.WriteString(command[last:item.start])
		out.WriteString(item.value)
		last = item.end
	}
	out.WriteString(command[last:])
	return out.String(), true
}
