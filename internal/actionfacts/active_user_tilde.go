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
// the active user (~<user> or ~<user>/..., <user> the base name of the
// POSIX activeHome) spelled as activeHome. bash expands such a prefix from
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
// prefix, the home is not a POSIX literal path or the command does not
// parse.
func ActiveUserTildeTwin(command, activeHome string) (twin string, user string, ok bool) {
	home, valid := normalizeActiveHome(activeHome)
	home = strings.TrimRight(home, "/")
	if !valid || !strings.HasPrefix(home, "/") || home == "" || !trustedPOSIXHomeLiteral.MatchString(home) {
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
