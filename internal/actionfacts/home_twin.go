// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// HomeResolvedTwin returns the complete analysis of a partial POSIX action
// whose runtime expansions are all paths under the caller's home: words that
// start with an unquoted ~/, or with $HOME/ or ${HOME}/ (optionally inside
// double quotes), and are otherwise literal ("> ~/.ssh/authorized_keys",
// tee -a "$HOME/.ssh/authorized_keys"). Each such word is replaced by the same
// path under input.ActiveHome, single-quoted. && and || lists are read as
// sequences, as ShortCircuitListReduction reads them, and any other
// runtime-expanded redirect target that can only name a file is a placeholder
// path, as in DynamicRedirectTargetReduction.
//
// The twin assumes the shell's HOME is the caller's home, which holds for an
// agent's own shell unless the action changes it, so an action that mentions
// HOME anywhere else, or has a here-document, is declined. A caller may count
// a check about a path under the home that holds on the twin as holding for
// the action, but a check that fails on the twin proves nothing.
func HomeResolvedTwin(input Input) (twin Facts, ok bool) {
	defer func() {
		if recover() != nil {
			twin, ok = Facts{}, false
		}
	}()
	original, capture := analyzeWithRedirectTargets(input, "")
	if original.Parse.Status != StatusPartial || original.Parse.Dialect != DialectPOSIX ||
		!containsIssue(original.Parse.Issues, IssueDynamicWord) {
		return Facts{}, false
	}
	home := strings.TrimRight(original.ActiveHome, "/")
	if !posixShellHome(home) || strings.ContainsAny(home, "\x00\r\n") {
		return Facts{}, false
	}
	source := capture.source
	if sequence, listed := shortCircuitListSequence(source, false); listed {
		source = sequence
	}
	resolved, ok := homeResolvedSource(source, home)
	if !ok {
		return Facts{}, false
	}
	twin, capture = analyzeWithRedirectTargets(input, resolved)
	if !twin.Authoritative() {
		// A runtime-expanded redirect target the home does not resolve (a
		// filename pattern) becomes a static placeholder path, as in the
		// twin of DynamicRedirectTargetReduction.
		if static, _, ok := capture.twin(); ok {
			twin, _ = analyzeWithRedirectTargets(input, static)
		}
	}
	if !twin.Authoritative() || len(twin.Parse.Issues) != 0 ||
		twin.Parse.Dialect != DialectPOSIX || len(twin.Commands) == 0 {
		return Facts{}, false
	}
	return twin, true
}

// posixShellHome reports whether home, a normalized ActiveHome without a
// trailing slash, can be written for $HOME in a POSIX command: an absolute
// POSIX path, or a Windows drive path such as C:/Users/alice. The agents that
// run POSIX-shaped commands on Windows (Claude Code's Git Bash, Codex's
// PowerShell) read that spelling as the same directory, and without it a
// Windows home made every ~/ and $HOME/ write partial with no finding
// (GAP-0912).
func posixShellHome(home string) bool {
	if strings.HasPrefix(home, "/") {
		return true
	}
	return len(home) > 3 && isASCIILetter(home[0]) && home[1] == ':' && home[2] == '/'
}

// homeResolvedSource returns source with every home-anchored literal word
// replaced by its path under home.
func homeResolvedSource(source, home string) (string, bool) {
	if source == "" {
		return "", false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(strings.NewReader(source), "")
	if err != nil {
		return "", false
	}
	type span struct {
		start, end int
		path       string
	}
	var spans []span
	declined := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if declined {
			return false
		}
		switch typed := node.(type) {
		case *syntax.Redirect:
			declined = typed.Op == syntax.Hdoc || typed.Op == syntax.DashHdoc
		case *syntax.Word:
			target := typed
			suffix, anchored := homeAnchoredLiteralWord(typed)
			key := ""
			if !anchored {
				// dd of=$HOME/f, "of=$HOME/f", 'of='$HOME/f: the home word
				// after an option key; the whole word is respelled.
				key, suffix, anchored = optionHomeAnchoredPath(typed)
			}
			if !anchored {
				return true
			}
			start, end := int(target.Pos().Offset()), int(target.End().Offset())
			path := key + home + suffix
			if start < 0 || end <= start || end > len(source) ||
				strings.ContainsAny(path, "\x00\r\n") {
				declined = true
				return false
			}
			spans = append(spans, span{start: start, end: end, path: path})
			return false
		}
		return !declined
	})
	if declined || len(spans) == 0 {
		return "", false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var out, rest strings.Builder
	// A comment never runs, so a HOME inside one cannot change what ~ and
	// $HOME name (GAP-2473); the guard below reads the text without them.
	scan := withoutShellComments(source, syntax.LangPOSIX)
	last := 0
	for _, word := range spans {
		if word.start < last {
			return "", false
		}
		out.WriteString(source[last:word.start])
		rest.WriteString(scan[last:word.start])
		out.WriteString("'" + strings.ReplaceAll(word.path, "'", `'\''`) + "'")
		last = word.end
	}
	out.WriteString(source[last:])
	rest.WriteString(scan[last:])
	// Any other mention of HOME outside a comment (an assignment, export,
	// unset or read) could change what ~ and $HOME name when the command
	// runs.
	if strings.Contains(rest.String(), "HOME") {
		return "", false
	}
	return out.String(), true
}

// homeAnchoredLiteralWord returns the path below the home that word names
// when it starts with an unquoted ~/ or with a plain $HOME or ${HOME}
// (optionally inside double quotes) followed by "/", and the rest is literal
// text with no quoting escape and, outside quotes, no filename pattern.
func homeAnchoredLiteralWord(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) == 0 {
		return "", false
	}
	var suffix strings.Builder
	literal := func(value string, quoted bool) bool {
		if strings.ContainsAny(value, "\\\x00") || (!quoted && strings.ContainsAny(value, "*?[~")) {
			return false
		}
		suffix.WriteString(value)
		return true
	}
	anchored := false
	for index, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			if index == 0 && strings.HasPrefix(typed.Value, "~/") {
				anchored = true
				if !literal(typed.Value[1:], false) {
					return "", false
				}
				continue
			}
			if !anchored || !literal(typed.Value, false) {
				return "", false
			}
		case *syntax.SglQuoted:
			if !anchored || typed.Dollar || !literal(typed.Value, true) {
				return "", false
			}
		case *syntax.ParamExp:
			if index != 0 || !plainHomeParameter(typed) {
				return "", false
			}
			anchored = true
		case *syntax.DblQuoted:
			if typed.Dollar {
				return "", false
			}
			for inner, quotedPart := range typed.Parts {
				switch value := quotedPart.(type) {
				case *syntax.ParamExp:
					if index != 0 || inner != 0 || !plainHomeParameter(value) {
						return "", false
					}
					anchored = true
				case *syntax.Lit:
					if !anchored || !literal(value.Value, true) {
						return "", false
					}
				default:
					return "", false
				}
			}
		default:
			return "", false
		}
	}
	path := suffix.String()
	if !anchored || !strings.HasPrefix(path, "/") || path == "/" {
		return "", false
	}
	return path, true
}

// homeOptionKey is a literal option or operand key that ends at "=" (of=,
// --output=, --target-directory=).
var homeOptionKey = regexp.MustCompile(`^-{0,2}[A-Za-z_][A-Za-z0-9_-]*=$`)

// optionHomeAnchoredWord splits a word that is a literal key ending at "="
// followed by a home-anchored word ($HOME/..., ${HOME}/..., "$HOME/...")
// into the key and that home word. The shell expands HOME anywhere in a
// word, so dd of=$HOME/f writes the file of=<home>/f names, as the ~/,
// ~<login>/ and absolute spellings already read (GAP-2399).
func optionHomeAnchoredWord(word *syntax.Word) (*syntax.Lit, *syntax.Word, bool) {
	if word == nil || len(word.Parts) < 2 {
		return nil, nil, false
	}
	key, ok := word.Parts[0].(*syntax.Lit)
	if !ok || !homeOptionKey.MatchString(key.Value) {
		return nil, nil, false
	}
	rest := &syntax.Word{Parts: word.Parts[1:]}
	if _, anchored := homeAnchoredLiteralWord(rest); !anchored {
		return nil, nil, false
	}
	return key, rest, true
}

// optionHomeAnchoredPath reads a word that is an option key ending at "="
// and then a plain $HOME or ${HOME} followed by "/" and literal text, where
// the key may be literal, single-quoted or double-quoted and the home word
// may sit inside double quotes ("of=$HOME/f", 'of='$HOME/f, of="${HOME}/f").
// The shell expands HOME inside double quotes, so each of these writes the
// file of=$HOME/f names (GAP-2399). It returns the key and the path below
// the home.
func optionHomeAnchoredPath(word *syntax.Word) (string, string, bool) {
	if word == nil {
		return "", "", false
	}
	type piece struct {
		lit    string
		home   bool
		quoted bool
	}
	var pieces []piece
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			pieces = append(pieces, piece{lit: typed.Value})
		case *syntax.SglQuoted:
			if typed.Dollar {
				return "", "", false
			}
			pieces = append(pieces, piece{lit: typed.Value, quoted: true})
		case *syntax.ParamExp:
			if !plainHomeParameter(typed) {
				return "", "", false
			}
			pieces = append(pieces, piece{home: true})
		case *syntax.DblQuoted:
			if typed.Dollar {
				return "", "", false
			}
			for _, inner := range typed.Parts {
				switch value := inner.(type) {
				case *syntax.Lit:
					pieces = append(pieces, piece{lit: value.Value, quoted: true})
				case *syntax.ParamExp:
					if !plainHomeParameter(value) {
						return "", "", false
					}
					pieces = append(pieces, piece{home: true})
				default:
					return "", "", false
				}
			}
		default:
			return "", "", false
		}
	}
	var key, suffix strings.Builder
	homeAt := -1
	for index, item := range pieces {
		if item.home {
			homeAt = index
			break
		}
		if strings.ContainsAny(item.lit, "\\\x00") || (!item.quoted && strings.ContainsAny(item.lit, "*?[~$`")) {
			return "", "", false
		}
		key.WriteString(item.lit)
	}
	if homeAt < 1 || !homeOptionKey.MatchString(key.String()) {
		return "", "", false
	}
	for _, item := range pieces[homeAt+1:] {
		if item.home || strings.ContainsAny(item.lit, "\\\x00") ||
			(!item.quoted && strings.ContainsAny(item.lit, "*?[~")) {
			return "", "", false
		}
		suffix.WriteString(item.lit)
	}
	path := suffix.String()
	if !strings.HasPrefix(path, "/") || path == "/" {
		return "", "", false
	}
	return key.String(), path, true
}

// optionHomeRewriteWord is optionHomeAnchoredWord for a home word the
// trusted-home rewrite can spell as ActiveHome exactly.
func optionHomeRewriteWord(word *syntax.Word) (*syntax.Word, bool) {
	_, rest, ok := optionHomeAnchoredWord(word)
	if !ok || (!plainHomeRewriteWord(rest) && !quotedPlainHomeRewriteWord(rest)) {
		return nil, false
	}
	return rest, true
}

// withoutShellComments returns source with the text of every shell comment
// ("# ..." up to its line end) replaced by spaces, so every byte offset into
// source is unchanged. A comment is never run, so it cannot change what HOME,
// ~ or USERPROFILE name; the home twins read their raw-text HOME, USER and
// USERPROFILE guards from this text, and a trailing "# HOME" no longer turns
// a twin off (GAP-2473). Only comments the parser reports are blanked, so a
// "#" inside a word, a quote, $# or ${#x} is kept. source is returned
// unchanged when it has no "#" or does not parse.
func withoutShellComments(source string, lang syntax.LangVariant) string {
	if !strings.Contains(source, "#") {
		return source
	}
	file, err := syntax.NewParser(syntax.Variant(lang), syntax.KeepComments(true)).
		Parse(strings.NewReader(source), "")
	if err != nil {
		return source
	}
	out := []byte(source)
	syntax.Walk(file, func(node syntax.Node) bool {
		comment, ok := node.(*syntax.Comment)
		if !ok {
			return true
		}
		start, end := int(comment.Pos().Offset()), int(comment.End().Offset())
		if start < 0 || end <= start || end > len(out) || out[start] != '#' {
			return true
		}
		for i := start; i < end; i++ {
			if out[i] != '\n' && out[i] != '\r' {
				out[i] = ' '
			}
		}
		return true
	})
	return string(out)
}
