// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// copyGlobOperand stands, in the argv a copy call is read from, for a source
// word that the shell expands at run time (a glob such as /etc/pam.d/*) but
// that cannot expand to an option. It is never a path the walk opens.
const copyGlobOperand = "\x00copy-glob"

// copyGlobOperandsAsNames reads each non-final copy word that expands at run
// time but starts with a fixed name character as one more source name. The
// shell never turns such a word into an option, so it cannot move the
// destination or make the copy keep links. Without this, cpOperands read any
// expanding word as "may be an option", left the destination unknown, and
// opened a global copy scope that made every later write of the command (a
// second cp, a mv, a redirect) an authorized-keys block, as for
// cp /etc/pam.d/* /backup/ && cp a b (rel-1-0-10:GAP-0018).
//
// The final word stays as read: a destination that is not static is unknown.
// A call with an option that takes its value from the next word, or any
// option the walk does not know, keeps the old reading, so a glob there may
// still be the value of -t or -S.
//
// A copy with a word, source or destination, that may name a protected file
// by its own text keeps the old reading, as globs that reach a protected file
// by name are decided by identity elsewhere (rel-1-0-10:GAP-0018 rows B2 and
// B3): the placeholder names nothing, so a copy out of or into another
// account's SSH folder, an .ssh folder the walk cannot tie to this home
// (rel-1-0-10:GAP-0944), or a credentials folder (~/.aws/*, ~/.net*,
// rel-1-0-10:GAP-0963) had no reading at all where rel blocks
// (copyGlobMayNameProtected). A copy the walk did not place in a folder (after
// a cd it cannot resolve) keeps the old reading for a relative glob, which may
// then reach any file; an absolute glob names the same files from any folder
// (rel-1-0-10:GAP-0960, GAP-0964).
func copyGlobOperandsAsNames(args []*syntax.Word, words []string, static []bool, home string, placed bool) ([]string, []bool) {
	if len(args) < 3 || len(words) != len(args) || len(static) != len(args) {
		return words, static
	}
	for i, arg := range args[1:] {
		if copyGlobMayNameProtected(arg, home) {
			return words, static
		}
		if !placed && !static[i+1] && !copyWordRooted(arg) {
			return words, static
		}
	}
	var out []string
	var outStatic []bool
	options := true
	for i := 1; i < len(args)-1; i++ {
		if static[i] {
			word := words[i]
			if options && word == "--" {
				options = false
			} else if options && strings.HasPrefix(word, "-") && word != "-" && !copyOptionKeepsNoValue(word) {
				return words, static
			}
			continue
		}
		if !copyWordKeepsFirstByte(args[i]) {
			return words, static
		}
		if out == nil {
			out, outStatic = slices.Clone(words), slices.Clone(static)
		}
		out[i], outStatic[i] = copyGlobOperand, true
	}
	if out == nil {
		return words, static
	}
	return out, outStatic
}

// copyOptionKeepsNoValue reports a static copy option that takes no value
// from the next word and is known to the walk.
func copyOptionKeepsNoValue(option string) bool {
	if strings.HasPrefix(option, "--") {
		switch option {
		case "--recursive", "--archive", "--verbose", "--force", "--interactive",
			"--no-clobber", "--update", "--dereference", "--no-dereference",
			"--preserve", "--parents", "--remove-destination", "--no-target-directory":
			return true
		}
		return false
	}
	for _, c := range option[1:] {
		if !strings.ContainsRune("abcdfHiLlnPpRrsTuvxZ", c) {
			return false
		}
	}
	return true
}

// copyWordKeepsFirstByte reports a word whose first part is a literal that
// starts with a name character, so no expansion of the rest can put a dash
// first.
func copyWordKeepsFirstByte(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	lit, ok := word.Parts[0].(*syntax.Lit)
	if !ok || lit.Value == "" {
		return false
	}
	c := lit.Value[0]
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '/' || c == '.' || c == '_' || c == '~'
}

// copyGlobProtectedPaths are the trailing paths a copy glob must not be able
// to name for the placeholder reading: the SSH folder and its authorized-keys
// files, DefenseClaw state, and one path for every row of the shared
// credentials-file table, so a row added there is covered here.
var copyGlobProtectedPaths = sync.OnceValue(func() [][]string {
	paths := [][]string{{".ssh"}, {".defenseclaw"}}
	for _, name := range AuthorizedKeysFiles {
		paths = append(paths, []string{name})
	}
	for _, probe := range actionfacts.CredentialFileShapeProbePaths() {
		if parts := strings.Split(strings.Trim(probe, "/"), "/"); len(parts) != 0 && parts[0] != "" {
			paths = append(paths, parts)
		}
	}
	return paths
})

// copyGlobMayNameProtected reports a copy word whose text may name a
// protected path (copyGlobProtectedPaths), or a folder on the way to one,
// read component by component in either slash spelling: a run of the word's
// components names the whole protected path (the word names it or a file
// below it) or, at the word's end, its first components (a folder on the way
// to it). A literal component must be the name, a pattern must match it, and
// the match needs at least one component with a literal piece, so a bare
// dir/* names nothing by its text. In a POSIX reading a pattern that does not start with
// a dot does not match a dot name; a Windows spelling does. A glob whose
// folder is the home itself (~/*, $HOME/.*) may reach every protected folder
// of the home.
func copyGlobMayNameProtected(word *syntax.Word, home string) bool {
	text, raw, windows := copyWordPatternText(word)
	components := strings.FieldsFunc(text, func(r rune) bool { return r == '/' || r == '\\' })
	if len(components) == 0 {
		return false
	}
	if last := components[len(components)-1]; strings.ContainsAny(last, "*?[") {
		dir := strings.TrimRight(raw[:max(0, len(raw)-len(last))], "/\\")
		if dir == "~" || dir == "$HOME" || dir == "${HOME}" || home != "" && path.Clean(filepath.ToSlash(dir)) == path.Clean(filepath.ToSlash(home)) {
			return true
		}
	}
	windows = windows || runtime.GOOS == "windows"
	for _, protected := range copyGlobProtectedPaths() {
		for start := range components {
			run := components[start:]
			if len(run) > len(protected) {
				run = run[:len(protected)]
			} else if start+len(run) != len(components) {
				continue
			}
			anchored, matched := false, true
			for k, component := range run {
				name := protected[k]
				if !strings.ContainsAny(component, "*?[") {
					if !strings.EqualFold(component, name) {
						matched = false
						break
					}
					anchored = true
					continue
				}
				if !windows && strings.HasPrefix(name, ".") && !strings.HasPrefix(component, ".") {
					matched = false
					break
				}
				if !actionGlobNameMatch(component, name) {
					matched = false
					break
				}
				anchored = anchored || actionGlobHasLiteral(component)
			}
			if matched && anchored {
				return true
			}
		}
	}
	return false
}

// copyWordPatternText spells a copy word as a pattern: literal parts as they
// are, any expansion as *. It also returns the raw text with $HOME kept, and
// whether the word is in a Windows spelling (a drive letter or a backslash
// separator).
func copyWordPatternText(word *syntax.Word) (text, raw string, windows bool) {
	var t, r strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			t.WriteString(part.Value)
			r.WriteString(part.Value)
		case *syntax.SglQuoted:
			t.WriteString(part.Value)
			r.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					t.WriteString(lit.Value)
					r.WriteString(lit.Value)
				} else {
					t.WriteByte('*')
					r.WriteString(copyWordParamText(inner))
				}
			}
		default:
			t.WriteByte('*')
			r.WriteString(copyWordParamText(part))
		}
	}
	text, raw = t.String(), r.String()
	windows = strings.Contains(text, `\`) || len(text) >= 2 && text[1] == ':'
	return text, raw, windows
}

func copyWordParamText(part syntax.WordPart) string {
	if param, ok := part.(*syntax.ParamExp); ok && param.Param != nil && param.Param.Value == "HOME" && param.Exp == nil && param.Slice == nil && param.Repl == nil && !param.Length && !param.Excl {
		if param.Short {
			return "$HOME"
		}
		return "${HOME}"
	}
	return "*"
}

// copyWordRooted reports a copy word whose first literal names a rooted place
// (/x, ~, a drive letter), so the files it names do not depend on the folder
// the call runs in.
func copyWordRooted(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	if param, ok := word.Parts[0].(*syntax.ParamExp); ok {
		return copyWordParamText(param) != "*"
	}
	lit, ok := word.Parts[0].(*syntax.Lit)
	if !ok || lit.Value == "" {
		return false
	}
	v := lit.Value
	return v[0] == '/' || v[0] == '~' || len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/')
}
