// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Uncertain classes of a shell word the resolver cannot settle. Each is an
// UnprovenReasonKey class: the call takes the pack's unknown tier, never a
// plain allow (rel-1-0-10 GAP-0293 review, one property: an operand is
// proven to name no protected file, or it is uncertain).
const (
	wordUncertainDynamic   = "dynamic-argument"
	wordUncertainUnread    = UnprovenTargetUnresolved
	wordUncertainTruncated = "shell-parse-bound"
)

// maxResolvedCandidates bounds the paths one word may expand to. A word past
// it is uncertain, not cut short.
const maxResolvedCandidates = 256

// shellGlobOptions are the bash options that change pathname expansion.
type shellGlobOptions struct {
	dotGlob, noCaseGlob, nullGlob, failGlob, extGlob, noGlob bool
}

// shellGlobOptionsFromEnv reads the options a non-interactive bash imports
// from the call's environment: BASHOPTS (dotglob, nocaseglob, nullglob,
// failglob, extglob), SHELLOPTS (noglob) and GLOBIGNORE (which turns dotglob
// on). An option a startup file sets is the startup's business
// (noDereferenceTouchStartupUnknown).
func shellGlobOptionsFromEnv(getenv func(string) string) shellGlobOptions {
	var o shellGlobOptions
	for _, name := range strings.Split(getenv("BASHOPTS"), ":") {
		switch name {
		case "dotglob":
			o.dotGlob = true
		case "nocaseglob":
			o.noCaseGlob = true
		case "nullglob":
			o.nullGlob = true
		case "failglob":
			o.failGlob = true
		case "extglob":
			o.extGlob = true
		}
	}
	for _, name := range strings.Split(getenv("SHELLOPTS"), ":") {
		if name == "noglob" {
			o.noGlob = true
		}
	}
	if getenv("GLOBIGNORE") != "" {
		o.dotGlob = true // read as dotglob: it only widens the candidates
	}
	return o
}

// resolvedWord is what one shell word names on the disk: every candidate
// path bash may pass, or the class that keeps it uncertain.
type resolvedWord struct {
	candidates []string
	uncertain  string
}

// resolveShellWord is the one reading of a write operand:
//
//  1. full quote removal in one place: single and double quotes, backslashes
//     and $'..' ANSI-C strings (hex, octal, \u escapes), with parameters
//     only from known values;
//  2. the result as a glob pattern whose quoted characters are escaped;
//  3. pathname expansion by bash's rules through the package's one glob walk
//     (actionExpandGlob: leading dots, read and name bounds, unreadable
//     directories), with dotglob, nocaseglob and noglob from opts. A pattern
//     that matches nothing is the LITERAL word (nullglob off), when the
//     directory it names exists.
//
// A command substitution, an unknown parameter, a brace or extended glob
// part, a directory the walk cannot read or a result past the bound is
// uncertain. The caller judges every candidate by identity.
func resolveShellWord(word *syntax.Word, values actionValues, cwd string, opts shellGlobOptions) resolvedWord {
	if word == nil || !filepath.IsAbs(cwd) || !resolverWordKnown(word, values) {
		return resolvedWord{uncertain: wordUncertainDynamic}
	}
	home := values["HOME"]
	pairs := []string{"PWD=" + cwd}
	for name, value := range values {
		if name != "PWD" {
			pairs = append(pairs, name+"="+value)
		}
	}
	cfg := &expand.Config{
		Env:     expand.ListEnviron(pairs...),
		NoUnset: true,
		CmdSubst: func(io.Writer, *syntax.CmdSubst) error {
			return errors.New("command substitution")
		},
		ProcSubst: func(*syntax.ProcSubst) (string, error) {
			return "", errors.New("process substitution")
		},
	}
	pattern, ok := resolverPattern(word, cfg, home)
	if !ok {
		return resolvedWord{uncertain: wordUncertainDynamic}
	}
	// Quote removal with globbing disabled (cfg has no ReadDir): the word
	// as the shell passes it when nothing is expanded.
	fields, err := expand.Fields(cfg, word)
	if err != nil || len(fields) != 1 {
		return resolvedWord{uncertain: wordUncertainDynamic}
	}
	literalText := fields[0]
	if opts.noGlob || !resolverPatternActive(pattern) {
		return resolvedWord{candidates: resolverCandidates([]string{literalText}, cwd, false)}
	}
	base := ""
	if !filepath.IsAbs(pattern) {
		base = filepath.Clean(cwd)
	}
	hidden := actionGlobViewHidden(cwd, home)
	userView := !hidden && actionProcessOwnsHome(home)
	dots := func() bool { return opts.dotGlob || actionShellProfileMayDotglob(home) }
	matches, complete, unseen := actionExpandGlobFold(OperandPath(pattern, cwd), base, hidden, userView, dots, opts.noCaseGlob)
	switch {
	case unseen || !complete:
		return resolvedWord{uncertain: wordUncertainUnread}
	case len(matches) > maxResolvedCandidates:
		return resolvedWord{uncertain: wordUncertainTruncated}
	case len(matches) > 0:
		return resolvedWord{candidates: matches}
	case opts.nullGlob || opts.failGlob:
		return resolvedWord{} // nothing is written
	}
	// An unmatched pattern is the literal word. The command writes it only
	// when its directory exists; a name under one that is not there names
	// nothing.
	return resolvedWord{candidates: resolverCandidates([]string{literalText}, cwd, true)}
}

func resolverCandidates(fields []string, cwd string, needParent bool) []string {
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if field == "" || strings.ContainsAny(field, "\x00\r\n") {
			continue
		}
		path := OperandPath(field, cwd)
		if needParent {
			if info, err := pathStat(filepath.Dir(path)); err != nil || !info.IsDir() {
				continue
			}
		}
		out = append(out, path)
	}
	return out
}

// resolverPattern is the word as a glob pattern: unquoted text as written
// (a backslash escapes), quoted and ANSI-C text with its glob characters
// escaped, a known unquoted parameter as its value.
func resolverPattern(word *syntax.Word, cfg *expand.Config, home string) (string, bool) {
	var b strings.Builder
	for index, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			value := part.Value
			if index == 0 && home != "" && (value == "~" || strings.HasPrefix(value, "~/")) {
				value = home + value[1:]
			}
			b.WriteString(value)
		case *syntax.SglQuoted, *syntax.DblQuoted:
			text, err := expand.Literal(cfg, &syntax.Word{Parts: []syntax.WordPart{part}})
			if err != nil {
				return "", false
			}
			b.WriteString(resolverEscape(text))
		case *syntax.ParamExp:
			text, err := expand.Literal(cfg, &syntax.Word{Parts: []syntax.WordPart{part}})
			if err != nil || strings.ContainsAny(text, " \t\r\n") {
				return "", false // field splitting: more than one word
			}
			b.WriteString(text)
		default:
			return "", false
		}
	}
	return b.String(), true
}

// resolverEscape makes text match only itself.
func resolverEscape(text string) string {
	if !strings.ContainsAny(text, "\\*?[]") {
		return text
	}
	var b strings.Builder
	for _, r := range text {
		if strings.ContainsRune("\\*?[]", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// resolverPatternActive reports an unescaped *, ? or [ in pattern.
func resolverPatternActive(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '*', '?', '[':
			return true
		}
	}
	return false
}

// shellWordNeedsResolver is the cheap syntactic test for a word whose
// shell expansion can differ from its plain value: a glob character in any
// part (quoted, escaped or active), an ANSI-C string, or a backslash. A word
// of plain text and plain parameters keeps its plain reading.
func shellWordNeedsResolver(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[\\") {
				return true
			}
		case *syntax.SglQuoted:
			if part.Dollar || strings.ContainsAny(part.Value, "*?[") {
				return true
			}
		case *syntax.DblQuoted:
			if part.Dollar {
				return true
			}
			for _, inner := range part.Parts {
				if lit, ok := inner.(*syntax.Lit); ok && strings.ContainsAny(lit.Value, "*?[\\") {
					return true
				}
			}
		case *syntax.ExtGlob:
			return true
		}
	}
	return false
}

// resolverWordKnown reports that every part of word is fixed text or a
// parameter whose value the caller knows (no length, slice, replace or
// indirection forms), so the expansion depends only on the disk.
func resolverWordKnown(word *syntax.Word, values actionValues) bool {
	known := true
	syntax.Walk(word, func(node syntax.Node) bool {
		if !known {
			return false
		}
		switch part := node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.BraceExp, *syntax.ExtGlob:
			known = false
		case *syntax.ParamExp:
			if part.Param == nil || part.Excl || part.Length || part.Width || part.IsSet ||
				part.Slice != nil || part.Repl != nil || part.Exp != nil || part.Index != nil ||
				part.NestedParam != nil || part.Flags != nil || len(part.Modifiers) != 0 {
				known = false
				break
			}
			if _, ok := values[part.Param.Value]; !ok {
				known = false
			}
		}
		return known
	})
	return known
}
