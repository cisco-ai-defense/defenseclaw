// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Uncertain classes of a shell word the resolver cannot settle. Each is an
// UnprovenReasonKey class (unprovenReasonTitles): the call takes the pack's
// unknown tier, never a plain allow (rel-1-0-10 GAP-0293 review, one
// property: an operand is PROVEN to name no protected file, or it is
// UNCERTAIN). A word the resolver does not model EXACTLY is uncertain; it is
// never approximated.
const (
	wordUncertainDynamic   = "dynamic-argument"
	wordUncertainUnread    = UnprovenTargetUnresolved
	wordUncertainTruncated = "shell-parse-bound"
)

// maxResolvedCandidates bounds the paths one word may expand to, counted by
// a bounded.Counter on bounded.Paths (the one bound rule, rel-1-0-10
// GAP-0301): a word past it is truncated, so uncertain, never cut short and
// never judged below the unknown tier.
const maxResolvedCandidates = 256

// shellGlobOptions are the bash options that change pathname expansion. The
// first group the resolver models exactly (dotGlob, noCaseGlob, nullGlob,
// failGlob, noGlob); the second group it does not, so a word with an active
// glob character is uncertain whenever one of them may be on (globStar,
// extGlob, globIgnore), or may have been changed by the command itself
// (unknown).
type shellGlobOptions struct {
	dotGlob, noCaseGlob, nullGlob, failGlob, noGlob bool
	globStar, extGlob, globIgnore, unknown          bool
}

// unmodeled reports an option state the resolver cannot expand exactly.
func (o shellGlobOptions) unmodeled() bool {
	return o.globStar || o.extGlob || o.globIgnore || o.unknown
}

// shellGlobOptionsFromEnv reads the options a non-interactive bash imports
// from the call's environment: BASHOPTS (dotglob, nocaseglob, nullglob,
// failglob, extglob, globstar), SHELLOPTS (noglob) and GLOBIGNORE (a filter
// the resolver does not model). An option a startup file sets is the
// startup's business (ShellStartup).
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
		case "globstar":
			o.globStar = true
		}
	}
	for _, name := range strings.Split(getenv("SHELLOPTS"), ":") {
		if name == "noglob" {
			o.noGlob = true
		}
	}
	o.globIgnore = getenv("GLOBIGNORE") != ""
	return o
}

// globOptionsChangeText is the text that can change the glob options inside
// one call: shopt, set with an option, an assignment of GLOBIGNORE,
// BASHOPTS or SHELLOPTS, eval and source (they run text the scan does not
// read), a nested bash with -O or -o. Read as text on purpose: every later
// glob word of such a call is uncertain.
var globOptionsChangeText = regexp.MustCompile(`shopt|GLOBIGNORE|BASHOPTS|SHELLOPTS|(^|[;&|(\s])(set\s+[-+]|eval\b|source\b|\.\s)|\bbash\s+[^|;&]*-[Oo]`)

// globOptionsMayChange reports a command whose glob options the scan cannot
// know at a later word.
func globOptionsMayChange(command string) bool { return globOptionsChangeText.MatchString(command) }

// shellGlobOptionsForCall is the options a call's glob words are expanded
// with: the agent's environment (the client's header for a per-user gateway,
// startup.glob), and unknown when the call itself may change them.
func shellGlobOptionsForCall(command string, startup ShellStartup) shellGlobOptions {
	o := startup.glob
	if globOptionsMayChange(command) {
		o.unknown = true
	}
	return o
}

// resolvedWord is what one shell word names on the disk: every candidate
// path bash may pass, or the class that keeps it uncertain.
type resolvedWord struct {
	candidates []string
	uncertain  string
	// caps are the caps the word hit (bounded.Paths past the candidate
	// bound); a hit also sets uncertain to wordUncertainTruncated.
	caps bounded.CapSet
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
// Step 3 is exact only for the glob subset that Go's matcher reads as bash
// does: * and ?, a bracket set of literal members, and a digit range. Any
// other form (a negated or class bracket expression, extglob, **), any
// option the resolver does not model (opts.unmodeled) and any command that
// may change the options before the word is UNCERTAIN, as are a command
// substitution, an unknown parameter, a brace part, a directory the walk
// cannot read and a result past the bound. The caller judges every
// candidate by identity.
func resolveShellWord(word *syntax.Word, values actionValues, cwd string, opts shellGlobOptions) resolvedWord {
	if word == nil || !filepath.IsAbs(cwd) || !resolverWordKnown(word, values) {
		return resolvedWord{uncertain: wordUncertainDynamic}
	}
	home := values["HOME"]
	cfg := resolverConfig(values, cwd)
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
	if !resolverPatternActive(pattern) {
		return resolvedWord{candidates: resolverCandidates([]string{literalText}, cwd, false)}
	}
	switch {
	case opts.unmodeled():
		return resolvedWord{uncertain: wordUncertainDynamic}
	case opts.noGlob:
		return resolvedWord{candidates: resolverCandidates([]string{literalText}, cwd, false)}
	case !resolverPatternModeled(pattern):
		return resolvedWord{uncertain: wordUncertainDynamic}
	}
	base := ""
	if !filepath.IsAbs(pattern) {
		base = filepath.Clean(cwd)
	}
	hidden := actionGlobViewHidden(cwd, home)
	userView := !hidden && actionProcessOwnsHome(home)
	dots := func() bool { return opts.dotGlob || actionShellProfileMayDotglob(home) }
	matches, complete, unseen := actionExpandGlobFold(OperandPath(pattern, cwd), base, hidden, userView, dots, opts.noCaseGlob)
	var truncated bounded.Truncated
	candidates := bounded.NewCounter(&truncated, bounded.Paths, maxResolvedCandidates)
	switch {
	case unseen || !complete:
		return resolvedWord{uncertain: wordUncertainUnread}
	case !candidates.TakeN(len(matches)):
		return resolvedWord{uncertain: wordUncertainTruncated, caps: truncated.Set(&candidates)}
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

// resolveWriteWord is resolveShellWord for an operand of a write verb. Bash
// globs the WHOLE word, so a word with an attached value (dd of=PATH,
// --output=PATH) is read as bash reads it: when its pattern part matches
// nothing, the program receives the literal word and writes the value after
// the equals sign; when it matches a file whose name is "name=value" in the
// working directory, the program receives that name and writes its value.
// Any other match is uncertain. Without a glob character the value after the
// equals sign is the operand too.
func resolveWriteWord(word *syntax.Word, values actionValues, cwd string, opts shellGlobOptions) resolvedWord {
	whole := resolveShellWord(word, values, cwd, opts)
	tail, name, attached := resolverAttachedValue(word)
	if !attached {
		return whole
	}
	if _, active := resolverWordPattern(word, values, cwd); !active {
		value := resolveShellWord(tail, values, cwd, opts)
		whole.candidates = append(whole.candidates, value.candidates...)
		whole.caps = whole.caps.Union(value.caps)
		if whole.uncertain == "" {
			whole.uncertain = value.uncertain
		}
		return whole
	}
	if whole.uncertain != "" {
		return whole
	}
	fields, err := expand.Fields(resolverConfig(values, cwd), tail)
	if err != nil || len(fields) != 1 {
		whole.uncertain = wordUncertainDynamic
		return whole
	}
	literalWhole, err := expand.Fields(resolverConfig(values, cwd), word)
	if err != nil || len(literalWhole) != 1 {
		whole.uncertain = wordUncertainDynamic
		return whole
	}
	literalPath := OperandPath(literalWhole[0], cwd)
	var values2 []string
	for _, candidate := range whole.candidates {
		base := filepath.Base(candidate)
		switch {
		case candidate == literalPath:
			values2 = append(values2, OperandPath(fields[0], cwd))
		case filepath.Dir(candidate) == filepath.Clean(cwd) && strings.HasPrefix(base, name+"="):
			values2 = append(values2, OperandPath(strings.TrimPrefix(base, name+"="), cwd))
		default:
			whole.uncertain = wordUncertainDynamic
			return whole
		}
	}
	whole.candidates = values2
	return whole
}

// resolverConfig is the quote-removal environment: known values only, no
// command or process substitution, no globbing.
func resolverConfig(values actionValues, cwd string) *expand.Config {
	pairs := []string{"PWD=" + cwd}
	for name, value := range values {
		if name != "PWD" {
			pairs = append(pairs, name+"="+value)
		}
	}
	return &expand.Config{
		Env:     expand.ListEnviron(pairs...),
		NoUnset: true,
		CmdSubst: func(io.Writer, *syntax.CmdSubst) error {
			return errors.New("command substitution")
		},
		ProcSubst: func(*syntax.ProcSubst) (string, error) {
			return "", errors.New("process substitution")
		},
	}
}

// resolverWordPattern is the word as the glob pattern the shell expands,
// when it holds an active glob character. The mention scan records and
// judges this pattern for the words the resolver reads, not the plain value
// that spells a quoted bracket as a pattern character.
func resolverWordPattern(word *syntax.Word, values actionValues, cwd string) (string, bool) {
	if word == nil || !resolverWordKnown(word, values) {
		return "", false
	}
	pattern, ok := resolverPattern(word, resolverConfig(values, cwd), values["HOME"])
	if !ok || !resolverPatternActive(pattern) {
		return "", false
	}
	return pattern, true
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

// resolverPatternModeled reports a glob pattern in the subset whose match
// Go's matcher and bash agree on exactly: * and ? (no **, and none of the
// extglob openers ?( *( +( @( !( ), and a bracket set of literal members
// with an optional digit range. A negated set ([! or [^), a class or
// collating form ([: [= [.), an escape inside the set, a set that starts
// with ] or has no closing ], and a letter range (the order of letters
// follows the locale in bash) are not.
func resolverPatternModeled(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '*':
			if i+1 < len(pattern) && (pattern[i+1] == '*' || pattern[i+1] == '(') {
				return false
			}
		case '?', '+', '@', '!':
			if i+1 < len(pattern) && pattern[i+1] == '(' {
				return false
			}
		case '[':
			j := i + 1
			if j >= len(pattern) || pattern[j] == '!' || pattern[j] == '^' || pattern[j] == ']' {
				return false
			}
			closed := false
			for ; j < len(pattern); j++ {
				ch := pattern[j]
				if ch == ']' {
					closed = true
					break
				}
				if ch == '[' || ch == '\\' {
					return false
				}
				if ch == '-' {
					if j == i+1 || j+1 >= len(pattern) || !isASCIIDigit(pattern[j-1]) || !isASCIIDigit(pattern[j+1]) || pattern[j-1] > pattern[j+1] {
						return false
					}
				}
			}
			if !closed {
				return false
			}
			i = j
		}
	}
	return true
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// resolverAttachedValue is the word after the equals sign of an attached
// option value (dd of=PATH, --output=PATH) and the text before it: the text
// after the first equals sign of the word's leading literal and the rest of
// the word.
func resolverAttachedValue(word *syntax.Word) (*syntax.Word, string, bool) {
	if word == nil || len(word.Parts) == 0 {
		return nil, "", false
	}
	lit, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return nil, "", false
	}
	name, rest, found := strings.Cut(lit.Value, "=")
	if !found || name == "" || strings.ContainsAny(name, "*?[\\/ ") {
		return nil, "", false
	}
	parts := make([]syntax.WordPart, 0, len(word.Parts))
	if rest != "" {
		parts = append(parts, &syntax.Lit{Value: rest})
	}
	parts = append(parts, word.Parts[1:]...)
	if len(parts) == 0 {
		return nil, "", false
	}
	return &syntax.Word{Parts: parts}, name, true
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
