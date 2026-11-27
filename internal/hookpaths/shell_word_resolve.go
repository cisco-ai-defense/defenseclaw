// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io"
	"path/filepath"
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

// MaxResolvedCandidates bounds the paths one word may expand to, counted by
// a bounded.Counter on bounded.Paths (the one bound rule, rel-1-0-10
// GAP-0301): a word past it is truncated, so uncertain, never cut short and
// never judged below the unknown tier.
const MaxResolvedCandidates = 256

// shellGlobOptions are the bash options that change pathname expansion. The
// resolver models dotGlob, noCaseGlob, nullGlob, failGlob, noGlob and
// globStar exactly; extGlob changes only the parse (an extglob word is never
// modeled). It does not model the GLOBIGNORE filter (globIgnore) or options
// the command may change in a way it does not spell (unknown): a word with an
// active glob character is uncertain then. may holds the options a statement
// of the call itself may turn either way (globOptionsInCall): the word is read
// under each value.
type shellGlobOptions struct {
	dotGlob, noCaseGlob, nullGlob, failGlob, noGlob bool
	globStar, extGlob, globIgnore, unknown          bool
	may                                             uint8
}

// unmodeled reports an option state the resolver cannot expand exactly.
func (o shellGlobOptions) unmodeled() bool {
	return o.globIgnore || o.unknown
}

// shellGlobOptionsFromEnv reads the options a non-interactive bash imports
// from the call's environment: BASHOPTS (dotglob, nocaseglob, nullglob,
// failglob, extglob, globstar), SHELLOPTS (noglob) and GLOBIGNORE (a filter
// the resolver does not model). An option a startup file sets is the
// startup's business (ShellStartup).
func shellGlobOptionsFromEnv(getenv func(string) string) shellGlobOptions {
	var o shellGlobOptions
	for _, name := range strings.Split(getenv("BASHOPTS"), ":") {
		bit, glob := shoptGlobBits[name]
		if glob && bit == 0 {
			o.extGlob = true
		}
		for _, f := range globMayFields {
			if glob && bit == f.bit {
				*f.field(&o) = true
			}
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

// shellGlobOptionsForCall is the options a call's glob words are expanded
// with: the agent's environment (the client's header for a per-user gateway,
// startup.glob) and what the call's own statements may set
// (globOptionsInCall, rel-1-0-10:GAP-0380).
func shellGlobOptionsForCall(command string, startup ShellStartup) shellGlobOptions {
	return globOptionsInCall(command, startup.glob)
}

// resolvedWord is what one shell word names on the disk: every candidate
// path bash may pass, or the class that keeps it uncertain.
type resolvedWord struct {
	candidates []string
	uncertain  string
	// caps are the caps the word hit (bounded.Paths past the candidate
	// bound); a hit also sets uncertain to wordUncertainTruncated.
	caps bounded.CapSet
	// literal is the word as bash passes it when its pattern matches
	// nothing (quotes removed, pattern characters as written), for a word
	// that is uncertain only because the pattern form or a glob option is
	// not modeled: the one candidate that is always possible, which the
	// caller still checks by identity (GAP-0415). "" for any other word.
	literal string
	// superset is, for a word that is uncertain only because its pattern
	// form or a glob option is not modeled, every path a WIDER reading names
	// in folders the walk sees completely (resolverSuperset), the literal
	// word included. No reading bash may take names a path outside it, so a
	// superset with no protected file proves the word names none
	// (UncertainGlobWriteReason). nil when the wider walk is not complete.
	superset []string
	// preGlob marks a word uncertain before any pathname expansion: an
	// unknown parameter, a command or process substitution, an arithmetic
	// or brace part, a word that splits. An extglob form is a glob form, not
	// preGlob (UncertainGlobWriteReason).
	preGlob bool
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
	if opts.may != 0 {
		return resolveShellWordReadings(word, values, cwd, opts)
	}
	if word == nil || !filepath.IsAbs(cwd) {
		return resolvedWord{uncertain: wordUncertainDynamic, preGlob: true}
	}
	if !resolverWordKnown(word, values) {
		if !resolverWordHasExtGlob(word) {
			return resolvedWord{uncertain: wordUncertainDynamic, preGlob: true}
		}
		out := resolvedWord{uncertain: wordUncertainDynamic}
		if wide, ok := resolverExtGlobWide(word, values, cwd); ok {
			// The literal bash passes when nothing matches is a name in the
			// same folder: the wide pattern stands in for it.
			out.superset = resolverSuperset(wide, OperandPath(wide, cwd), cwd, values["HOME"])
		}
		return out
	}
	home := values["HOME"]
	cfg := resolverConfig(values, cwd)
	pattern, ok := resolverPattern(word, cfg, home)
	if !ok {
		return resolvedWord{uncertain: wordUncertainDynamic, preGlob: true}
	}
	// Quote removal with globbing disabled (cfg has no ReadDir): the word
	// as the shell passes it when nothing is expanded.
	fields, err := expand.Fields(cfg, word)
	if err != nil || len(fields) != 1 {
		return resolvedWord{uncertain: wordUncertainDynamic, preGlob: true}
	}
	literalText := fields[0]
	if !resolverPatternActive(pattern) {
		return resolvedWord{candidates: resolverCandidates([]string{literalText}, cwd, false)}
	}
	switch {
	case opts.unmodeled(), !resolverPatternModeled(pattern) && !opts.noGlob:
		literal := OperandPath(literalText, cwd)
		return resolvedWord{uncertain: wordUncertainDynamic, literal: literal, superset: resolverSuperset(pattern, literal, cwd, home)}
	case opts.noGlob:
		return resolvedWord{candidates: resolverCandidates([]string{literalText}, cwd, false)}
	}
	base := ""
	if !filepath.IsAbs(pattern) {
		base = filepath.Clean(cwd)
	}
	hidden := actionGlobViewHidden(cwd, home)
	userView := !hidden && actionProcessOwnsHome(home)
	dots := func() bool { return opts.dotGlob || actionShellProfileMayDotglob(home) }
	matches, complete, unseen, capped := actionExpandGlobWalk(OperandPath(pattern, cwd), base, hidden, userView, dots, opts.noCaseGlob, opts.globStar)
	var truncated bounded.Truncated
	candidates := bounded.NewCounter(&truncated, bounded.Paths, MaxResolvedCandidates)
	switch {
	case capped:
		// A walk that read every folder it reached and stopped only at a
		// counted bound is TRUNCATED, as a result past MaxResolvedCandidates
		// is: the bound rule judges it, on the hook call
		// (rel-1-0-10:GAP-1324).
		cut := bounded.Of(bounded.Paths)
		noteGlobCut(cut)
		return resolvedWord{uncertain: wordUncertainTruncated, caps: cut}
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
		switch {
		case whole.uncertain == "":
			whole.uncertain, whole.preGlob, whole.superset = value.uncertain, value.preGlob, value.superset
			if whole.superset != nil {
				whole.superset = append(whole.superset, whole.candidates...)
			}
		case value.uncertain != "":
			whole.superset = nil // the value's own reading is not proven
		case whole.superset != nil:
			whole.superset = append(whole.superset, value.candidates...)
		}
		return whole
	}
	if whole.uncertain != "" {
		// The program receives the word as bash passes it when nothing
		// matches, and writes the value after the equals sign: that value is
		// the literal candidate (dd of=PATTERN), not the whole word. The
		// wider reading names the value too: the value read alone, and the
		// value of each "name=value" file the wide walk names in the folder.
		if whole.superset != nil {
			value := resolveShellWord(tail, values, cwd, opts)
			switch {
			case value.uncertain == "":
				whole.superset = append(whole.superset, value.candidates...)
			case value.superset != nil:
				whole.superset = append(whole.superset, value.superset...)
			default:
				whole.superset = nil
			}
			for _, candidate := range whole.superset {
				if base := filepath.Base(candidate); filepath.Dir(candidate) == filepath.Clean(cwd) && strings.HasPrefix(base, name+"=") {
					whole.superset = append(whole.superset, OperandPath(strings.TrimPrefix(base, name+"="), cwd))
				}
			}
		}
		if whole.literal != "" {
			if fields, err := expand.Fields(resolverConfig(values, cwd), tail); err == nil && len(fields) == 1 {
				whole.literal = OperandPath(fields[0], cwd)
			}
		}
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
	if len(whole.candidates) == 0 && !opts.nullGlob && !opts.failGlob {
		// The whole word matched nothing, so the program receives it as
		// written and writes the value after the equals sign. Whether that
		// value names a file is a question for the value's folder, not the
		// whole word's (of=./key[9]: the folder of the whole word is "of=.",
		// which is not there): dd of=./key[9] writes ./key[9]
		// (rel-1-0-10:GAP-1289).
		whole.candidates = resolverCandidates([]string{fields[0]}, cwd, true)
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

// resolverPatternModeled reports a glob pattern the one walk expands as bash
// does: *, ?, ** (globstar's when it is on, *'s when off), backslash escapes
// and every bracket form (bashGlobMatch, rel-1-0-10:GAP-0378). The extglob
// openers ?( *( +( @( !( are not. A name whose match the user's locale or
// shell version decides leaves the walk incomplete, so uncertain.
func resolverPatternModeled(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '*', '?', '+', '@', '!':
			if i+1 < len(pattern) && pattern[i+1] == '(' {
				return false
			}
		}
	}
	return true
}

// resolverSuperset is every path a reading of pattern WIDER than any bash may
// take names, for a word the resolver cannot expand exactly (an extglob
// form, the GLOBIGNORE filter, options the call may change in a way it does
// not spell): each extglob group read as *, which matches every string the
// group matches, with dotglob, nocaseglob and globstar on and no filter
// (GLOBIGNORE, nullglob and failglob only drop names), plus the literal word.
// It returns nil when the wider walk is not complete (a folder it cannot see
// or read, a bound) or the pattern has a group it does not read: the word
// stays uncertain (rel-1-0-10:GAP-0378, GAP-0380).
func resolverSuperset(pattern, literal, cwd, home string) []string {
	wide, ok := resolverWidePattern(pattern)
	if !ok || actionGlobViewHidden(cwd, home) {
		return nil
	}
	base := ""
	if !filepath.IsAbs(wide) {
		base = filepath.Clean(cwd)
	}
	matches, complete, unseen := actionExpandGlobStar(OperandPath(wide, cwd), base, false,
		actionProcessOwnsHome(home), func() bool { return true }, true, true)
	if unseen || !complete || len(matches) >= MaxResolvedCandidates {
		return nil
	}
	return append(matches, literal)
}

// resolverExtGlobWide is the pattern of an extglob word with every group
// read as * (a group matches no string * does not), for a word whose other
// parts the resolver knows. ok is false for any other word, or a group that
// holds a slash.
func resolverExtGlobWide(word *syntax.Word, values actionValues, cwd string) (string, bool) {
	parts := make([]syntax.WordPart, 0, len(word.Parts))
	for _, part := range word.Parts {
		if group, isGroup := part.(*syntax.ExtGlob); isGroup {
			if group.Pattern == nil || strings.Contains(group.Pattern.Value, "/") {
				return "", false
			}
			part = &syntax.Lit{Value: "*"}
		}
		parts = append(parts, part)
	}
	wide := &syntax.Word{Parts: parts}
	if !resolverWordKnown(wide, values) {
		return "", false
	}
	return resolverPattern(wide, resolverConfig(values, cwd), values["HOME"])
}

// resolverWidePattern is pattern with every extglob group (?(..), *(..),
// +(..), @(..), !(..)) read as *. ok is false for a group that is not
// closed or that holds a slash.
func resolverWidePattern(pattern string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' && i+1 < len(pattern) {
			b.WriteString(pattern[i : i+2])
			i++
			continue
		}
		if strings.IndexByte("?*+@!", c) < 0 || i+1 >= len(pattern) || pattern[i+1] != '(' {
			b.WriteByte(c)
			continue
		}
		depth, j := 0, i+1
		for ; j < len(pattern); j++ {
			switch pattern[j] {
			case '\\':
				j++
				continue
			case '/':
				return "", false
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if j >= len(pattern) {
			return "", false
		}
		b.WriteByte('*')
		i = j
	}
	return b.String(), true
}

// resolveShellWordReadings is resolveShellWord for a word the call's own
// statements may expand under other options (opts.may): the word is read
// under each, and every path any reading names is a candidate. A reading
// that is uncertain keeps the word uncertain.
func resolveShellWordReadings(word *syntax.Word, values actionValues, cwd string, opts shellGlobOptions) resolvedWord {
	var out resolvedWord
	seen := map[string]bool{}
	supersetLost := false
	for _, reading := range globReadings(opts) {
		got := resolveShellWord(word, values, cwd, reading)
		for _, candidate := range got.candidates {
			if !seen[candidate] {
				seen[candidate] = true
				out.candidates = append(out.candidates, candidate)
			}
		}
		out.caps = out.caps.Union(got.caps)
		if out.uncertain == "" {
			out.uncertain, out.preGlob = got.uncertain, got.preGlob
		}
		if out.literal == "" {
			out.literal = got.literal
		}
		if got.uncertain != "" {
			// A reading's wider walk proves only that reading: the word is
			// proven only when every uncertain reading has one.
			if got.superset == nil {
				out.superset, supersetLost = nil, true
			} else if !supersetLost {
				out.superset = append(out.superset, got.superset...)
			}
		}
	}
	if out.superset != nil {
		out.superset = append(out.superset, out.candidates...) // the exact readings' paths too
	}
	return out
}

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
// resolverWordHasExtGlob reports an extglob part (?( *( +( @( !() in word.
func resolverWordHasExtGlob(word *syntax.Word) bool {
	found := false
	syntax.Walk(word, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.ExtGlob); ok {
			found = true
		}
		return !found
	})
	return found
}

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
				part.Slice != nil || part.Repl != nil || part.Index != nil ||
				part.NestedParam != nil || part.Flags != nil || len(part.Modifiers) != 0 {
				known = false
				break
			}
			// ${p:-word}, ${p-word}, ${p:+word}, ${p+word} of a parameter the
			// caller knows are read by the shell expander; any other
			// operator (assignment, error, trimming) is not.
			if part.Exp != nil && part.Exp.Op != syntax.DefaultUnset && part.Exp.Op != syntax.DefaultUnsetOrNull &&
				part.Exp.Op != syntax.AlternateUnset && part.Exp.Op != syntax.AlternateUnsetOrNull {
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
