// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	// psBoundValueMaxRunes bounds one value a variable is bound to; a longer
	// value is not tracked.
	psBoundValueMaxRunes = 8 << 10
	// psBoundAlternatives bounds the values one variable holds at once (the
	// ways control flow can have bound it) and so the readings of a command.
	// It is set far above any ordinary script: past it the command counts as
	// past its bound (a value dropped without a trace could be the protected
	// one), so an ordinary command never gets there.
	psBoundAlternatives = 64
	// psBoundExactValues is how many values one variable holds each on its
	// own; from there on a value the proof cannot tell from a held one adds
	// no reading (psAddValue).
	psBoundExactValues = 8
	// psBoundCombinations bounds the strings one interpolated literal can
	// hold before they are deduplicated.
	psBoundCombinations = 4 * psBoundAlternatives
	// psBoundTextMaxBytes bounds the text of one value being built.
	psBoundTextMaxBytes = 4 * psBoundValueMaxRunes
	// psBoundLoopRounds bounds the extra passes over a loop whose values are
	// still growing; past it the command counts as past its bound.
	psBoundLoopRounds = 2
)

// psBindings maps a variable (lower case) to the values it can hold at the
// point being read. A variable that control flow bound to different values on
// different paths holds all of them; one that is unknown is absent. The
// slices are never changed in place.
type psBindings map[string][]string

func (b psBindings) clone() psBindings {
	c := make(psBindings, len(b))
	for name, values := range b {
		c[name] = values
	}
	return c
}

func (b psBindings) size() int {
	n := 0
	for _, values := range b {
		n += len(values)
	}
	return n
}

// psMerger is what the proof knows about where a value lands: the user home,
// the working directory a relative path is resolved against, and the paths
// the hook client found to be links.
type psMerger struct {
	home, cwd string
	links     map[string]bool
}

func newPSMerger(home, cwd string, targets map[string]string) psMerger {
	return psMerger{home: home, cwd: cwd, links: psLinkSpellings(targets, cwd)}
}

// psLinkKey is a path as the link set holds it: lower case, backslashes, no
// trailing separator.
func psLinkKey(path string) string {
	return strings.ToLower(strings.TrimRight(strings.ReplaceAll(path, "/", `\`), `\`))
}

// psLinkSpellings returns the paths (psLinkKey) that the resolved-target map
// of the hook client places somewhere other than where they are spelled:
// links and hard links onto other files, directories and the paths of client
// facts about them, also as a relative spelling resolved against cwd.
func psLinkSpellings(targets map[string]string, cwd string) map[string]bool {
	var links map[string]bool
	for key, target := range targets {
		path := key
		if strings.HasPrefix(path, "\x00") {
			// A client fact about a path is keyed "\x00<fact>:<path>".
			i := strings.IndexByte(path, ':')
			if i < 0 {
				continue
			}
			path = path[i+1:]
		}
		if path == "" || psLinkKey(path) == psLinkKey(target) {
			continue
		}
		if links == nil {
			links = map[string]bool{}
		}
		links[psLinkKey(path)] = true
		if abs, ok := psResolveRelative(cwd, path); ok {
			links[psLinkKey(abs)] = true
		}
	}
	return links
}

// psResolveRelative returns a relative path of plain segments (no drive, not
// rooted, no stream) as the absolute path it names under the drive path cwd.
func psResolveRelative(cwd, path string) (string, bool) {
	if len(cwd) < 3 || cwd[1] != ':' || strings.ContainsRune(path, ':') {
		return "", false
	}
	path = strings.ReplaceAll(path, "/", `\`)
	for strings.HasPrefix(path, `.\`) {
		path = path[2:]
	}
	if path == "" || path == "." || strings.HasPrefix(path, `\`) {
		return "", false
	}
	return strings.TrimRight(cwd, `\/`) + `\` + path, true
}

// pinned reports a value that can stand for a path the hook client placed
// somewhere else (a link onto other state): the link itself, a path under it,
// or a path text appended to the value completes to it (a directory that holds
// the link, a name cut short). Where such a path lands cannot be read from its
// shape, so it is never merged with another value. A sibling name that only
// starts with the link text and goes on in the same segment (the link name
// with more name after it) is another name and is not pinned.
func (m psMerger) pinned(value string) bool {
	if len(m.links) == 0 {
		return false
	}
	candidates := []string{psLinkKey(value)}
	if abs, ok := psResolveRelative(m.cwd, value); ok {
		candidates = append(candidates, psLinkKey(abs))
	}
	for _, candidate := range candidates {
		for link := range m.links {
			if strings.HasPrefix(link, candidate) || psIsOrUnderLink(candidate, link) {
				return true
			}
		}
	}
	return false
}

// psIsOrUnderLink reports a path key that is the link or goes on below it.
// The link name followed by dots or blanks is the same name (Windows drops
// them), and a stream suffix or a separator after it goes on below the link.
// Any other text after the link name is a sibling name, not a path under it.
func psIsOrUnderLink(path, link string) bool {
	if !strings.HasPrefix(path, link) {
		return false
	}
	rest := strings.TrimLeft(path[len(link):], ". ")
	return rest == "" || rest[0] == '\\' || rest[0] == ':'
}

// psAddValue returns values with value added when it is new. From
// psBoundExactValues values on, a value the proof cannot tell from one it
// holds (psMerger.signature) is that value; a new value that does not fit
// below psBoundAlternatives is dropped and sets *overflow.
func psAddValue(values []string, value string, m psMerger, overflow *bool) []string {
	if slices.Contains(values, value) {
		return values
	}
	if len(values) >= psBoundExactValues {
		if signature, ok := m.signature(value); ok {
			for _, held := range values {
				if held, ok := m.signature(held); ok && held == signature {
					return values
				}
			}
		}
	}
	if len(values) >= psBoundAlternatives {
		*overflow = true
		return values
	}
	return append(values[:len(values):len(values)], value)
}

// signature identifies a value the proof reads the same as every value with
// its signature: a path of plain segments that is not in DefenseClaw state
// and that the hook client did not find to be a link. Such a path, and any
// path made from it by appending text (a child, a ".." walk back up and down
// a name), is judged only by how many segments it has, how many of its
// leading segments the home shares (that decides where a walk up lands
// against the state directory) and whether it ends in a separator. A drive
// path, a relative path (resolved against the working directory) and a path
// under a remote server and share (a walk up stops at the share) are such
// paths. Anything else (a variable, a wildcard, a short name, a stream, a
// rooted path, a local server or administrative share, a segment that names
// the state directory or could be completed to it) has no signature and is
// held on its own.
func (m psMerger) signature(value string) (string, bool) {
	if m.pinned(value) {
		return "", false
	}
	trailing := strconv.FormatBool(strings.HasSuffix(value, `\`) || strings.HasSuffix(value, "/"))
	if segments, ok := psRemotePathSegments(value); ok {
		return "unc/" + strconv.Itoa(len(segments)) + "/" + trailing, true
	}
	if abs, ok := psResolveRelative(m.cwd, value); ok {
		value = abs
	}
	homeParts := strings.Split(strings.ToLower(strings.TrimRight(strings.ReplaceAll(m.home, "/", `\`), `\`)), `\`)
	parts, ok := psPlainPathSegments(value)
	if !ok {
		return "", false
	}
	shared := 0
	for shared < len(homeParts) && shared < len(parts) && homeParts[shared] == strings.ToLower(parts[shared]) {
		shared++
	}
	return strconv.Itoa(len(parts)) + "/" + strconv.Itoa(shared) + "/" + trailing, true
}

// psASCIILetter reports an ASCII letter.
func psASCIILetter(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// psPlainPathSegments splits an absolute drive path of plain segments.
func psPlainPathSegments(value string) ([]string, bool) {
	if len(value) < 3 || value[1] != ':' || value[2] != '\\' && value[2] != '/' || !psASCIILetter(rune(value[0])) {
		return nil, false
	}
	parts := strings.Split(strings.TrimRight(strings.ReplaceAll(value, "/", `\`), `\`), `\`)
	for _, part := range parts[1:] {
		if !psPlainSegment(part) {
			return nil, false
		}
	}
	return parts, true
}

// psPlainSegment reports a path segment that is not, and cannot be completed
// to, the state directory (.defenseclaw: a name that holds it and goes on,
// such as .defenseclaw_notes, is another name) or a name that stands for it
// (a trailing dot or blank, a short name, a stream), and has no character the
// proof reads specially.
func psPlainSegment(part string) bool {
	if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") ||
		strings.HasPrefix(".defenseclaw", strings.ToLower(part)) {
		return false
	}
	for _, c := range part {
		if !psASCIILetter(c) && (c < '0' || c > '9') && !strings.ContainsRune("_-. ()+#@,=", c) {
			return false
		}
	}
	return true
}

// psRemotePathSegments splits the part of a UNC path below its share when the
// server is a remote name and the share is not administrative. A walk up
// from such a path stops at the share, so only how many segments it has
// matters.
func psRemotePathSegments(value string) ([]string, bool) {
	value = strings.ReplaceAll(value, "/", `\`)
	if !strings.HasPrefix(value, `\\`) {
		return nil, false
	}
	parts := strings.Split(strings.TrimRight(value[2:], `\`), `\`)
	if len(parts) < 3 {
		return nil, false
	}
	server := strings.ToLower(parts[0])
	if server == "." || server == "localhost" || strings.HasPrefix(server, "127.") || strings.HasPrefix(server, "0.") ||
		!psPlainSegment(server) || strings.ContainsAny(server, " ()") {
		return nil, false
	}
	for _, part := range parts[1:] {
		if !psPlainSegment(part) {
			return nil, false
		}
	}
	return parts[2:], true
}

// psUnionBindings returns what a variable can hold after either path: every
// value it holds on one path or the other.
func psUnionBindings(a, b psBindings, m psMerger, overflow *bool) psBindings {
	out := a.clone()
	for name, values := range b {
		merged := out[name]
		for _, value := range values {
			merged = psAddValue(merged, value, m, overflow)
		}
		out[name] = merged
	}
	return out
}

// psBindStaticValues returns the readings of a PowerShell command in which a
// variable that earlier assignments bound to a string is replaced by the
// string, one reading per way control flow can have bound it. A call that
// writes $path after $path = "<state file>" writes the state file as much as
// one that spells it, so the state-write proof reads both (the literal
// spelling was proven, the bound one was only a rule match that observe mode
// downgrades).
//
// Only values that name DefenseClaw are tracked, so ordinary scripts are
// read unchanged. A value is a single- or double-quoted string whose
// expansions are bound variables or the user home ($HOME, $env:USERPROFILE),
// or a bound variable; any other right-hand side, compound assignment or
// unresolvable expansion makes the variable unknown from there on. Strings
// that PowerShell does not expand (single-quoted, here-strings) and comments
// are copied unchanged.
//
// Control flow keeps every executable alternative. A block that may run (an
// if, a loop, a script block) leaves the variable holding what it held before
// or what the block left; an if with an else leaves what its branches left;
// a branch whose condition is the constant $false never runs, so what it
// binds and what it reads are not counted. A block is read twice when its
// first pass binds something new, so a value bound late in a loop reaches an
// earlier use in the next round. A block proven on one reading counts;
// nothing else does. A value past a bound sets budget.over.
func psBindStaticValues(command string, merge psMerger, budget *psBudget) (readings []string) {
	if !strings.Contains(strings.ToLower(command), "defenseclaw") || !strings.ContainsRune(command, '$') {
		return nil
	}
	r := []rune(command)
	readingCount := 1
	for choice := 0; choice < readingCount && choice < psBoundAlternatives; choice++ {
		binder := &psBinder{r: r, scan: newPSScan(r, budget), budget: budget, merge: merge, choice: choice, readings: 1}
		binder.run(0, psBindings{}, false)
		// Past a bound a protected value may have been dropped: the command
		// counts as the write, as for every other bound of this proof.
		if binder.overflow {
			budget.over = true
		}
		if budget.over {
			return nil
		}
		readingCount = max(readingCount, binder.readings)
		text := string(binder.out)
		if !binder.changed || text == command {
			continue
		}
		if !slices.Contains(readings, text) {
			readings = append(readings, text)
		}
	}
	return readings
}

// psBinder rewrites one command for one choice of the alternative a use of a
// multiply bound variable reads.
type psBinder struct {
	r        []rune
	scan     *psStateScan
	budget   *psBudget
	merge    psMerger
	choice   int
	readings int // most values any one use could read
	changed  bool
	out      []rune
	dead     int  // depth of the never-run blocks being read: nothing binds or expands there
	overflow bool // a value, a loop pass or a combination past its bound was dropped
}

// psBindChain is an if / elseif / else chain being read.
type psBindChain struct {
	before  psBindings
	ends    []psBindings
	sealed  bool // a branch that always runs was read; later branches never do
	hasElse bool
}

// psPendingBlock is the keyword whose block a { opens, and its condition.
type psPendingBlock struct {
	kind, cond string
	after      int // index after the keyword and its condition
}

func (b *psBinder) put(text []rune) {
	b.scan.account(len(text))
	b.out = append(b.out, text...)
}

// run reads from i to the end, or in a block to the } that closes it (not
// consumed), starting from st, and returns where it stopped and what the
// variables hold there. st is changed in place.
func (b *psBinder) run(i int, st psBindings, inBlock bool) (int, psBindings) {
	r := b.r
	copyTo := func(j int) {
		j = min(j, len(r))
		if j > i {
			b.put(r[i:j])
			i = j
		}
	}
	lookup := func(name string) (string, bool) {
		values := st[strings.ToLower(name)]
		if len(values) == 0 {
			return "", false
		}
		b.readings = max(b.readings, len(values))
		return values[b.choice%len(values)], true
	}
	var chain *psBindChain
	var pending psPendingBlock
	for i < len(r) && b.budget.step() && !b.budget.over {
		c := r[i]
		switch {
		case psSingleQuote(c):
			copyTo(b.scan.singleQuoted(i))
		case c == '@' && i+1 < len(r) && (psSingleQuote(r[i+1]) || psDoubleQuote(r[i+1])) && b.scan.hereStringOpen(i+2):
			copyTo(b.scan.hereString(i))
		case psDoubleQuote(c) && b.dead > 0:
			copyTo(b.scan.doubleQuoted(i))
		case psDoubleQuote(c):
			end := b.scan.doubleQuoted(i)
			text, bound := psExpandBound(string(r[i:end]), lookup)
			if bound {
				b.changed = true
			}
			b.put([]rune(text))
			i = end
		case c == '`':
			copyTo(i + 2)
		case c == '#' && b.scan.tokenStart(i):
			j := i
			for j < len(r) && r[j] != '\n' {
				j++
			}
			copyTo(j)
		case c == '<' && i+1 < len(r) && r[i+1] == '#':
			j := i + 2
			for j+1 < len(r) && (r[j] != '#' || r[j+1] != '>') {
				j++
			}
			copyTo(j + 2)
		case c == '}' && inBlock:
			return i, st
		case c == '{':
			kind, cond := pending.take(r, i)
			pending = psPendingBlock{}
			copyTo(i + 1)
			i, st = b.block(i, kind, cond, st, &chain)
		case unicode.IsLetter(c) && b.scan.tokenStart(i):
			start, j := i, i
			for j < len(r) && unicode.IsLetter(r[j]) {
				j++
			}
			copyTo(j)
			// Part of a longer word (ForEach-Object, a path): not a keyword.
			if j < len(r) && !strings.ContainsRune(" \t\r\n({;}", r[j]) {
				break
			}
			if keyword := b.keyword(strings.ToLower(string(r[start:j])), start); keyword.kind != "" {
				pending = keyword
			}
		case c == '$' && b.dead > 0:
			// A block that never runs binds nothing and writes nothing.
			_, end, _ := psVariableName(r, i)
			copyTo(max(end, i+1))
		case c == '$':
			name, end, braced := psVariableName(r, i)
			if name == "" {
				copyTo(i + 1)
				break
			}
			key := strings.ToLower(name)
			after := end
			for after < len(r) && (r[after] == ' ' || r[after] == '\t') {
				after++
			}
			if b.scan.assignmentAt(end) {
				// $name = <value>: bind, or forget the name. The value is read
				// before the name is forgotten ($p = $p keeps $p).
				values, valueEnd, ok := b.assignedValues(after, st)
				delete(st, key)
				if !ok || r[after] != '=' {
					copyTo(end)
					break
				}
				copyTo(valueEnd)
				var kept []string
				for _, value := range values {
					if strings.Contains(strings.ToLower(value), "defenseclaw") && len([]rune(value)) <= psBoundValueMaxRunes {
						kept = psAddValue(kept, value, b.merge, &b.overflow)
					}
				}
				if len(kept) > 0 {
					st[key] = kept
				}
				break
			}
			if strings.HasPrefix(strings.ToLower(string(r[after:min(after+3, len(r))])), "in ") && !braced {
				delete(st, key) // foreach ($name in ...)
				copyTo(end)
				break
			}
			if value, ok := lookup(name); ok {
				b.put([]rune(managed.PowerShellLiteral(value)))
				i = end
				b.changed = true
				break
			}
			copyTo(end)
		default:
			copyTo(i + 1)
		}
	}
	return i, st
}

// take returns the keyword whose block the { at i opens, when only blanks
// lie between its condition and the {.
func (p psPendingBlock) take(r []rune, i int) (kind, cond string) {
	if p.kind == "" {
		return "", ""
	}
	j := i
	for j > p.after && (r[j-1] == ' ' || r[j-1] == '\t' || r[j-1] == '\r' || r[j-1] == '\n') {
		j--
	}
	if j != p.after {
		return "", ""
	}
	return p.kind, p.cond
}

// keyword records a block keyword read at [start, start+len(word)).
func (b *psBinder) keyword(word string, start int) psPendingBlock {
	r := b.r
	j := start + len([]rune(word))
	switch word {
	case "else", "try", "finally", "do":
		return psPendingBlock{kind: word, after: j}
	case "if", "elseif", "while", "for", "foreach", "switch", "catch", "until", "trap":
		k := j
		for k < len(r) && (r[k] == ' ' || r[k] == '\t' || r[k] == '\r' || r[k] == '\n') {
			k++
		}
		if k < len(r) && r[k] == '(' {
			if end := b.matchParen(k); end > 0 {
				return psPendingBlock{kind: word, cond: string(r[k+1 : end-1]), after: end}
			}
			return psPendingBlock{}
		}
		return psPendingBlock{kind: word, after: j}
	}
	return psPendingBlock{}
}

// matchParen returns the index after the ) that closes the ( at k, or -1.
func (b *psBinder) matchParen(k int) int {
	r := b.r
	depth := 0
	for j := k; j < len(r) && b.budget.step(); j++ {
		switch {
		case psSingleQuote(r[j]):
			j = b.scan.singleQuoted(j) - 1
		case psDoubleQuote(r[j]):
			j = b.scan.doubleQuoted(j) - 1
		case r[j] == '`':
			j++
		case r[j] == '(':
			depth++
		case r[j] == ')':
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return -1
}

// psConstCondition folds the constant conditions: -1 for one that is always
// false, 1 for one that is always true, 0 for any other.
func psConstCondition(cond string) int {
	switch strings.ToLower(strings.Trim(cond, " \t\r\n()")) {
	case "$false", "$null", "0", "''", `""`, "!$true", "-not $true":
		return -1
	case "$true", "1", "!$false", "-not $false":
		return 1
	}
	return 0
}

// block reads the block whose { was just copied (i is the index after it)
// and returns the index after its } and what the variables hold after it.
func (b *psBinder) block(i int, kind, cond string, st psBindings, chain **psBindChain) (int, psBindings) {
	switch kind {
	case "if", "elseif", "else":
		if kind == "if" || *chain == nil {
			*chain = &psBindChain{before: st.clone()}
		}
		ch := *chain
		constant := 0
		if kind != "else" {
			constant = psConstCondition(cond)
		}
		dead := ch.sealed || constant < 0
		var next int
		var end psBindings
		if dead {
			next = b.runDead(i)
		} else {
			next, end = b.run(i, ch.before.clone(), true)
		}
		next = b.closeBlock(next)
		if !dead {
			ch.ends = append(ch.ends, end)
			ch.hasElse = ch.hasElse || kind == "else"
			ch.sealed = constant > 0
		}
		if b.elseFollows(next) {
			return next, st
		}
		result := psBindings{}
		for _, end := range ch.ends {
			result = psUnionBindings(result, end, b.merge, &b.overflow)
		}
		if !ch.sealed && !ch.hasElse {
			result = psUnionBindings(result, ch.before, b.merge, &b.overflow)
		}
		*chain = nil
		return next, result
	}
	if kind == "while" && psConstCondition(cond) < 0 {
		return b.closeBlock(b.runDead(i)), st
	}
	// A loop or a script block runs not at all, once or again: what it binds
	// reaches its own earlier uses, and what follows it.
	mark := len(b.out)
	entry := st
	var next int
	var end psBindings
	for round := 0; ; round++ {
		next, end = b.run(i, entry.clone(), true)
		merged := psUnionBindings(entry, end, b.merge, &b.overflow)
		if merged.size() == entry.size() {
			break
		}
		if round >= psBoundLoopRounds {
			b.overflow = true // the values are still growing: not all are known
			break
		}
		b.out = b.out[:mark]
		entry = merged
	}
	return b.closeBlock(next), psUnionBindings(st, end, b.merge, &b.overflow)
}

// runDead reads the block whose { was just copied (i is the index after it)
// as text that never runs, and returns the index of its }.
func (b *psBinder) runDead(i int) int {
	b.dead++
	next, _ := b.run(i, psBindings{}, true)
	b.dead--
	return next
}

// closeBlock copies the } at i and returns the index after it.
func (b *psBinder) closeBlock(i int) int {
	if i < len(b.r) {
		b.put(b.r[i : i+1])
		return i + 1
	}
	return i
}

// elseFollows reports that else or elseif is the next word after i.
func (b *psBinder) elseFollows(i int) bool {
	r := b.r
	for i < len(r) && (r[i] == ' ' || r[i] == '\t' || r[i] == '\r' || r[i] == '\n') {
		i++
	}
	j := i
	for j < len(r) && unicode.IsLetter(r[j]) {
		j++
	}
	word := strings.ToLower(string(r[i:j]))
	return (word == "else" || word == "elseif") && (j >= len(r) || strings.ContainsRune(" \t\r\n({", r[j]))
}

// psVariableName reads $name or ${name} at i and returns the name and the
// index after it. A drive-qualified name ($env:X, ${C:\f}) has no plain name.
func psVariableName(r []rune, i int) (name string, end int, braced bool) {
	if i+1 >= len(r) {
		return "", i + 1, false
	}
	if r[i+1] == '{' {
		for j := i + 2; j < len(r) && r[j] != '\n'; j++ {
			if r[j] == '}' {
				name = string(r[i+2 : j])
				if strings.ContainsAny(name, ":`\\/") {
					return "", j + 1, true
				}
				return name, j + 1, true
			}
		}
		return "", i + 1, true
	}
	j := i + 1
	for j < len(r) && (r[j] == '_' || unicode.IsLetter(r[j]) || unicode.IsDigit(r[j])) {
		j++
	}
	if j == i+1 || j < len(r) && r[j] == ':' {
		return "", j, false
	}
	return string(r[i+1 : j]), j, false
}

// assignedValues reads the right-hand side of an assignment whose = is at
// r[eq]: one quoted string, or one bound variable, that ends the statement.
// It returns every value the right-hand side can have.
func (b *psBinder) assignedValues(eq int, st psBindings) (values []string, end int, ok bool) {
	r := b.r
	if eq >= len(r) || r[eq] != '=' {
		return nil, 0, false
	}
	start := eq + 1
	for start < len(r) && (r[start] == ' ' || r[start] == '\t') {
		start++
	}
	if start >= len(r) {
		return nil, 0, false
	}
	var literalEnd int
	switch {
	case psSingleQuote(r[start]):
		literalEnd = b.scan.singleQuoted(start)
		inner := string(r[start+1 : max(literalEnd-1, start+1)])
		values = []string{managed.PowerShellLiteralValue(inner)}
	case psDoubleQuote(r[start]):
		literalEnd = b.scan.doubleQuoted(start)
		var expanded bool
		values, expanded = psDoubleQuotedValues(string(r[start:literalEnd]), st, b.merge.home, &b.overflow)
		if !expanded {
			return nil, 0, false
		}
	case r[start] == '$':
		name, nameEnd, _ := psVariableName(r, start)
		bound := st[strings.ToLower(name)]
		if name == "" || len(bound) == 0 {
			return nil, 0, false
		}
		values, literalEnd = bound, nameEnd
	default:
		return nil, 0, false
	}
	// The value must be the whole right-hand side.
	rest := literalEnd
	for rest < len(r) && (r[rest] == ' ' || r[rest] == '\t' || r[rest] == '\r') {
		rest++
	}
	if rest < len(r) && r[rest] != ';' && r[rest] != '\n' && r[rest] != '}' {
		return nil, 0, false
	}
	return values, literalEnd, true
}

// psDoubleQuotedValues returns the strings a double-quoted PowerShell literal
// can hold: escapes decoded, $name and ${name} of bound variables and the
// user home expanded, one string per combination of the values the variables
// hold; combinations past the bound set *overflow. expanded is false for any other expansion ($(...), an unbound
// variable), whose value is not known.
func psDoubleQuotedValues(literal string, st psBindings, home string, overflow *bool) (values []string, expanded bool) {
	r := []rune(literal)
	if len(r) < 2 {
		return nil, false
	}
	parts := []string{""}
	add := func(text string) bool {
		for k := range parts {
			parts[k] += text
			if len(parts[k]) > psBoundTextMaxBytes {
				return false
			}
		}
		return true
	}
	for i := 1; i < len(r)-1; i++ {
		text := ""
		switch {
		case r[i] == '`' && i+1 < len(r)-1:
			i++
			switch r[i] {
			case 'n':
				text = "\n"
			case 'r':
				text = "\r"
			case 't':
				text = "\t"
			case '0':
				return nil, false
			default:
				text = string(r[i])
			}
		case psDoubleQuote(r[i]) && i+1 < len(r)-1 && psDoubleQuote(r[i+1]):
			text = string(r[i])
			i++
		case r[i] == '$':
			if i+1 < len(r)-1 && r[i+1] == '(' {
				return nil, false
			}
			if value, end, ok := psHomeVariable(r[:len(r)-1], i, home); ok {
				text = value
				i = end - 1
				break
			}
			name, end, _ := psVariableName(r[:len(r)-1], i)
			alternatives := st[strings.ToLower(name)]
			if name == "" || len(alternatives) == 0 {
				if name == "" && (i+1 >= len(r)-1 || r[i+1] != '_' && !unicode.IsLetter(r[i+1]) && r[i+1] != '{') {
					text = string(r[i]) // a lone $ is text
					break
				}
				return nil, false
			}
			var next []string
			for _, part := range parts {
				for _, alternative := range alternatives {
					if len(next) >= psBoundCombinations {
						*overflow = true
						continue
					}
					next = append(next, part+alternative)
				}
			}
			parts = next
			i = end - 1
			continue
		default:
			text = string(r[i])
		}
		if !add(text) {
			return nil, false
		}
	}
	return parts, true
}

// psHomeVariable resolves the spellings of the user home: $HOME, ${HOME},
// $env:USERPROFILE, ${env:USERPROFILE}, $env:HOME.
func psHomeVariable(r []rune, i int, home string) (value string, end int, ok bool) {
	if home == "" {
		return "", 0, false
	}
	rest := strings.ToLower(string(r[i:min(i+24, len(r))]))
	for _, spelling := range []string{"${env:userprofile}", "${env:home}", "${home}", "$env:userprofile", "$env:home", "$home"} {
		if strings.HasPrefix(rest, spelling) {
			end = i + len([]rune(spelling))
			if !strings.HasPrefix(spelling, "${") && end < len(r) && (r[end] == '_' || unicode.IsLetter(r[end]) || unicode.IsDigit(r[end])) {
				return "", 0, false
			}
			return home, end, true
		}
	}
	return "", 0, false
}

// psExpandBound replaces $name and ${name} of bound variables inside a
// double-quoted literal, leaving the rest of it as written. It reports
// whether anything was replaced; a literal with a $(...) is left unread.
func psExpandBound(literal string, lookup func(string) (string, bool)) (string, bool) {
	if !strings.ContainsRune(literal, '$') || strings.Contains(literal, "$(") {
		return literal, false
	}
	r := []rune(literal)
	var b strings.Builder
	replaced := false
	for i := 0; i < len(r); i++ {
		if r[i] == '`' && i+1 < len(r) {
			b.WriteRune(r[i])
			i++
			b.WriteRune(r[i])
			continue
		}
		if r[i] == '$' {
			if name, end, _ := psVariableName(r, i); name != "" {
				if value, ok := lookup(name); ok {
					escaped := strings.NewReplacer("`", "``", "\"", "`\"", "$", "`$").Replace(value)
					b.WriteString(escaped)
					i = end - 1
					replaced = true
					continue
				}
			}
		}
		b.WriteRune(r[i])
	}
	return b.String(), replaced
}

// psPatchDirectives name the files an apply_patch envelope writes, moves or
// removes.
var psPatchDirectives = []string{"*** add file:", "*** update file:", "*** delete file:", "*** move to:"}

// psPatchRunTargets lists, as PowerShell single-quoted literals, the files
// the envelope in a statement names when the statement runs apply_patch or
// Codex's own apply-patch entry (a program run with
// --codex-run-as-apply-patch). The envelope is the statement's text, with `n
// read as a line break; a statement that only mentions an envelope or the
// flag (Write-Output, echo) runs nothing and lists none. Each target is
// judged as the Set-Content write it is.
func psPatchRunTargets(statement, cwd string, budget *psBudget) []string {
	lower := strings.ToLower(statement)
	if !strings.Contains(lower, "*** ") || !strings.Contains(lower, "defenseclaw") {
		return nil
	}
	if !psRunsPatch(psWords(statement, budget), budget) || budget.over {
		return nil
	}
	const maxTargets = 64
	var targets []string
	envelope := strings.NewReplacer("`n", "\n", "\r\n", "\n", "\r", "\n").Replace(statement)
	for _, line := range strings.Split(envelope, "\n") {
		line = strings.TrimSpace(line)
		for _, directive := range psPatchDirectives {
			if len(line) < len(directive) || !strings.EqualFold(line[:len(directive)], directive) {
				continue
			}
			path := strings.Trim(strings.TrimSpace(line[len(directive):]), "'\"")
			if path == "" {
				continue
			}
			if cwd != "" && !psAbsolutePath(path) {
				path = strings.TrimRight(cwd, `\/`) + `\` + path
			}
			targets = append(targets, managed.PowerShellLiteral(path))
			if len(targets) >= maxTargets {
				return targets
			}
		}
	}
	return targets
}

// psLauncherDepth bounds the launchers one patch run is read through
// (cmd /c if ... start ... call codex.exe); a chain past it counts as the run.
const psLauncherDepth = 8

// psRunsPatch reports that the statement runs the patch tool: the program it
// starts is apply_patch, or Codex's own (a name with codex in it) given
// --codex-run-as-apply-patch, also when cmd /c or Start-Process starts it.
// The program is the one in command position: a launcher whose arguments only
// mention Codex or carry the flag as text (Start-Process whoami.exe, cmd /c
// echo) applies nothing.
func psRunsPatch(words []psWord, budget *psBudget) bool {
	k := 0
	if len(words) > 1 && (words[0].text == "&" || words[0].text == ".") {
		k = 1
	}
	if k >= len(words) {
		return false
	}
	var line []string
	switch psExecutableName(psUnquote(words[k].text, budget)) {
	case "start-process", "saps", "start":
		file, arguments, positional := psStartProcessParts(psJoinListWords(words[k:], budget), budget)
		if file == "" {
			return false
		}
		line = []string{psUnquote(file, budget)}
		for _, list := range append([]string{arguments}, positional...) {
			for _, part := range psSplitArguments(psArrayBody(list), budget) {
				line = append(line, psUnquote(part, budget))
			}
		}
	default:
		for _, word := range words[k:] {
			line = append(line, psUnquote(word.text, budget))
		}
	}
	return psLineRunsPatch(line, 0)
}

// psLineRunsPatch reports a command line (program first) that runs the patch
// tool, through the launchers cmd /c, start, call, if, else and do: a launcher
// runs the command it names, so the program in command position decides.
func psLineRunsPatch(line []string, depth int) bool {
	if len(line) == 0 {
		return false
	}
	if depth > psLauncherDepth {
		return true
	}
	program := psExecutableName(strings.TrimLeft(psCmdUnquote(line[0]), "@"))
	switch {
	case program == "apply_patch" || program == "applypatch":
		return true
	case strings.Contains(program, "codex"):
		return psHasPatchFlag(line[1:])
	case program == "cmd":
		return psCmdRunsPatch(line[1:], depth)
	case program == "call" || program == "else" || program == "do":
		return psLineRunsPatch(line[1:], depth+1)
	case program == "if":
		return psCmdSegmentsRunPatch([][]string{line}, depth+1)
	case program == "start":
		return psLineRunsPatch(psCmdStartCommand(line[1:]), depth+1)
	}
	return false
}

// psCmdUnquote drops the double quotes cmd would drop from a word.
func psCmdUnquote(word string) string {
	return strings.ReplaceAll(word, `"`, "")
}

// psCmdStartCommand returns the command line cmd's start runs: start
// ["title"] [/d dir] [/node n] [/affinity mask] [other /options] program
// arguments. The first quoted word is the window title, wherever it stands
// among the options, so it is never the program; /d, /node, /affinity and
// /machine take the word after them.
func psCmdStartCommand(args []string) []string {
	titled := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, `"`) && !titled:
			titled = true
		case strings.HasPrefix(arg, "/"):
			switch strings.ToLower(arg) {
			case "/d", "/node", "/affinity", "/machine":
				i++
			}
		default:
			return args[i:]
		}
	}
	return nil
}

// psCmdTruth is what the condition of a cmd if says when it is a literal.
type psCmdTruth int

const (
	psCmdUnknown psCmdTruth = iota // cmd decides at run time: both branches may run
	psCmdTrue                      // only the command runs
	psCmdFalse                     // only the else runs
)

// psCmdIfParts reads the arguments of cmd's if: [/i] [not] errorlevel n |
// exist f | defined v | cmdextversion n | a==b | a OP b, then the command
// (empty when it follows in a parenthesised group). A = run is one "=" word
// (psCmdSegments). The truth is known only when both sides of a comparison
// are literals (no %variable% or !variable!).
func psCmdIfParts(args []string) (psCmdTruth, []string) {
	i, fold, negate := 0, false, false
	for i < len(args) {
		if strings.EqualFold(args[i], "/i") {
			fold = true
		} else if strings.EqualFold(args[i], "not") {
			negate = !negate
		} else {
			break
		}
		i++
	}
	if i >= len(args) {
		return psCmdUnknown, nil
	}
	truth := psCmdUnknown
	switch strings.ToLower(args[i]) {
	case "errorlevel", "exist", "defined", "cmdextversion":
		i += 2
	default:
		switch {
		case i+2 < len(args) && args[i+1] == "=":
			truth = psCmdCompare("equ", args[i], args[i+2], fold)
			i += 3
		case i+2 < len(args) && psCmdCompareOperator(args[i+1]):
			truth = psCmdCompare(strings.ToLower(args[i+1]), args[i], args[i+2], fold)
			i += 3
		default:
			return psCmdUnknown, nil
		}
	}
	if negate && truth != psCmdUnknown {
		truth = psCmdTrue + psCmdFalse - truth
	}
	return truth, args[min(i, len(args)):]
}

// psCmdCompare evaluates a comparison of two literals: operands made of
// digits compare as decimal numbers (09 is 9, 010 is 10), anything else as
// text (without case with /i). An operand written as a hexadecimal number
// next to another number is not decided.
func psCmdCompare(operator, left, right string, fold bool) psCmdTruth {
	if strings.ContainsAny(left+right, "%!") {
		return psCmdUnknown
	}
	if fold {
		left, right = strings.ToLower(left), strings.ToLower(right)
	}
	order := strings.Compare(left, right)
	a, hexA, okA := psParseCmdNumber(left)
	b, hexB, okB := psParseCmdNumber(right)
	switch {
	case okA && okB && (hexA || hexB):
		return psCmdUnknown
	case okA && okB:
		order = a.compare(b)
	}
	holds := false
	switch operator {
	case "equ":
		holds = order == 0
	case "neq":
		holds = order != 0
	case "lss":
		holds = order < 0
	case "leq":
		holds = order <= 0
	case "gtr":
		holds = order > 0
	case "geq":
		holds = order >= 0
	default:
		return psCmdUnknown
	}
	if holds {
		return psCmdTrue
	}
	return psCmdFalse
}

// psCmdNumber is a number of any size written with decimal digits.
type psCmdNumber struct {
	negative bool
	digits   string // without leading zeros; "0" for zero
}

// psParseCmdNumber reads an optionally signed number of digits. hex reports
// the 0x form, whose value is not read.
func psParseCmdNumber(text string) (number psCmdNumber, hex, ok bool) {
	body := text
	if strings.HasPrefix(body, "-") || strings.HasPrefix(body, "+") {
		number.negative = body[0] == '-'
		body = body[1:]
	}
	if body == "" {
		return psCmdNumber{}, false, false
	}
	if len(body) > 2 && body[0] == '0' && (body[1] == 'x' || body[1] == 'X') {
		for _, c := range body[2:] {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return psCmdNumber{}, false, false
			}
		}
		return psCmdNumber{}, true, true
	}
	for _, c := range body {
		if c < '0' || c > '9' {
			return psCmdNumber{}, false, false
		}
	}
	number.digits = strings.TrimLeft(body, "0")
	if number.digits == "" {
		number.digits, number.negative = "0", false
	}
	return number, false, true
}

// compare orders two numbers: negative, zero or positive as n is less than,
// equal to or greater than other.
func (n psCmdNumber) compare(other psCmdNumber) int {
	if n.negative != other.negative {
		if n.negative {
			return -1
		}
		return 1
	}
	order := cmp.Compare(len(n.digits), len(other.digits))
	if order == 0 {
		order = strings.Compare(n.digits, other.digits)
	}
	if n.negative {
		return -order
	}
	return order
}

// psCmdCompareOperator reports an operator word of cmd's if comparison.
func psCmdCompareOperator(word string) bool {
	switch strings.ToLower(word) {
	case "equ", "neq", "lss", "leq", "gtr", "geq":
		return true
	}
	return false
}

// psCmdRunsPatch reports that the command string cmd runs (what follows /c,
// /k or /r, however PowerShell quoted it into words) runs the patch tool.
// cmd reads that string as a command line of its own: the program is its
// first word, so "codex.exe --codex-run-as-apply-patch" in one PowerShell
// word starts Codex and cmd /c echo starts nothing.
func psCmdRunsPatch(args []string, depth int) bool {
	for i, arg := range args {
		lower := strings.ToLower(arg)
		if len(lower) < 2 || lower[0] != '/' || !strings.ContainsRune("ckr", rune(lower[1])) {
			continue
		}
		command := psCmdCommandLine(append([]string{arg[2:]}, args[i+1:]...))
		return psCmdSegmentsRunPatch(psCmdSegments(command), depth+1)
	}
	return false
}

// psCmdOpen and psCmdClose are the segments a parenthesis becomes (a NUL
// cannot be in a command line, so no word is mistaken for one).
const (
	psCmdOpen  = "\x00("
	psCmdClose = "\x00)"
)

// psCmdGroupEnd returns the index of the parenthesis that closes the group
// the segments from index from are in, or len(segments).
func psCmdGroupEnd(segments [][]string, from int) int {
	level := 0
	for j := from; j < len(segments); j++ {
		if len(segments[j]) != 1 {
			continue
		}
		switch segments[j][0] {
		case psCmdOpen:
			level++
		case psCmdClose:
			if level == 0 {
				return j
			}
			level--
		}
	}
	return len(segments)
}

// psCmdSegmentsRunPatch reports that the commands cmd runs from these
// segments (psCmdSegments) run the patch tool. An if is conditional: with a
// literal condition that is false only its else can run, with one that is
// true only its command can, and with one cmd decides at run time both can.
// Without parentheses the command of an if is the rest of the line.
func psCmdSegmentsRunPatch(segments [][]string, depth int) bool {
	for i := 0; i < len(segments); i++ {
		segment := segments[i]
		if len(segment) == 1 && (segment[0] == psCmdOpen || segment[0] == psCmdClose) {
			continue
		}
		if psExecutableName(strings.TrimLeft(psCmdUnquote(segment[0]), "@")) != "if" {
			if psLineRunsPatch(segment, depth) {
				return true
			}
			continue
		}
		truth, command := psCmdIfParts(segment[1:])
		var then, otherwise [][]string
		next := i + 1
		if len(command) > 0 {
			next = psCmdGroupEnd(segments, i+1)
			then = append([][]string{command}, segments[i+1:next]...)
		} else if next < len(segments) && len(segments[next]) == 1 && segments[next][0] == psCmdOpen {
			end := psCmdGroupEnd(segments, next+1)
			then = segments[next+1 : end]
			next = min(end+1, len(segments))
			if next < len(segments) && strings.EqualFold(segments[next][0], "else") {
				rest := segments[next][1:]
				switch {
				case len(rest) > 0:
					end = psCmdGroupEnd(segments, next+1)
					otherwise = append([][]string{rest}, segments[next+1:end]...)
					next = end
				case next+1 < len(segments) && len(segments[next+1]) == 1 && segments[next+1][0] == psCmdOpen:
					end = psCmdGroupEnd(segments, next+2)
					otherwise = segments[next+2 : end]
					next = min(end+1, len(segments))
				default:
					next++
				}
			}
		}
		if truth != psCmdFalse && psCmdSegmentsRunPatch(then, depth) {
			return true
		}
		if truth != psCmdTrue && psCmdSegmentsRunPatch(otherwise, depth) {
			return true
		}
		i = next - 1
	}
	return false
}

// psCmdCommandLine joins the words PowerShell passed after /c into the line
// cmd receives: the first is the command string and stays as it is; a later
// word with a blank in it is quoted, as PowerShell quotes it.
func psCmdCommandLine(pieces []string) string {
	var line []string
	for _, piece := range pieces {
		if piece == "" {
			continue
		}
		if len(line) > 0 && strings.ContainsAny(piece, " \t") && !strings.HasPrefix(piece, `"`) {
			piece = `"` + piece + `"`
		}
		line = append(line, piece)
	}
	return strings.Join(line, " ")
}

// psCmdSegments splits a cmd command line into its commands (at & and |; a
// parenthesis is a segment of its own) and their words (at blanks, commas and semicolons; a run of =
// is a word of its own), outside double quotes; a word keeps its double
// quotes, which tell a window title from a program, and a caret takes the
// next character as text.
func psCmdSegments(line string) [][]string {
	var segments [][]string
	var segment []string
	var word strings.Builder
	started, quoted, escaped := false, false, false
	flush := func() {
		if started {
			segment = append(segment, word.String())
			word.Reset()
			started = false
		}
	}
	endCommand := func() {
		flush()
		if len(segment) > 0 {
			segments = append(segments, segment)
			segment = nil
		}
	}
	for _, c := range line {
		switch {
		case escaped:
			word.WriteRune(c)
			started, escaped = true, false
		case c == '"':
			quoted = !quoted
			word.WriteRune(c)
			started = true
		case quoted:
			word.WriteRune(c)
		case c == '^':
			escaped = true
		case c == '(':
			endCommand()
			segments = append(segments, []string{psCmdOpen})
		case c == ')':
			endCommand()
			segments = append(segments, []string{psCmdClose})
		case c == '&' || c == '|':
			endCommand()
		case c == '=':
			flush()
			if len(segment) == 0 || segment[len(segment)-1] != "=" {
				segment = append(segment, "=")
			}
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';':
			flush()
		default:
			word.WriteRune(c)
			started = true
		}
	}
	endCommand()
	return segments
}

// psHasPatchFlag reports an argument that is, or lists, the option
// --codex-run-as-apply-patch. The option is case sensitive and exact: a
// longer option that starts with it, or another spelling of its letters, is
// another option that Codex rejects before any patch run.
func psHasPatchFlag(args []string) bool {
	for _, arg := range args {
		for _, option := range strings.FieldsFunc(arg, func(c rune) bool { return strings.ContainsRune(" \t,;\"'", c) }) {
			if option == "--codex-run-as-apply-patch" {
				return true
			}
		}
	}
	return false
}

// psExecutableName is the program name with the script suffixes dropped too.
func psExecutableName(word string) string {
	name := psProgramName(word)
	for _, suffix := range []string{".bat", ".cmd", ".com"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return name
}

// psAbsolutePath reports a drive, UNC or rooted path.
func psAbsolutePath(path string) bool {
	return len(path) >= 2 && path[1] == ':' || strings.HasPrefix(path, `\`) || strings.HasPrefix(path, "/")
}
