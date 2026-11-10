// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"unicode"
)

const (
	// psBoundValueMaxRunes bounds one value a variable is bound to; a longer
	// value is not tracked.
	psBoundValueMaxRunes = 8 << 10
	// psBoundAlternatives bounds the values one variable holds at once (the
	// ways control flow can have bound it) and so the readings of a command.
	psBoundAlternatives = 8
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

// psAddValue returns values with value added when it is new. A new value
// that does not fit sets *overflow: a value dropped without a trace could be
// the protected one, so the caller counts the command as past its bound.
func psAddValue(values []string, value string, overflow *bool) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	if len(values) >= psBoundAlternatives {
		*overflow = true
		return values
	}
	return append(values[:len(values):len(values)], value)
}

// psUnionBindings returns what a variable can hold after either path: every
// value it holds on one path or the other.
func psUnionBindings(a, b psBindings, overflow *bool) psBindings {
	out := a.clone()
	for name, values := range b {
		merged := out[name]
		for _, value := range values {
			merged = psAddValue(merged, value, overflow)
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
// nothing else does.
func psBindStaticValues(command, home string, budget *psBudget) []string {
	if !strings.Contains(strings.ToLower(command), "defenseclaw") || !strings.ContainsRune(command, '$') {
		return nil
	}
	r := []rune(command)
	var readings []string
	readingCount := 1
	for choice := 0; choice < readingCount && choice < psBoundAlternatives; choice++ {
		binder := &psBinder{r: r, scan: newPSScan(r, budget), budget: budget, home: home, choice: choice, readings: 1}
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
		duplicate := false
		for _, reading := range readings {
			duplicate = duplicate || reading == text
		}
		if !duplicate {
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
	home     string
	choice   int
	readings int // most values any one use could read
	changed  bool
	out      []rune
	dead     int  // depth of the never-run blocks being read: nothing binds or expands there
	overflow bool // a value or a loop pass past its bound was dropped
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
						kept = psAddValue(kept, value, &b.overflow)
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
				b.put([]rune("'" + strings.ReplaceAll(value, "'", "''") + "'"))
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
			result = psUnionBindings(result, end, &b.overflow)
		}
		if !ch.sealed && !ch.hasElse {
			result = psUnionBindings(result, ch.before, &b.overflow)
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
		merged := psUnionBindings(entry, end, &b.overflow)
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
	return b.closeBlock(next), psUnionBindings(st, end, &b.overflow)
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
		values = []string{strings.NewReplacer("''", "'", "\u2018\u2018", "'", "\u2019\u2019", "'").Replace(inner)}
	case psDoubleQuote(r[start]):
		literalEnd = b.scan.doubleQuoted(start)
		var expanded bool
		values, expanded = psDoubleQuotedValues(string(r[start:literalEnd]), st, b.home, &b.overflow)
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
					if len(next) >= 2*psBoundAlternatives {
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
			targets = append(targets, "'"+strings.ReplaceAll(path, "'", "''")+"'")
			if len(targets) >= maxTargets {
				return targets
			}
		}
	}
	return targets
}

// psRunsPatch reports that the statement runs the patch tool: its command is
// apply_patch, or Codex's own program (a name with codex in it) given
// --codex-run-as-apply-patch, also behind cmd /c or Start-Process. A program
// that only carries the flag as text (whoami.exe, cmd /c echo) applies
// nothing.
func psRunsPatch(words []psWord, budget *psBudget) bool {
	k := 0
	if len(words) > 1 && (words[0].text == "&" || words[0].text == ".") {
		k = 1
	}
	if k >= len(words) {
		return false
	}
	program := psExecutableName(psUnquote(words[k].text, budget))
	switch {
	case program == "apply_patch" || program == "applypatch":
		return true
	case strings.Contains(program, "codex"):
		return psHasPatchFlag(words[k+1:], budget)
	case program == "start-process" || program == "start" || program == "saps" || program == "cmd":
		return psLaunchesCodex(words[k+1:], budget)
	}
	return false
}

// psLaunchesCodex reports arguments that start Codex's own program and give
// it the patch flag, as cmd /c codex.exe or Start-Process codex.exe do. A
// launcher with no Codex program among its arguments, such as cmd /c echo,
// starts no patch.
func psLaunchesCodex(args []psWord, budget *psBudget) bool {
	for _, word := range args {
		text := psUnquote(word.text, budget)
		if !strings.Contains(text, "--codex-run-as-apply-patch") && strings.Contains(psExecutableName(text), "codex") {
			return psHasPatchFlag(args, budget)
		}
	}
	return false
}

// psHasPatchFlag reports a word that is, or lists, --codex-run-as-apply-patch.
func psHasPatchFlag(words []psWord, budget *psBudget) bool {
	for _, word := range words {
		if strings.Contains(psUnquote(word.text, budget), "--codex-run-as-apply-patch") {
			return true
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
