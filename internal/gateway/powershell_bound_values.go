// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"unicode"
)

// psBoundValueMaxRunes bounds one value a variable is bound to; a longer
// value is not tracked.
const psBoundValueMaxRunes = 8 << 10

// psBindStaticValues returns the reading of a PowerShell command in which a
// variable that an earlier assignment bound to one string value is replaced
// by that value, and whether anything was replaced. A call that writes
// $path after $path = "<state file>" writes the state file as much as one
// that spells it, so the state-write proof reads both (the literal spelling
// was proven, the bound one was only a rule match that observe mode
// downgrades).
//
// Only values that name DefenseClaw are tracked, so ordinary scripts are
// read unchanged. A value is a single- or double-quoted string whose
// expansions are bound variables or the user home ($HOME, $env:USERPROFILE);
// any other right-hand side, compound assignment, loop variable or
// unresolvable expansion makes the variable unknown from there on. Strings
// that PowerShell does not expand (single-quoted, here-strings) and comments
// are copied unchanged. The reading is one way the call can run: a block
// proven on it counts, nothing else does.
func psBindStaticValues(command, home string, budget *psBudget) (string, bool) {
	if !strings.Contains(strings.ToLower(command), "defenseclaw") || !strings.ContainsRune(command, '$') {
		return command, false
	}
	r := []rune(command)
	scan := newPSScan(r, budget)
	bindings := map[string]string{}
	var out []rune
	changed := false
	i := 0
	copyTo := func(j int) {
		if j > len(r) {
			j = len(r)
		}
		if j > i {
			scan.account(j - i)
			out = append(out, r[i:j]...)
			i = j
		}
	}
	for i < len(r) && budget.step() && !budget.over {
		c := r[i]
		switch {
		case psSingleQuote(c):
			copyTo(scan.singleQuoted(i))
		case c == '@' && i+1 < len(r) && (psSingleQuote(r[i+1]) || psDoubleQuote(r[i+1])) && scan.hereStringOpen(i+2):
			copyTo(scan.hereString(i))
		case psDoubleQuote(c):
			end := scan.doubleQuoted(i)
			text, bound := psExpandBound(string(r[i:end]), bindings, home)
			if bound {
				changed = true
			}
			scan.account(len([]rune(text)))
			out = append(out, []rune(text)...)
			i = end
		case c == '`':
			copyTo(i + 2)
		case c == '#' && scan.tokenStart(i):
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
			if scan.assignmentAt(end) {
				// $name = <value>: bind, or forget the name.
				delete(bindings, key)
				if value, valueEnd, ok := psAssignedValue(scan, r, after, bindings, home); ok && r[after] == '=' {
					copyTo(valueEnd)
					if strings.Contains(strings.ToLower(value), "defenseclaw") && len([]rune(value)) <= psBoundValueMaxRunes {
						bindings[key] = value
					}
					break
				}
				copyTo(end)
				break
			}
			if strings.HasPrefix(strings.ToLower(string(r[after:min(after+3, len(r))])), "in ") && !braced {
				delete(bindings, key) // foreach ($name in ...)
				copyTo(end)
				break
			}
			if value, ok := bindings[key]; ok {
				text := "'" + strings.ReplaceAll(value, "'", "''") + "'"
				scan.account(len([]rune(text)))
				out = append(out, []rune(text)...)
				i = end
				changed = true
				break
			}
			copyTo(end)
		default:
			copyTo(i + 1)
		}
	}
	if budget.over || !changed {
		return command, false
	}
	return string(out), true
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

// psAssignedValue reads the right-hand side of an assignment whose = is at
// r[eq]: one quoted string, or one bound variable, that ends the statement.
func psAssignedValue(scan *psStateScan, r []rune, eq int, bindings map[string]string, home string) (value string, end int, ok bool) {
	if eq >= len(r) || r[eq] != '=' {
		return "", 0, false
	}
	start := eq + 1
	for start < len(r) && (r[start] == ' ' || r[start] == '\t') {
		start++
	}
	if start >= len(r) {
		return "", 0, false
	}
	var literalEnd int
	switch {
	case psSingleQuote(r[start]):
		literalEnd = scan.singleQuoted(start)
		inner := string(r[start+1 : max(literalEnd-1, start+1)])
		value = strings.NewReplacer("''", "'", "\u2018\u2018", "'", "\u2019\u2019", "'").Replace(inner)
	case psDoubleQuote(r[start]):
		literalEnd = scan.doubleQuoted(start)
		var expanded bool
		value, expanded = psDoubleQuotedValue(string(r[start:literalEnd]), bindings, home)
		if !expanded {
			return "", 0, false
		}
	case r[start] == '$':
		name, nameEnd, _ := psVariableName(r, start)
		bound, known := bindings[strings.ToLower(name)]
		if name == "" || !known {
			return "", 0, false
		}
		value, literalEnd = bound, nameEnd
	default:
		return "", 0, false
	}
	// The value must be the whole right-hand side.
	rest := literalEnd
	for rest < len(r) && (r[rest] == ' ' || r[rest] == '\t' || r[rest] == '\r') {
		rest++
	}
	if rest < len(r) && r[rest] != ';' && r[rest] != '\n' && r[rest] != '}' {
		return "", 0, false
	}
	return value, literalEnd, true
}

// psDoubleQuotedValue returns the string a double-quoted PowerShell literal
// holds: escapes decoded, $name and ${name} of bound variables and the user
// home expanded. expanded is false for any other expansion ($(...), an
// unbound variable), whose value is not known.
func psDoubleQuotedValue(literal string, bindings map[string]string, home string) (string, bool) {
	r := []rune(literal)
	if len(r) < 2 {
		return "", false
	}
	var b strings.Builder
	for i := 1; i < len(r)-1; i++ {
		switch {
		case r[i] == '`' && i+1 < len(r)-1:
			i++
			switch r[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '0':
				return "", false
			default:
				b.WriteRune(r[i])
			}
		case psDoubleQuote(r[i]) && i+1 < len(r)-1 && psDoubleQuote(r[i+1]):
			b.WriteRune(r[i])
			i++
		case r[i] == '$':
			if i+1 < len(r)-1 && r[i+1] == '(' {
				return "", false
			}
			if value, end, ok := psHomeVariable(r[:len(r)-1], i, home); ok {
				b.WriteString(value)
				i = end - 1
				continue
			}
			name, end, _ := psVariableName(r[:len(r)-1], i)
			value, ok := bindings[strings.ToLower(name)]
			if name == "" || !ok {
				if name == "" && (i+1 >= len(r)-1 || r[i+1] != '_' && !unicode.IsLetter(r[i+1]) && r[i+1] != '{') {
					b.WriteRune(r[i]) // a lone $ is text
					continue
				}
				return "", false
			}
			b.WriteString(value)
			i = end - 1
		default:
			b.WriteRune(r[i])
		}
	}
	return b.String(), true
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
func psExpandBound(literal string, bindings map[string]string, home string) (string, bool) {
	if len(bindings) == 0 || !strings.ContainsRune(literal, '$') || strings.Contains(literal, "$(") {
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
				if value, ok := bindings[strings.ToLower(name)]; ok {
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
// Codex's own apply-patch entry (codex --codex-run-as-apply-patch). The
// envelope is the statement's text, with `n read as a line break; a statement
// that only mentions an envelope runs nothing and lists none. Each target is
// judged as the Set-Content write it is.
func psPatchRunTargets(statement, cwd string, budget *psBudget) []string {
	lower := strings.ToLower(statement)
	if !strings.Contains(lower, "*** ") || !strings.Contains(lower, "defenseclaw") {
		return nil
	}
	words := psWords(statement, budget)
	runs := false
	for k, word := range words {
		text := psUnquote(word.text, budget)
		if text == "--codex-run-as-apply-patch" {
			runs = true
			break
		}
		if k > 1 || k == 1 && words[0].text != "&" && words[0].text != "." {
			continue
		}
		switch strings.TrimSuffix(strings.TrimSuffix(psProgramName(text), ".bat"), ".cmd") {
		case "apply_patch", "applypatch":
			runs = true
		}
	}
	if !runs || budget.over {
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

// psAbsolutePath reports a drive, UNC or rooted path.
func psAbsolutePath(path string) bool {
	return len(path) >= 2 && path[1] == ':' || strings.HasPrefix(path, `\`) || strings.HasPrefix(path, "/")
}
