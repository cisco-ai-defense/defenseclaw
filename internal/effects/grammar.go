// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// Closed grammars for the operands the program table cannot account for by
// position alone (round 9, GAP-0185). A script, a format string and a config
// file are code or data with their own syntax: the table may mark such a token
// accounted only if the grammar here parses it completely and finds nothing that
// writes, runs or reads another file. Everything else stays unaccounted, so the
// call is never fully known. Each recognizer fails closed: any construct it does
// not recognize is rejected.

// TextKind names the grammar a flag value or a first positional is checked by.
type TextKind string

const (
	TextNone         TextKind = ""
	TextSed          TextKind = "sed"
	TextAwk          TextKind = "awk"
	TextRegex        TextKind = "regex" // a grep pattern: matched, never executed
	TextCurlFormat   TextKind = "curl_format"
	TextScriptFile   TextKind = "script_file" // -f FILE: the content is a script we do not read
	TextConfigFile   TextKind = "config_file" // curl -K FILE
	maxGrammarSource          = 8 << 10
)

// textBad reports a value the grammar for kind does not accept.
func textBad(kind TextKind, v Word) bool {
	if kind == TextNone {
		return false
	}
	if !v.Static || len(v.Value) > maxGrammarSource {
		return true
	}
	switch kind {
	case TextSed:
		return !sedScriptOK(v.Value)
	case TextAwk:
		return !awkProgramOK(v.Value)
	case TextCurlFormat:
		return !curlFormatOK(v.Value)
	case TextRegex:
		return false
	}
	return true // script and config files, and any kind not listed
}

// curlFormatOK accepts a -w / --write-out format that cannot write a file or
// load its format from one: %output{...} writes to a file, a leading @ reads the
// format from a file.
func curlFormatOK(s string) bool {
	if strings.HasPrefix(s, "@") {
		return false
	}
	return !strings.Contains(s, "%output") && !strings.Contains(s, "%{output")
}

// awkProgramOK accepts an awk program with no output redirection, no pipe, no
// system() / getline, no gawk directive and no comment. String literals are
// skipped; a program that mixes quotes with a / (a regex literal may hide a
// quote) is rejected rather than guessed at.
func awkProgramOK(s string) bool {
	if strings.ContainsAny(s, "#@") {
		return false
	}
	if strings.Contains(s, `"`) && strings.Contains(s, "/") {
		return false
	}
	var code strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '"' {
			code.WriteByte(c)
			continue
		}
		i++
		closed := false
		for ; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				continue
			}
			if s[i] == '\n' {
				return false // a string never spans a line
			}
			if s[i] == '"' {
				closed = true
				break
			}
		}
		if !closed {
			return false
		}
		code.WriteByte(' ')
	}
	text := code.String()
	if strings.ContainsAny(text, ">|") {
		return false
	}
	low := strings.ToLower(text)
	for _, banned := range []string{"system", "getline", "close", "fflush", "include", "load", "srand", "typeof"} {
		if strings.Contains(low, banned) {
			return false
		}
	}
	return true
}

// sedScriptOK accepts a sed script made only of commands that read and edit the
// pattern space: no w / W (write a file), r / R (read one), e (execute) and no
// s///w, s///e flag. The delimiter rule is GNU's (the next unescaped delimiter
// ends a part, brackets are not special); a bracket that BSD sed would carry
// across the delimiter is rejected so both implementations agree.
func sedScriptOK(s string) bool {
	if len(s) > maxGrammarSource {
		return false
	}
	p := &sedParser{s: s}
	depth := 0
	for {
		p.skip(" \t;\n")
		if p.eof() {
			return depth == 0
		}
		switch p.s[p.i] {
		case '#':
			for !p.eof() && p.s[p.i] != '\n' {
				p.i++
			}
			continue
		case '}':
			if depth == 0 {
				return false
			}
			depth--
			p.i++
			if !p.endOfCommand() {
				return false
			}
			continue
		}
		if !p.address() {
			return false
		}
		p.skip(" \t")
		for !p.eof() && p.s[p.i] == '!' {
			p.i++
			p.skip(" \t")
		}
		if p.eof() {
			return false
		}
		c := p.s[p.i]
		p.i++
		switch c {
		case '{':
			depth++
		case 'p', 'd', 'D', 'n', 'N', 'g', 'G', 'h', 'H', 'x', '=', 'P', 'z', 'F':
			if !p.endOfCommand() {
				return false
			}
		case 'l', 'q', 'Q', 'L':
			p.skip(" \t")
			p.digits()
			if !p.endOfCommand() {
				return false
			}
		case 's':
			if !p.subst() {
				return false
			}
		case 'y':
			if !p.translit() {
				return false
			}
		case 'b', 't', 'T':
			p.skip(" \t")
			p.upTo(";\n}")
		case ':':
			p.skip(" \t")
			if p.upTo(";\n") == "" {
				return false
			}
		case 'a', 'i', 'c':
			// one-liner text runs to the end of the line; a backslash continues it.
			for !p.eof() && p.s[p.i] != '\n' {
				if p.s[p.i] == '\\' && p.i+1 < len(p.s) {
					p.i++
				}
				p.i++
			}
		default:
			return false // w W r R e v and anything unknown
		}
	}
}

type sedParser struct {
	s       string
	i       int
	hadAddr bool
}

func (p *sedParser) eof() bool { return p.i >= len(p.s) }

func (p *sedParser) skip(set string) {
	for !p.eof() && strings.IndexByte(set, p.s[p.i]) >= 0 {
		p.i++
	}
}

func (p *sedParser) digits() int {
	n := 0
	for !p.eof() && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
		n++
	}
	return n
}

func (p *sedParser) upTo(set string) string {
	start := p.i
	for !p.eof() && strings.IndexByte(set, p.s[p.i]) < 0 {
		p.i++
	}
	return strings.TrimSpace(p.s[start:p.i])
}

// endOfCommand consumes the spaces after a command and requires a separator, a
// closing brace or the end of the script.
func (p *sedParser) endOfCommand() bool {
	p.skip(" \t")
	if p.eof() {
		return true
	}
	switch p.s[p.i] {
	case ';', '\n', '}', '#':
		return true
	}
	return false
}

// address parses an optional address or address range.
func (p *sedParser) address() bool {
	if !p.addr1() {
		return false
	}
	first := p.hadAddr
	p.skip(" \t")
	if !p.eof() && p.s[p.i] == ',' {
		if !first {
			return false
		}
		p.i++
		p.skip(" \t")
		if !p.eof() && (p.s[p.i] == '+' || p.s[p.i] == '~') {
			p.i++
			return p.digits() > 0
		}
		return p.addr1() && p.hadAddr
	}
	return true
}

// addr1 parses one address; hadAddr records whether it consumed one.
func (p *sedParser) addr1() bool {
	p.hadAddr = false
	if p.eof() {
		return true
	}
	c := p.s[p.i]
	switch {
	case c >= '0' && c <= '9':
		p.digits()
		if !p.eof() && p.s[p.i] == '~' {
			p.i++
			p.digits()
		}
		p.hadAddr = true
	case c == '$':
		p.i++
		p.hadAddr = true
	case c == '/' || c == '\\':
		delim := c
		p.i++
		if c == '\\' {
			if p.eof() {
				return false
			}
			delim = p.s[p.i]
			p.i++
		}
		if _, ok := p.part(delim, true); !ok {
			return false
		}
		for !p.eof() && (p.s[p.i] == 'I' || p.s[p.i] == 'M') {
			p.i++
		}
		p.hadAddr = true
	}
	return true
}

// part reads up to the next unescaped delimiter, GNU style, and returns the
// text. A part with an unbalanced [ is rejected (BSD sed lets a bracket
// expression carry the delimiter).
func (p *sedParser) part(delim byte, regex bool) (string, bool) {
	start := p.i
	for !p.eof() {
		c := p.s[p.i]
		if c == '\n' && regex {
			return "", false
		}
		if c == '\\' {
			p.i += 2
			continue
		}
		if c == delim {
			text := p.s[start:p.i]
			p.i++
			if strings.Count(text, "[") != strings.Count(text, "]") {
				return "", false
			}
			return text, true
		}
		p.i++
	}
	return "", false
}

func (p *sedParser) subst() bool {
	if p.eof() {
		return false
	}
	delim := p.s[p.i]
	if delim == '\n' || delim == '\\' || delim == ' ' {
		return false
	}
	p.i++
	if _, ok := p.part(delim, true); !ok {
		return false
	}
	if _, ok := p.part(delim, false); !ok {
		return false
	}
	for !p.eof() {
		c := p.s[p.i]
		switch {
		case c == 'g' || c == 'p' || c == 'i' || c == 'I' || c == 'm' || c == 'M' || (c >= '0' && c <= '9'):
			p.i++
		case c == 'e' || c == 'w':
			return false
		default:
			return p.endOfCommand()
		}
	}
	return true
}

func (p *sedParser) translit() bool {
	if p.eof() {
		return false
	}
	delim := p.s[p.i]
	if delim == '\n' || delim == '\\' || delim == ' ' {
		return false
	}
	p.i++
	if _, ok := p.part(delim, false); !ok {
		return false
	}
	if _, ok := p.part(delim, false); !ok {
		return false
	}
	return p.endOfCommand()
}
