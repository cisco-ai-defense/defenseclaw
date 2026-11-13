// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

// sedScriptReplaceOnly reports a sed script that is read in full and holds
// only commands that change the pattern space or the output: substitute
// (without the w and e flags), transliterate, delete, print, hold-space
// moves, append/insert/change text, branches, line numbers, and quit. A
// script the reader cannot settle (an unknown command, an unterminated
// part, an unbalanced brace) or any command that writes or runs something
// (w, W, e, r, R, v, a label definition) is not replace-only: the replace
// verb proof does not hold for it (rel-1-0-10 GAP-0377). The reader follows
// GNU sed's own grammar and is deliberately small: anything it does not
// name is refused.
func sedScriptReplaceOnly(script string) bool {
	p := sedScan{s: script}
	return p.script()
}

type sedScan struct {
	s string
	i int
}

func (p *sedScan) more() bool { return p.i < len(p.s) }

func (p *sedScan) peek() byte { return p.s[p.i] }

func (p *sedScan) skipBlank() {
	for p.more() && (p.peek() == ' ' || p.peek() == '\t') {
		p.i++
	}
}

func (p *sedScan) skipSeparators() {
	for p.more() && (p.peek() == ' ' || p.peek() == '\t' || p.peek() == '\n' || p.peek() == ';') {
		p.i++
	}
}

func (p *sedScan) digits() bool {
	start := p.i
	for p.more() && p.peek() >= '0' && p.peek() <= '9' {
		p.i++
	}
	return p.i > start
}

func (p *sedScan) script() bool {
	depth := 0
	for {
		p.skipSeparators()
		if !p.more() {
			return depth == 0
		}
		switch p.peek() {
		case '#':
			for p.more() && p.peek() != '\n' {
				p.i++
			}
			continue
		case '}':
			if depth == 0 {
				return false
			}
			depth--
			p.i++
			if !p.endCommand() {
				return false
			}
			continue
		}
		if !p.addresses() {
			return false
		}
		p.skipBlank()
		for p.more() && p.peek() == '!' {
			p.i++
			p.skipBlank()
		}
		if !p.more() {
			return false
		}
		command := p.peek()
		p.i++
		switch command {
		case '{':
			depth++
		case 'p', 'P', 'd', 'D', 'n', 'N', 'g', 'G', 'h', 'H', 'x', '=', 'z', 'F':
			if !p.endCommand() {
				return false
			}
		case 'l', 'L', 'q', 'Q':
			p.skipBlank()
			p.digits()
			if !p.endCommand() {
				return false
			}
		case 's':
			if !p.substitute() {
				return false
			}
		case 'y':
			if !p.transliterate() {
				return false
			}
		case 'a', 'i', 'c':
			p.text()
		case 'b', 't', 'T':
			p.label()
		default:
			return false
		}
	}
}

// endCommand ends one command: only blanks, then a separator, the end of the
// script or a closing brace may follow.
func (p *sedScan) endCommand() bool {
	p.skipBlank()
	if !p.more() {
		return true
	}
	switch p.peek() {
	case ';', '\n':
		p.i++
		return true
	case '}':
		return true
	}
	return false
}

// addresses reads zero, one or two addresses. It reports false for a
// malformed one.
func (p *sedScan) addresses() bool {
	consumed, ok := p.address(true)
	if !ok {
		return false
	}
	if !consumed {
		return true
	}
	p.skipBlank()
	if p.more() && p.peek() == ',' {
		p.i++
		p.skipBlank()
		consumed, ok = p.address(false)
		return ok && consumed
	}
	return true
}

func (p *sedScan) address(first bool) (consumed, ok bool) {
	if !p.more() {
		return false, true
	}
	switch c := p.peek(); {
	case c >= '0' && c <= '9':
		p.digits()
		if p.more() && p.peek() == '~' {
			p.i++
			p.digits()
		}
		return true, true
	case c == '$':
		p.i++
		return true, true
	case c == '/' || c == '\\':
		delimiter := byte('/')
		if c == '\\' {
			p.i++
			if !p.more() || p.peek() == '\n' || p.peek() == '\\' {
				return true, false
			}
			delimiter = p.peek()
		}
		p.i++
		if !p.part(delimiter) {
			return true, false
		}
		for p.more() && (p.peek() == 'I' || p.peek() == 'M') {
			p.i++
		}
		return true, true
	case !first && (c == '+' || c == '~'):
		p.i++
		return true, p.digits()
	}
	return false, true
}

// part reads up to the next unescaped delimiter and consumes it.
func (p *sedScan) part(delimiter byte) bool {
	for p.more() {
		switch p.peek() {
		case '\\':
			p.i += 2
			continue
		case delimiter:
			p.i++
			return true
		}
		p.i++
	}
	return false
}

func (p *sedScan) substitute() bool {
	if !p.more() {
		return false
	}
	delimiter := p.peek()
	if delimiter == '\n' || delimiter == '\\' {
		return false
	}
	p.i++
	// the first part (regex or source set) and the second (replacement or
	// target set) each end at an unescaped delimiter
	if !p.part(delimiter) {
		return false
	}
	if !p.part(delimiter) {
		return false
	}
	for p.more() {
		c := p.peek()
		switch {
		case c == 'e' || c == 'w':
			return false
		case c == 'g' || c == 'p' || c == 'i' || c == 'I' || c == 'm' || c == 'M' || c >= '0' && c <= '9':
			p.i++
			continue
		}
		break
	}
	return p.endCommand()
}

func (p *sedScan) transliterate() bool {
	if !p.more() {
		return false
	}
	delimiter := p.peek()
	if delimiter == '\n' || delimiter == '\\' {
		return false
	}
	p.i++
	// the first part (regex or source set) and the second (replacement or
	// target set) each end at an unescaped delimiter
	if !p.part(delimiter) {
		return false
	}
	if !p.part(delimiter) {
		return false
	}
	return p.endCommand()
}

// text reads the text of a, i and c: to the end of the line, a backslash
// before a newline continuing it.
func (p *sedScan) text() {
	for p.more() {
		switch p.peek() {
		case '\\':
			p.i += 2
			continue
		case '\n':
			p.i++
			return
		}
		p.i++
	}
}

// label reads the label of b, t and T: to a semicolon or a newline.
func (p *sedScan) label() {
	for p.more() && p.peek() != ';' && p.peek() != '\n' {
		p.i++
	}
}
