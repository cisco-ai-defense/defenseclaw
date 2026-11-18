// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

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

// sedScriptEffects reads the output operands and literal commands of a sed
// script. They are independent of the file that -i replaces: a safe entry
// replacement cannot excuse a w/W output or an e command. The reader accepts
// the same script positions with -e, -eSCRIPT and --expression=SCRIPT.
func sedScriptEffects(words []string) (outputs, commands []string) {
	var scripts []string
	explicit := false
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "-e" || word == "--expression":
			explicit = true
			if i+1 < len(words) {
				i++
				scripts = append(scripts, words[i])
			}
		case strings.HasPrefix(word, "--expression="):
			explicit = true
			scripts = append(scripts, strings.TrimPrefix(word, "--expression="))
		case strings.HasPrefix(word, "-e") && len(word) > 2:
			explicit = true
			scripts = append(scripts, word[2:])
		case word == "--":
			if !explicit && i+1 < len(words) {
				scripts = append(scripts, words[i+1])
			}
			i = len(words)
		case strings.HasPrefix(word, "-"):
			// Other options do not make their following word a script.
		case !explicit:
			scripts = append(scripts, word)
			explicit = true
		}
	}
	for _, script := range scripts {
		if len(script) > MaxPayloadBytes || strings.Contains(script, sedHole) {
			continue
		}
		p := sedScan{s: script}
		for p.more() {
			p.skipSeparators()
			if !p.more() || !p.addresses() {
				break
			}
			p.skipBlank()
			for p.more() && p.peek() == '!' {
				p.i++
				p.skipBlank()
			}
			if !p.more() {
				break
			}
			command := p.peek()
			p.i++
			switch command {
			case '{', '}':
				// The next command can start immediately after a brace.
			case '#':
				for p.more() && p.peek() != '\n' {
					p.i++
				}
			case 'a', 'i', 'c':
				p.text()
			case 'b', 't', 'T':
				p.label()
			case 'w', 'W', 'e':
				p.skipBlank()
				start := p.i
				for p.more() && p.peek() != '\n' {
					p.i++
				}
				value := strings.TrimSpace(script[start:p.i])
				if value != "" {
					if command == 'e' {
						commands = append(commands, value)
					} else {
						outputs = append(outputs, value)
					}
				}
			case 's':
				if !p.more() {
					break
				}
				delim := p.peek()
				p.i++
				if !p.part(delim) {
					break
				}
				if !p.part(delim) {
					break
				}
				for p.more() && p.peek() != ';' && p.peek() != '\n' {
					if p.peek() == 'w' {
						p.i++
						p.skipBlank()
						start := p.i
						for p.more() && p.peek() != '\n' {
							p.i++
						}
						name := strings.TrimSpace(script[start:p.i])
						if name != "" {
							outputs = append(outputs, name)
						}
						break
					}
					p.i++
				}
			case 'y':
				p.transliterate()
			default:
				for p.more() && p.peek() != ';' && p.peek() != '\n' {
					p.i++
				}
			}
		}
	}
	return outputs, commands
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
