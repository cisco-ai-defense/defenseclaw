// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
	"strings"
)

var nodeDirectFileWrite = regexp.MustCompile(`^require\(['"]fs['"]\)\.(?:writeFileSync|appendFileSync)\(`)

// nodeInertWriteData accepts a complete inline file write whose destination
// is ordinary and whose second operand cannot execute code. It is shared by
// the interpreter boundary and the protected-path mention reader.
func nodeInertWriteData(code, cwd, home string) bool {
	if !filepath.IsAbs(cwd) || !filepath.IsAbs(home) {
		return false
	}
	code = strings.TrimSpace(code)
	location := nodeDirectFileWrite.FindStringIndex(code)
	if location == nil || len(code) > 16<<10 {
		return false
	}
	call, complete := literalBoundedCall(code, location[1]-1)
	if !complete || strings.Trim(strings.TrimSpace(code[location[1]-1+len(call):]), "; ") != "" {
		return false
	}
	args, complete := nodeTopLevelArgs(call)
	if !complete || len(args) != 2 || !nodeInertData(args[1]) {
		return false
	}
	target, fixed := nodeStaticTarget(args[0], home)
	if !fixed {
		return false
	}
	resolved, answered := ResolveWriteTarget(OperandPath(target, cwd))
	return answered && !protectedReachPath(resolved, newProtectedFiles(home), filepath.Join(home, ".ssh"))
}

func nodeStaticTarget(value, home string) (string, bool) {
	if target, fixed := literalString(value); fixed {
		return target, true
	}
	value = strings.TrimSpace(value)
	const prefix = "process.env.HOME +"
	if !strings.HasPrefix(value, prefix) || !filepath.IsAbs(home) {
		return "", false
	}
	suffix, fixed := literalString(strings.TrimSpace(strings.TrimPrefix(value, prefix)))
	if !fixed || !strings.HasPrefix(suffix, "/") || strings.Contains(suffix, "..") {
		return "", false
	}
	return home + suffix, true
}

func nodeInertData(value string) bool {
	if _, fixed := literalString(value); fixed {
		return true
	}
	value = strings.TrimSpace(value)
	const prefix = "JSON.stringify"
	if !strings.HasPrefix(value, prefix+"(") {
		return false
	}
	call, complete := literalBoundedCall(value, len(prefix))
	if !complete || len(call) != len(value)-len(prefix) {
		return false
	}
	json := nodeDataParser{text: strings.TrimSpace(call[1 : len(call)-1])}
	return json.value(0) && json.end()
}

// nodeTopLevelArgs keeps commas in a data object or array inside one operand.
func nodeTopLevelArgs(call string) ([]string, bool) {
	if len(call) < 2 || call[0] != '(' || call[len(call)-1] != ')' {
		return nil, false
	}
	var args []string
	start := 1
	var quote byte
	var stack []byte
	for i := 1; i < len(call)-1; i++ {
		c := call[i]
		if quote != 0 {
			if c == '\\' { // A dynamic escape is outside the static proof.
				return nil, false
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(', '{', '[':
			stack = append(stack, c)
		case ')', '}', ']':
			if len(stack) == 0 || stack[len(stack)-1] != map[byte]byte{')': '(', '}': '{', ']': '['}[c] {
				return nil, false
			}
			stack = stack[:len(stack)-1]
		case ',':
			if len(stack) == 0 {
				args = append(args, strings.TrimSpace(call[start:i]))
				start = i + 1
			}
		}
	}
	if quote != 0 || len(stack) != 0 {
		return nil, false
	}
	return append(args, strings.TrimSpace(call[start:len(call)-1])), true
}

type nodeDataParser struct {
	text string
	pos  int
}

func (p *nodeDataParser) space() {
	for p.pos < len(p.text) && (p.text[p.pos] == ' ' || p.text[p.pos] == '\t' || p.text[p.pos] == '\n') {
		p.pos++
	}
}

func (p *nodeDataParser) end() bool {
	p.space()
	return p.pos == len(p.text)
}

func (p *nodeDataParser) string() bool {
	p.space()
	if p.pos >= len(p.text) || p.text[p.pos] != '\'' && p.text[p.pos] != '"' {
		return false
	}
	quote := p.text[p.pos]
	p.pos++
	for p.pos < len(p.text) {
		c := p.text[p.pos]
		p.pos++
		if c == '\\' {
			return false
		}
		if c == quote {
			return true
		}
	}
	return false
}

func (p *nodeDataParser) value(depth int) bool {
	if depth >= 8 {
		return false
	}
	p.space()
	if p.pos >= len(p.text) {
		return false
	}
	switch p.text[p.pos] {
	case '\'', '"':
		return p.string()
	case '{', '[':
		open := p.text[p.pos]
		close := byte('}')
		if open == '[' {
			close = ']'
		}
		p.pos++
		p.space()
		if p.pos < len(p.text) && p.text[p.pos] == close {
			p.pos++
			return true
		}
		for {
			if open == '{' {
				if p.pos < len(p.text) && (p.text[p.pos] == '\'' || p.text[p.pos] == '"') {
					if !p.string() {
						return false
					}
				} else if !p.identifier() {
					return false
				}
				p.space()
				if p.pos >= len(p.text) || p.text[p.pos] != ':' {
					return false
				}
				p.pos++
			}
			if !p.value(depth + 1) {
				return false
			}
			p.space()
			if p.pos >= len(p.text) {
				return false
			}
			if p.text[p.pos] == close {
				p.pos++
				return true
			}
			if p.text[p.pos] != ',' {
				return false
			}
			p.pos++
		}
	default:
		start := p.pos
		for p.pos < len(p.text) && (p.text[p.pos] >= 'a' && p.text[p.pos] <= 'z' ||
			p.text[p.pos] >= '0' && p.text[p.pos] <= '9' || strings.ContainsRune("-+.eE", rune(p.text[p.pos]))) {
			p.pos++
		}
		token := p.text[start:p.pos]
		return token == "true" || token == "false" || token == "null" || nodeNumber.MatchString(token)
	}
}

var nodeNumber = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)

func (p *nodeDataParser) identifier() bool {
	p.space()
	start := p.pos
	if start >= len(p.text) || !nodeIdentFirst(p.text[start]) {
		return false
	}
	p.pos++
	for p.pos < len(p.text) && (nodeIdentFirst(p.text[p.pos]) || p.text[p.pos] >= '0' && p.text[p.pos] <= '9') {
		p.pos++
	}
	return p.pos > start
}

func nodeIdentFirst(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$'
}
