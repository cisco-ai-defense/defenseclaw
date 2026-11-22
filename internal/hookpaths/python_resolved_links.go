// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type pythonResolvedLink struct {
	source, name string
	symbolic     bool
	start, end   int
}

func pythonOSLinkCalls(code, home string) ([]pythonResolvedLink, [][2]int, bool) {
	if !pythonImportsOS.MatchString(code) {
		return nil, nil, false
	}
	starts := pythonOSLinkCallStart.FindAllStringIndex(code, -1)
	var links []pythonResolvedLink
	var spans [][2]int
	for _, loc := range starts {
		open := loc[1] - 1
		close, ok := pythonCallClose(code, open)
		if !ok {
			return nil, nil, false
		}
		args, ok := pythonCallArguments(code[open+1 : close])
		if !ok || len(args) != 2 {
			return nil, nil, false
		}
		source, sourceOK := pythonPathExpression(args[0], home)
		name, nameOK := pythonPathExpression(args[1], home)
		if !sourceOK || !nameOK || source == "" || name == "" {
			return nil, nil, false
		}
		spans = append(spans, [2]int{loc[0], close + 1})
		links = append(links, pythonResolvedLink{
			source: source, name: name,
			symbolic: strings.Contains(code[loc[0]:loc[1]], "symlink"),
			start:    loc[0], end: close + 1,
		})
	}
	return links, spans, len(starts) > 0
}

var pythonOSLinkCallStart = regexp.MustCompile(`\bos\.(?:sym)?link\(`)

func pythonCallClose(s string, open int) (int, bool) {
	quote, escaped, depth := byte(0), false, 0
	for i := open; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
			if depth < 0 {
				return 0, false
			}
		}
	}
	return 0, false
}

func pythonCallArguments(s string) ([]string, bool) {
	var args []string
	start, parens, brackets, braces := 0, 0, 0, 0
	quote, escaped := byte(0), false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			parens++
		case ')':
			parens--
		case '[':
			brackets++
		case ']':
			brackets--
		case '{':
			braces++
		case '}':
			braces--
		case ',':
			if parens == 0 && brackets == 0 && braces == 0 {
				args = append(args, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
		if parens < 0 || brackets < 0 || braces < 0 {
			return nil, false
		}
	}
	if quote != 0 || parens != 0 || brackets != 0 || braces != 0 {
		return nil, false
	}
	args = append(args, strings.TrimSpace(s[start:]))
	return args, len(args) > 0
}

type pythonPathParser struct {
	s    string
	i    int
	home string
}

func pythonPathExpression(s, home string) (string, bool) {
	p := pythonPathParser{s: s, home: home}
	value, ok := p.expr()
	p.space()
	return value, ok && p.i == len(p.s)
}

func (p *pythonPathParser) space() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n') {
		p.i++
	}
}

func (p *pythonPathParser) expr() (string, bool) {
	value, ok := p.atom()
	if !ok {
		return "", false
	}
	for {
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != '+' {
			return value, true
		}
		p.i++
		next, ok := p.atom()
		if !ok {
			return "", false
		}
		value += next
	}
}

func (p *pythonPathParser) atom() (string, bool) {
	p.space()
	if p.i >= len(p.s) {
		return "", false
	}
	if p.s[p.i] == '\'' || p.s[p.i] == '"' {
		return p.stringLiteral()
	}
	switch {
	case strings.HasPrefix(p.s[p.i:], "os.environ"):
		p.i += len("os.environ")
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != '[' {
			return "", false
		}
		p.i++
		key, ok := p.atom()
		if !ok || key != "HOME" {
			return "", false
		}
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != ']' {
			return "", false
		}
		p.i++
		return p.home, p.home != ""
	case strings.HasPrefix(p.s[p.i:], "os.path.expanduser"):
		p.i += len("os.path.expanduser")
		args, ok := p.callArgs()
		if !ok || len(args) != 1 {
			return "", false
		}
		path, ok := pythonPathExpression(args[0], p.home)
		if !ok {
			return "", false
		}
		if path == "~" {
			return p.home, p.home != ""
		}
		if strings.HasPrefix(path, "~/") && p.home != "" {
			return filepath.Join(p.home, path[2:]), true
		}
		return path, true
	case strings.HasPrefix(p.s[p.i:], "os.path.join"):
		p.i += len("os.path.join")
		args, ok := p.callArgs()
		if !ok || len(args) < 2 {
			return "", false
		}
		parts := make([]string, 0, len(args))
		for _, arg := range args {
			part, ok := pythonPathExpression(arg, p.home)
			if !ok {
				return "", false
			}
			parts = append(parts, part)
		}
		return filepath.Join(parts...), true
	case strings.HasPrefix(p.s[p.i:], "chr(126)"):
		p.i += len("chr(126)")
		return "~", true
	default:
		return "", false
	}
}

func (p *pythonPathParser) callArgs() ([]string, bool) {
	p.space()
	if p.i >= len(p.s) || p.s[p.i] != '(' {
		return nil, false
	}
	open := p.i
	close, ok := pythonCallClose(p.s, open)
	if !ok {
		return nil, false
	}
	args, ok := pythonCallArguments(p.s[open+1 : close])
	if !ok {
		return nil, false
	}
	p.i = close + 1
	return args, true
}

func (p *pythonPathParser) stringLiteral() (string, bool) {
	quote := p.s[p.i]
	start := p.i
	p.i++
	escaped := false
	for p.i < len(p.s) {
		c := p.s[p.i]
		p.i++
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == quote {
			raw := p.s[start:p.i]
			if quote == '"' {
				value, err := strconv.Unquote(raw)
				return value, err == nil
			}
			body := raw[1 : len(raw)-1]
			body = strings.ReplaceAll(body, `\\'`, `'`)
			if strings.Contains(body, `\\`) {
				return "", false
			}
			return body, true
		}
	}
	return "", false
}
