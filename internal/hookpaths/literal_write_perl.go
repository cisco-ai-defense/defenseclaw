// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

type perlToken struct {
	text         string
	kind         byte
	start, end   int
	block        int
	blockKind    string
	modifierLoop bool
}

func perlIdent(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= 0x80
}

func perlClose(b byte) byte {
	switch b {
	case '(':
		return ')'
	case '[':
		return ']'
	case '{':
		return '}'
	case '<':
		return '>'
	}
	return b
}

func perlDelimitedEnd(code string, at int) (int, bool) {
	if at >= len(code) {
		return 0, false
	}
	open, close := code[at], perlClose(code[at])
	level := 0
	for i := at + 1; i < len(code); i++ {
		if code[i] == '\\' {
			i++
			continue
		}
		if close != open && code[i] == open {
			level++
			if level > 64 {
				return 0, false
			}
		}
		if code[i] == close {
			if level == 0 {
				return i + 1, true
			}
			level--
		}
	}
	return 0, false
}

func perlQuoteEnd(code string, at int) (int, bool) {
	for i := at + 1; i < len(code); i++ {
		if code[i] == '\\' {
			i++
			continue
		}
		if code[i] == code[at] {
			return i + 1, true
		}
	}
	return 0, false
}

func perlLex(code string) ([]perlToken, bool) {
	return perlLexAt(code, 0, 0)
}

func perlLexAt(code string, offset, recursion int) ([]perlToken, bool) {
	if recursion > 2 {
		return nil, false
	}
	out := make([]perlToken, 0, 32)
	emit := func(at, end int, kind byte) {
		out = append(out, perlToken{text: code[at:end], kind: kind, start: offset + at, end: offset + end})
	}
	operator := true
	statement := true
	lineStart := true
	var heredocs []perlHeredoc
	depth := 0
	steps := 0
	for i := 0; i < len(code); {
		steps++
		if steps > 4*len(code)+64 || depth > 64 {
			return nil, false
		}
		c := code[i]
		if c == '\n' {
			lineStart = true
			i++
			for _, marker := range heredocs {
				found := false
				for i < len(code) {
					end := strings.IndexByte(code[i:], '\n')
					if end < 0 {
						end = len(code) - i
					}
					line := code[i : i+end]
					candidate := line
					if marker.indent {
						candidate = strings.TrimSpace(line)
					}
					if candidate == marker.name {
						i += end
						if i < len(code) {
							i++
						}
						found = true
						break
					}
					if marker.interpolate && (strings.Contains(line, "@{[") || strings.Contains(line, "$"+"{\\")) {
						return nil, false
					}
					i += end
					if i < len(code) {
						i++
					}
				}
				if !found {
					return nil, false
				}
			}
			heredocs = nil
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\f' {
			i++
			continue
		}
		if lineStart && c == '=' && i+1 < len(code) && perlIdent(code[i+1]) {
			if !statement {
				return nil, false
			}
			for {
				end := strings.IndexByte(code[i:], '\n')
				if end < 0 {
					return out, true
				}
				i += end + 1
				if strings.HasPrefix(code[i:], "=cut") {
					end := strings.IndexByte(code[i:], '\n')
					if end < 0 {
						return out, true
					}
					i += end + 1
					break
				}
			}
			continue
		}
		lineStart = false
		if c == '#' && (i == 0 || code[i-1] != '$') {
			for i < len(code) && code[i] != '\n' {
				i++
			}
			continue
		}
		for _, dataWord := range []string{"__END__", "__DATA__"} {
			if strings.HasPrefix(code[i:], dataWord) && (i == 0 || !perlIdent(code[i-1])) {
				j := i + len(dataWord)
				if j == len(code) || !perlIdent(code[j]) {
					return out, true
				}
			}
		}
		if c == '<' && i+1 < len(code) && code[i+1] == '<' && operator {
			j := i + 2
			indent := j < len(code) && code[j] == '~'
			if indent {
				j++
			}
			interpolate := true
			if j >= len(code) {
				return nil, false
			}
			var marker string
			if code[j] == '\'' || code[j] == '"' {
				end, ok := perlQuoteEnd(code, j)
				if !ok {
					return nil, false
				}
				marker, interpolate, j = code[j+1:end-1], code[j] != '\'', end
			} else {
				end := j
				for end < len(code) && perlIdent(code[end]) {
					end++
				}
				if end == j {
					return nil, false
				}
				marker, j = code[j:end], end
			}
			heredocs = append(heredocs, perlHeredoc{name: marker, indent: indent, interpolate: interpolate})
			emit(i, j, 's')
			operator, statement = false, false
			i = j
			continue
		}
		if c == '\'' || c == '"' || c == 96 {
			end, ok := perlQuoteEnd(code, i)
			if !ok {
				return nil, false
			}
			if c != '\'' && (strings.Contains(code[i:end], "@{[") || strings.Contains(code[i:end], "$"+"{\\")) {
				return nil, false
			}
			emit(i, end, 's')
			operator, statement = false, false
			i = end
			continue
		}
		if c >= '0' && c <= '9' {
			end := i + 1
			for end < len(code) && (perlIdent(code[end]) || code[end] == '.') {
				end++
			}
			emit(i, end, 'n')
			operator, statement = false, false
			i = end
			continue
		}
		if perlIdent(c) && (c < '0' || c > '9') {
			end := i + 1
			for end < len(code) && (perlIdent(code[end]) || end+1 < len(code) && code[end] == ':' && code[end+1] == ':') {
				if code[end] == ':' {
					end += 2
				} else {
					end++
				}
			}
			word := code[i:end]
			if word == "format" {
				return nil, false
			}
			quoteContext := operator && (len(out) == 0 || !perlQuoteLikeExcluded(out[len(out)-1].text)) &&
				(len(out) == 0 || out[len(out)-1].text != "{" || end >= len(code) || code[end] != '}')
			quoteWord := word == "q" || word == "qq" || word == "qw" || word == "qr" ||
				word == "m" || word == "s" || word == "y" || word == "tr"
			quoteAt := end
			if quoteContext && quoteWord {
				for quoteAt < len(code) {
					if code[quoteAt] == ' ' || code[quoteAt] == '\t' || code[quoteAt] == '\n' {
						quoteAt++
						continue
					}
					if code[quoteAt] == '#' && quoteAt > end {
						for quoteAt < len(code) && code[quoteAt] != '\n' {
							quoteAt++
						}
						continue
					}
					break
				}
			}
			if quoteContext && quoteWord && quoteAt < len(code) && !strings.HasPrefix(code[quoteAt:], "=>") {
				last, ok := perlDelimitedEnd(code, quoteAt)
				if !ok {
					return nil, false
				}
				replStart, replEnd := 0, 0
				if word == "s" || word == "y" || word == "tr" {
					if perlClose(code[quoteAt]) == code[quoteAt] {
						replStart = last
						last, ok = perlDelimitedEnd(code, last-1)
						if !ok {
							return nil, false
						}
						replEnd = last - 1
					} else {
						j := last
						for j < len(code) && (code[j] == ' ' || code[j] == '\n' || code[j] == '\t') {
							j++
						}
						for j < len(code) && code[j] == '#' {
							for j < len(code) && code[j] != '\n' {
								j++
							}
							for j < len(code) && (code[j] == ' ' || code[j] == '\n' || code[j] == '\t') {
								j++
							}
						}
						if j >= len(code) || code[j] != code[quoteAt] {
							return nil, false
						}
						replStart = j + 1
						last, ok = perlDelimitedEnd(code, j)
						if !ok {
							return nil, false
						}
						replEnd = last - 1
					}
				}
				flags := last
				for flags < len(code) && code[flags] >= 'a' && code[flags] <= 'z' {
					flags++
				}
				if word == "qq" || word == "qr" || word == "m" || word == "s" {
					body := code[quoteAt:flags]
					if strings.Contains(body, "@{[") || strings.Contains(body, "$"+"{\\") {
						return nil, false
					}
				}
				emit(i, flags, 's')
				if word == "s" && strings.Contains(code[last:flags], "e") && replEnd > replStart {
					sub, complete := perlLexAt(code[replStart:replEnd], offset+replStart, recursion+1)
					if !complete {
						return nil, false
					}
					out = append(out, sub...)
				}
				operator, statement = false, false
				i = flags
				continue
			}
			emit(i, end, 'w')
			switch word {
			case "split", "grep", "map", "join", "print", "say", "return", "and", "or", "not", "if", "unless", "while", "until", "push", "unshift", "die", "warn", "for", "foreach", "sub", "use", "my", "our", "local", "BEGIN", "UNITCHECK", "CHECK", "INIT", "do", "eval":
				operator = true
			default:
				operator = false
			}
			if len(out) >= 2 && out[len(out)-2].text == "use" {
				operator = true
			}
			statement = false
			i = end
			continue
		}
		if (c == '/' || c == '?') && !operator && len(out) > 0 && out[len(out)-1].kind == 'w' {
			return nil, false
		}
		if c == '<' && operator {
			end, ok := perlDelimitedEnd(code, i)
			if !ok {
				return nil, false
			}
			emit(i, end, 's')
			operator, statement = false, false
			i = end
			continue
		}
		if (c == '/' || c == '?') && operator {
			end, ok := perlDelimitedEnd(code, i)
			if !ok {
				return nil, false
			}
			emit(i, end, 's')
			operator, statement = false, false
			i = end
			continue
		}
		start := i
		i++
		if i < len(code) {
			pair := code[start : i+1]
			if pair == "->" || pair == "::" || pair == "=>" || pair == "=~" || pair == "!~" {
				i++
			}
		}
		emit(start, i, 'o')
		switch code[start:i] {
		case "(", "[", "{":
			depth++
			operator = true
			statement = code[start] == '{'
		case ")", "]", "}":
			if depth == 0 {
				return nil, false
			}
			depth--
			operator = false
			statement = code[start] == '}'
		case ";":
			operator, statement = true, true
		default:
			operator, statement = true, false
		}
	}
	return out, depth == 0 && len(heredocs) == 0
}

type perlCall struct {
	name       string
	start, end int
	args       [4][2]int
	argc       int
	block      int
}

func perlBuiltinName(tokens []perlToken, at int) string {
	if tokens[at].kind != 'w' {
		return ""
	}
	name := strings.TrimPrefix(tokens[at].text, "CORE::")
	if strings.HasPrefix(name, "CORE::") {
		return ""
	}
	switch name {
	case "open", "sysopen", "unlink", "rename", "link", "symlink", "truncate":
	default:
		return ""
	}
	qualified := strings.HasPrefix(tokens[at].text, "CORE::")
	if tokens[at].text != name && !qualified {
		return ""
	}
	if at > 0 {
		prev := tokens[at-1].text
		if prev == "->" || prev == "::" || prev == "sub" || prev == "$" || prev == "@" {
			return ""
		}
		if prev == "&" && !qualified {
			if at < 2 {
				return ""
			}
			left := tokens[at-2]
			switch left.text {
			case ")", "]":
			case "}":
				if left.blockKind == "sub" {
					return ""
				}
			default:
				if left.kind != 'n' && left.kind != 's' {
					return ""
				}
			}
		}
		if (prev == "*" || prev == "%") && !qualified {
			if at < 2 || !perlTermToken(tokens[at-2]) {
				return ""
			}
		}
		if prev == "{" && at+1 < len(tokens) && tokens[at+1].text == "}" {
			return ""
		}
	}
	if at+1 < len(tokens) && tokens[at+1].text == "=>" {
		return ""
	}
	return name
}

type perlCollector struct {
	index int
	begin int
	depth int
	paren bool
}

func perlCalls(tokens []perlToken) []perlCall {
	var calls []perlCall
	var active []perlCollector
	depth := 0
	addArg := func(c *perlCollector, hi int) {
		call := &calls[c.index]
		if c.begin >= hi || call.argc >= len(call.args) {
			return
		}
		call.args[call.argc] = [2]int{tokens[c.begin].start, tokens[hi-1].end}
		call.argc++
	}
	for i, tok := range tokens {
		sym := tok.text
		for len(active) != 0 {
			top := &active[len(active)-1]
			if depth != top.depth {
				break
			}
			end := sym == ";" || sym == "}" ||
				sym == ")" && top.paren ||
				!top.paren && (sym == ")" || sym == "or" || sym == "and" ||
					sym == "xor" || sym == "if" || sym == "unless" ||
					sym == "while" || sym == "until" || sym == "for" || sym == "foreach")
			if end {
				addArg(top, i)
				calls[top.index].end = tok.start
				active = active[:len(active)-1]
				continue
			}
			if sym == "," || sym == "=>" {
				addArg(top, i)
				top.begin = i + 1
			}
			break
		}
		if name := perlBuiltinName(tokens, i); name != "" && i+1 < len(tokens) {
			paren := tokens[i+1].text == "("
			begin, atDepth := i+1, depth
			if paren {
				begin, atDepth = i+2, depth+1
			}
			calls = append(calls, perlCall{name: name, start: tok.start, block: tok.block})
			active = append(active, perlCollector{index: len(calls) - 1, begin: begin, depth: atDepth, paren: paren})
		}
		switch sym {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		}
	}
	for len(active) != 0 {
		top := &active[len(active)-1]
		addArg(top, len(tokens))
		if len(tokens) != 0 {
			calls[top.index].end = tokens[len(tokens)-1].end
		}
		active = active[:len(active)-1]
	}
	result := calls[:0]
	for _, call := range calls {
		if call.argc != 0 {
			result = append(result, call)
		}
	}
	return result
}

func perlFixedPath(tokens []perlToken, start, end int) (string, bool) {
	if start >= end {
		return "", false
	}
	var result strings.Builder
	wantString := true
	count := 0
	lo, hi := 0, len(tokens)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if tokens[mid].start < start {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	for j := lo; j < len(tokens) && tokens[j].start < end; j++ {
		tok := tokens[j]
		if tok.end > end {
			return "", false
		}
		count++
		if wantString {
			if tok.kind != 's' || len(tok.text) < 2 || tok.text[0] != '\'' && tok.text[0] != '"' {
				return "", false
			}
			value, ok := literalString(tok.text)
			if !ok {
				return "", false
			}
			if tok.text[0] == '"' && strings.ContainsAny(strings.ReplaceAll(value, "$ENV{HOME}", ""), "$@") {
				return "", false
			}
			result.WriteString(value)
		} else if tok.text != "." {
			return "", false
		}
		wantString = !wantString
	}
	if count == 0 || wantString {
		return "", false
	}
	return result.String(), true
}

// perlProvenWrites adds only paths supported by a complete Perl parse and a
// positive write rule. An incomplete program contributes no new operands.
// depth is the shell reader depth of the shell that runs the Perl.
func perlProvenWrites(code, cwd, home string, depth int) []string {
	if !strings.ContainsAny(code, "'\"") ||
		!strings.Contains(code, "open") && !strings.Contains(code, "unlink") &&
			!strings.Contains(code, "rename") && !strings.Contains(code, "link") &&
			!strings.Contains(code, "truncate") {
		return nil
	}
	tokens, complete := perlLex(code)
	if !complete {
		return nil
	}
	_, complete = perlBlockContexts(tokens)
	if !complete {
		return nil
	}
	calls := perlCalls(tokens)
	override := perlResolveOverrides(tokens, calls)
	paths := perlResolveDirectWrites(tokens, calls, override.skip)
	paths = append(paths, override.paths...)
	paths = append(paths, perlSysopenWrites(tokens, calls, perlNamedDefinitions(tokens), override.skip)...)
	return append(paths, perlPipeWrites(tokens, calls, override.skip, cwd, home, depth)...)
}

func perlQuoteLikeExcluded(previous string) bool {
	switch previous {
	case "->", "::", "sub", "&", "$", "@", "%", "*", "-":
		return true
	}
	return false
}

type perlBlock struct {
	parent int
	kind   string
}

func perlBlockContexts(tokens []perlToken) ([]perlBlock, bool) {
	blocks := []perlBlock{{parent: -1, kind: "root"}}
	stack := []int{0}
	stmtStart := 0
	for i := range tokens {
		tokens[i].block = stack[len(stack)-1]
		tokens[i].blockKind = blocks[stack[len(stack)-1]].kind
		switch tokens[i].text {
		case "while", "until", "for", "foreach":
			if i > stmtStart {
				for j := stmtStart; j < i; j++ {
					tokens[j].modifierLoop = true
				}
			}
		case ";":
			stmtStart = i + 1
		case "{":
			kind := "plain"
			for j := i - 1; j >= 0; j-- {
				word := tokens[j].text
				if word == ";" || word == "{" || word == "}" {
					break
				}
				switch word {
				case "sub":
					kind = "sub"
				case "for", "foreach", "while", "until":
					if kind != "sub" {
						kind = "loop"
					}
				case "BEGIN", "UNITCHECK", "CHECK", "INIT":
					if kind == "plain" {
						kind = word
					}
				case "eval":
					if kind == "plain" {
						kind = "eval"
					}
				case "do":
					if kind == "plain" {
						kind = "do"
					}
				}
			}
			blocks = append(blocks, perlBlock{parent: stack[len(stack)-1], kind: kind})
			stack = append(stack, len(blocks)-1)
			stmtStart = i + 1
		case "}":
			if len(stack) == 1 {
				return nil, false
			}
			stack = stack[:len(stack)-1]
			stmtStart = i + 1
		}
	}
	return blocks, len(stack) == 1
}

func perlTermToken(token perlToken) bool {
	if token.kind == 'w' || token.kind == 'n' || token.kind == 's' {
		return true
	}
	switch token.text {
	case ")", "]", "}":
		return true
	}
	return false
}

type perlHeredoc struct {
	name        string
	indent      bool
	interpolate bool
}
