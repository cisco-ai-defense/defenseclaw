// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strconv"
	"strings"
	"unicode"
)

// stringLit builds a StringLit from a TokString token, resolving the literal
// value for literal forms and, for expandable forms, the segment list.
func (p *parser) stringLit(t Token) *StringLit {
	sl := &StringLit{span: span{t.Start, t.End}, Kind: t.Str}
	switch t.Str {
	case StrSingle:
		inner := trimRuneDelims(t.Raw)
		sl.Value = collapseDoubled(inner, isSingleQuote)
		sl.Static = true
	case StrHereSingle:
		sl.Value = hereBody(t.Raw)
		sl.Static = true
	case StrDouble:
		inner := trimRuneDelims(t.Raw)
		inner = collapseDoubled(inner, isDoubleQuote)
		parts, static, lit := p.expandable(inner, t.Start+1)
		sl.Parts, sl.Static, sl.Value = parts, static, lit
	case StrHereDouble:
		inner := hereBody(t.Raw)
		parts, static, lit := p.expandable(inner, t.Start)
		sl.Parts, sl.Static, sl.Value = parts, static, lit
	default:
		sl.Value = t.Raw
		sl.Static = true
	}
	return sl
}

// trimRuneDelims drops the first and last rune (the quote delimiters), which
// may be multi-byte Unicode quote characters.
func trimRuneDelims(s string) string {
	rs := []rune(s)
	if len(rs) >= 2 {
		return string(rs[1 : len(rs)-1])
	}
	return ""
}

// collapseDoubled replaces each doubled quote-class pair (the quote-escape
// form) with one repl rune.
func collapseDoubled(s string, isClass func(rune) bool) string {
	rs := []rune(s)
	var b strings.Builder
	for i := 0; i < len(rs); i++ {
		if isClass(rs[i]) && i+1 < len(rs) && isClass(rs[i+1]) {
			b.WriteRune(rs[i]) // a doubled quote collapses to that same quote char
			i++
			continue
		}
		b.WriteRune(rs[i])
	}
	return b.String()
}

// hereBody extracts the content of a here-string (@" ... "@ / @' ... '@),
// which is the text between the first line break after the opener and the
// terminating line that begins with "@ or '@.
func hereBody(raw string) string {
	nl := strings.IndexByte(raw, '\n')
	if nl < 0 {
		return ""
	}
	body := raw[nl+1:]
	// strip the terminator: last line is  "@  or  '@
	if i := strings.LastIndexByte(body, '\n'); i >= 0 {
		return strings.TrimSuffix(body[:i], "\r")
	}
	// no trailing newline before terminator: drop the final 2 delimiter bytes
	if len(body) >= 2 {
		return body[:len(body)-2]
	}
	return body
}

// expandable scans the body of a double-quoted / here-double string and
// returns its segments (literal runs and embedded $var / $(...) expressions),
// whether it is fully static, and the concatenated literal skeleton.
func (p *parser) expandable(s string, base int) (parts []StringPart, static bool, literal string) {
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, StringPart{Lit: lit.String()})
			lit.Reset()
		}
	}
	runes := []rune(s)
	hasExpr := false
	forceDyn := false
	for i := 0; i < len(runes); {
		r := runes[i]
		switch {
		case r == '`' && i+1 < len(runes):
			if runes[i+1] == 'u' && i+2 < len(runes) && runes[i+2] == '{' {
				j := i + 3
				for j < len(runes) && runes[j] != '}' {
					j++
				}
				if j < len(runes) {
					switch p.dialect {
					case DialectWindowsPS51:
						lit.WriteString(string(runes[i+1 : j+1])) // `u{..} literal in 5.1
						i = j + 1
						continue
					case DialectUnknown:
						forceDyn = true
						lit.WriteString(string(runes[i+1 : j+1]))
						i = j + 1
						continue
					default:
						if cp, err := strconv.ParseInt(string(runes[i+3:j]), 16, 32); err == nil && cp >= 0 && cp <= 0x10FFFF {
							lit.WriteRune(rune(cp))
							i = j + 1
							continue
						}
					}
				}
				forceDyn = true // malformed `u{...}: cannot resolve statically
			}
			if runes[i+1] == 'e' {
				switch p.dialect {
				case DialectWindowsPS51:
					lit.WriteRune('e')
				case DialectUnknown:
					forceDyn = true
					lit.WriteRune('e')
				default:
					lit.WriteRune(0x1b)
				}
				i += 2
				continue
			}
			lit.WriteRune(backtickEscape(runes[i+1]))
			i += 2
		case r == '$' && i+1 < len(runes) && runes[i+1] == '(':
			flush()
			inner, consumed := scanParenBody(runes[i+2:])
			stmts, ds := p.subParse(inner)
			p.diags = append(p.diags, ds...)
			parts = append(parts, StringPart{Expr: &SubExpr{Statements: stmts}})
			hasExpr = true
			i += 2 + consumed
		case r == '$' && i+1 < len(runes) && runes[i+1] != '(' && dollarStartsVar(runes[i+1]):
			flush()
			v, consumed := scanEmbeddedVar(runes[i:])
			parts = append(parts, StringPart{Expr: v})
			hasExpr = true
			i += consumed
		default:
			lit.WriteRune(r)
			i++
		}
	}
	flush()
	static = !hasExpr && !forceDyn
	for _, pt := range parts {
		if pt.Expr == nil {
			literal += pt.Lit
		}
	}
	return parts, static, literal
}

func backtickEscape(r rune) rune {
	switch r {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case '0':
		return 0
	case 'a':
		return 7
	case 'b':
		return 8
	case 'f':
		return 12
	case 'v':
		return 11
	}
	return r
}

// dollarStartsVar reports whether a '$' followed by r begins a variable or a
// $( ) sub-expression (so a bareword ends before it). Matches the tokenizer:
// a name char, a digit, '_', '?', '^', '$', '{' or '('.
func dollarStartsVar(r rune) bool {
	return r == '(' || r == '{' || r == '$' || r == '?' || r == '^' || r == '_' || r == ':' ||
		unicode.IsLetter(r) || unicode.IsDigit(r)
}

// decodeBacktick resolves PowerShell backtick escapes in a bareword or command
// name per the parser's dialect. `n `t `r `0 `a `b `f `v and `<char> are the
// same in all editions; `e (ESC) and `u{hex} exist only in PS 6/7, so under
// DialectWindowsPS51 they stay literal and under DialectUnknown they make the
// value ambiguous (the second return is true -> the caller marks it
// non-static). When stripQuotes is set, unescaped quote-class delimiters are
// dropped (command-name generic token).
func (p *parser) decodeBacktick(raw string, stripQuotes bool) (string, bool) {
	rs := []rune(raw)
	var b strings.Builder
	ambiguous := false
	for i := 0; i < len(rs); i++ {
		if rs[i] == '`' && i+1 < len(rs) {
			c := rs[i+1]
			if c == 'u' && i+2 < len(rs) && rs[i+2] == '{' {
				j := i + 3
				for j < len(rs) && rs[j] != '}' {
					j++
				}
				if j < len(rs) {
					switch p.dialect {
					case DialectWindowsPS51:
						b.WriteString(string(rs[i+1 : j+1])) // `u{hex} is literal in 5.1
						i = j
						continue
					case DialectUnknown:
						ambiguous = true
						b.WriteString(string(rs[i+1 : j+1]))
						i = j
						continue
					default: // PS 6/7
						if cp, err := strconv.ParseInt(string(rs[i+3:j]), 16, 32); err == nil && cp >= 0 && cp <= 0x10FFFF {
							b.WriteRune(rune(cp))
							i = j
							continue
						}
					}
				}
				b.WriteRune('u')
				i++
				continue
			}
			if c == 'e' {
				switch p.dialect {
				case DialectWindowsPS51:
					b.WriteRune('e')
				case DialectUnknown:
					ambiguous = true
					b.WriteRune('e')
				default:
					b.WriteRune(0x1b)
				}
				i++
				continue
			}
			b.WriteRune(backtickEscape(c))
			i++
			continue
		}
		if stripQuotes && (isSingleQuote(rs[i]) || isDoubleQuote(rs[i])) {
			continue
		}
		b.WriteRune(rs[i])
	}
	return b.String(), ambiguous
}

// scanParenBody returns the text inside a $( ... ) starting just after the '(',
// and how many runes were consumed including the closing ')'.
func scanParenBody(runes []rune) (string, int) {
	depth := 1
	var b strings.Builder
	i := 0
	for ; i < len(runes); i++ {
		r := runes[i]
		if r == '(' {
			depth++
		} else if r == ')' {
			depth--
			if depth == 0 {
				return b.String(), i + 1
			}
		}
		b.WriteRune(r)
	}
	return b.String(), i
}

// scanEmbeddedVar reads a $var / ${...} / $scope:name beginning at runes[0]=='$'
// and returns a Variable plus the rune count consumed.
func scanEmbeddedVar(runes []rune) (Expr, int) {
	i := 1 // past $
	if i < len(runes) && runes[i] == '{' {
		i++
		start := i
		for i < len(runes) && runes[i] != '}' {
			i++
		}
		name := string(runes[start:i])
		if i < len(runes) {
			i++ // }
		}
		scope := ""
		if idx := strings.IndexByte(name, ':'); idx >= 0 {
			scope, name = name[:idx], name[idx+1:]
		}
		return &Variable{Name: name, Scope: scope}, i
	}
	if i < len(runes) && (runes[i] == '$' || runes[i] == '?' || runes[i] == '^') {
		return &Variable{Name: string(runes[i])}, i + 1
	}
	start := i
	for i < len(runes) && isNameChar(runes[i]) {
		i++
	}
	first := string(runes[start:i])
	scope := ""
	name := first
	if i < len(runes) && runes[i] == ':' && i > start {
		i++
		nstart := i
		for i < len(runes) && isNameChar(runes[i]) {
			i++
		}
		scope = first
		name = string(runes[nstart:i])
	}
	// member access inside interpolation ($obj.Prop) extends the token but we
	// only need the base variable for the literal skeleton.
	return &Variable{Name: name, Scope: scope}, i
}

var numberMultipliers = map[string]float64{"kb": 1 << 10, "mb": 1 << 20, "gb": 1 << 30, "tb": 1 << 40, "pb": 1 << 50}

func numberLit(t Token) *Number {
	n := &Number{span: span{t.Start, t.End}, Text: t.Raw}
	txt := strings.TrimRight(t.Raw, "lLdD")
	mult := 1.0
	lower := strings.ToLower(txt)
	for suf, m := range numberMultipliers {
		if strings.HasSuffix(lower, suf) {
			mult = m
			txt = txt[:len(txt)-2]
			break
		}
	}
	if strings.HasPrefix(strings.ToLower(txt), "0x") {
		if v, err := strconv.ParseInt(txt[2:], 16, 64); err == nil {
			n.Value = float64(v) * mult
			n.Int = true
		}
		return n
	}
	if v, err := strconv.ParseInt(txt, 10, 64); err == nil {
		n.Value = float64(v) * mult
		n.Int = true
		return n
	}
	if v, err := strconv.ParseFloat(txt, 64); err == nil {
		n.Value = v * mult
	}
	return n
}
