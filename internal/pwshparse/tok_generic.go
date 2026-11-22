// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

func (t *tokenizer) scanParameter() *Token {
	sb := make(sbuf, 0, 48)
	scanning := true
	sawColonAtEnd := false
	for scanning {
		c := t.getChar()
		if isWhitespace(c) {
			t.ungetChar()
			break
		}
		switch {
		case c == '{' || c == '}' || c == '(' || c == ')' || c == ';' || c == ',' || c == '|' || c == '&' ||
			c == '.' || c == '[' || c == '\r' || c == '\n' || c == 0:
			t.ungetChar()
			scanning = false
		case c == ':':
			scanning = false
			sawColonAtEnd = true
			if !t.inCommandMode() {
				t.ungetChar()
			}
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			sb.add(c)
		case isSingleQuote(c) || isDoubleQuote(c):
			if t.inCommandMode() {
				t.ungetChar()
				sb = append(newSbuf(t.script[t.tokenStart]), sb...)
				return t.scanGenericTokenSB(sb)
			}
			t.ungetChar()
			scanning = false
		default:
			if t.inCommandMode() {
				sb.add(c)
			} else {
				t.ungetChar()
				scanning = false
			}
		}
	}
	str := sb.String()
	if t.inExpressionMode() {
		if k, ok := lookupOperator(str); ok {
			return t.newToken(k)
		}
	}
	if len(str) == 0 {
		return t.newToken(TkMinus)
	}
	return t.newParameterToken(str, sawColonAtEnd)
}

func (t *tokenizer) checkOperatorInCommandMode(c char, kind TokenKind) *Token {
	if t.inCommandMode() && !forceStartNewToken(t.peekChar()) {
		return t.scanGenericToken(c)
	}
	return t.newToken(kind)
}

func (t *tokenizer) checkOperatorInCommandMode2(c1, c2 char, kind TokenKind) *Token {
	if t.inCommandMode() && !forceStartNewToken(t.peekChar()) {
		return t.scanGenericTokenSB(newSbuf(c1, c2))
	}
	return t.newToken(kind)
}

func (t *tokenizer) scanGenericToken(first char) *Token {
	return t.scanGenericTokenSB(newSbuf(first))
}

func (t *tokenizer) scanGenericTokenSur(first, sur char) *Token {
	sb := newSbuf(first)
	if sur != invalidChar {
		sb.add(sur)
	}
	return t.scanGenericTokenSB(sb)
}

func (t *tokenizer) scanGenericTokenSB(sb sbuf) *Token {
	var nested []*Token
	// formatSb equals sb until a brace is doubled or an expandable part is read; it is built on first need.
	var formatSb sbuf
	same := true
	diverge := func() {
		if same {
			formatSb = append(make(sbuf, 0, len(sb)+16), sb...)
			same = false
		}
	}
	c := t.getChar()
	for ; !forceStartNewToken(c); c = t.getChar() {
		if c == '`' {
			c1 := t.peekChar()
			if c1 != 0 {
				t.skipChar()
				var sur char
				c, sur = t.backtick(c1)
				if sur != invalidChar {
					sb.add(c)
					sb.add(sur)
					if !same {
						formatSb.add(c)
						formatSb.add(sur)
					}
					continue
				}
			}
		} else if isSingleQuote(c) {
			l := sb.length()
			t.scanStringLiteralInto(&sb)
			if !same {
				for i := l; i < sb.length(); i++ {
					formatSb.add(sb[i])
				}
			}
			continue
		} else if isDoubleQuote(c) {
			diverge()
			t.scanStringExpandableInto(&sb, &formatSb, &nested)
			continue
		} else if c == '$' {
			diverge()
			if t.scanDollarInStringExpandable(&sb, &formatSb, false, &nested) {
				continue
			}
		}
		sb.add(c)
		if c == '{' || c == '}' {
			diverge()
		}
		if !same {
			formatSb.add(c)
			if c == '{' || c == '}' {
				formatSb.add(c)
			}
		}
	}
	t.ungetChar()
	str := sb.String()
	if len(nested) > 0 {
		return t.newGenericExpandableToken(str, formatSb.String(), nested)
	}
	return t.newGenericToken(str)
}
