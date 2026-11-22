// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

// sbuf is a StringBuilder over UTF-16 code units.
type sbuf []char

// newSbuf returns a buffer holding cs with room for a typical token.
func newSbuf(cs ...char) sbuf { return append(make(sbuf, 0, 48), cs...) }

func (s *sbuf) add(c char)      { *s = append(*s, c) }
func (s *sbuf) addAll(c []char) { *s = append(*s, c...) }
func (s *sbuf) addStr(x string) { *s = append(*s, toUTF16(x)...) }
func (s sbuf) String() string   { return fromUTF16(s) }
func (s sbuf) length() int      { return len(s) }
func (s *sbuf) truncate(n int)  { *s = (*s)[:n] }

func (t *tokenizer) getVerbatimCommandArgument() *Token {
	t.skipWhiteSpace()
	t.tokenStart = t.curIndex
	inQuotes := false
	for {
		c := t.getChar()
		if c == '\r' || c == '\n' || (c == 0 && t.atEOF()) {
			t.ungetChar()
			break
		}
		if isDoubleQuote(c) {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && (c == '|' || (c == '&' && !t.atEOF() && t.peekChar() == '&')) {
			t.ungetChar()
			break
		}
	}
	e := t.currentExtent()
	return t.newStringLiteralToken(t.p.textOf(e), TkGeneric, 0)
}

func (t *tokenizer) scanStringLiteralInto(sb *sbuf) TokenFlags {
	errorIndex := t.curIndex - 1
	flags := TokenFlags(0)
	c := t.getChar()
	for c != 0 || !t.atEOF() {
		if isSingleQuote(c) {
			if !isSingleQuote(t.peekChar()) {
				break
			}
			c = t.getChar()
		}
		sb.add(c)
		c = t.getChar()
	}
	if c == 0 {
		t.ungetChar()
		t.reportIncomplete(errorIndex, "TerminatorExpectedAtEndOfString")
		flags = tfTokenInError
	}
	return flags
}

func (t *tokenizer) scanStringLiteral() *Token {
	sb := make(sbuf, 0, 48)
	flags := t.scanStringLiteralInto(&sb)
	return t.newStringLiteralToken(sb.String(), TkStringLiteral, flags)
}

func (t *tokenizer) scanSubExpression(hereString bool) *Token {
	t.tokenStart = t.curIndex - 2
	sb := make(sbuf, 0, 48)
	sb.addStr("$(")
	parenCount := 1
	flags := TokenFlags(0)
	scanning := true
	var skippedOffsets []int
	for scanning {
		c := t.getChar()
		switch c {
		case '(':
			sb.add(c)
			parenCount++
		case ')':
			sb.add(c)
			parenCount--
			if parenCount == 0 {
				scanning = false
			}
		case '`', '"', quoteDoubleLeft, quoteDoubleRight, quoteLowDoubleLft:
			c1 := t.peekChar()
			if !hereString && isDoubleQuote(c1) {
				t.skipChar()
				sb.add(c1)
				skippedOffsets = append(skippedOffsets, t.curIndex-2+t.nestedAdj)
			} else {
				sb.add(c)
			}
		case 0:
			if !t.atEOF() {
				sb.add(c)
				break
			}
			t.ungetChar()
			t.reportIncomplete(t.tokenStart, "IncompleteDollarSubexpressionReference")
			flags = tfTokenInError
			scanning = false
		default:
			sb.add(c)
		}
	}
	var bits *bitSet
	if len(skippedOffsets) > 0 {
		bits = newBitSet(skippedOffsets[len(skippedOffsets)-1] + 1)
		for _, i := range skippedOffsets {
			bits.set(i, true)
		}
	} else {
		bits = t.skipped
	}
	e := t.currentExtent()
	tok := &Token{Kind: TkStringLiteral, Flags: flags | staticTokenFlags[TkStringLiteral], Start: e.Start, End: e.End,
		Value: sb.String(), class: tcString, x: &tokExtra{skipped: bits}}
	return tok
}

func (t *tokenizer) scanStringExpandableInto(sb *sbuf, nested *[]*Token) TokenFlags {
	flags := TokenFlags(0)
	errorIndex := t.curIndex - 1
	c := t.getChar()
	for ; c != 0 || !t.atEOF(); c = t.getChar() {
		if isDoubleQuote(c) {
			if !isDoubleQuote(t.peekChar()) {
				break
			}
			c = t.getChar()
		} else if c == '$' {
			if t.scanDollarInStringExpandable(sb, false, nested) {
				continue
			}
		} else if c == '`' {
			c1 := t.peekChar()
			if c1 != 0 {
				t.skipChar()
				var sur char
				c, sur = t.backtick(c1)
				if sur != invalidChar {
					sb.add(c)
					sb.add(sur)
					continue
				}
			}
		}
		sb.add(c)
	}
	if c == 0 {
		t.ungetChar()
		t.reportIncomplete(errorIndex, "TerminatorExpectedAtEndOfString")
		flags = tfTokenInError
	}
	return flags
}

func (t *tokenizer) scanDollarInStringExpandable(sb *sbuf, hereString bool, nested *[]*Token) bool {
	dollarIndex := t.curIndex - 1
	c1 := t.peekChar()
	saveTokenStart := t.tokenStart
	oldMode := t.mode
	oldList := t.tokenList
	oldWant := t.wantTokens
	var nestedToken *Token
	t.wantTokens = false
	t.tokenList = nil
	t.mode = modeExpression
	if c1 == '(' {
		t.skipChar()
		nestedToken = t.scanSubExpression(hereString)
	} else if isVariableStart(c1) || c1 == '{' {
		t.tokenStart = t.curIndex - 1
		nestedToken = t.scanVariable(false, true)
	}
	t.wantTokens = oldWant
	t.tokenList = oldList
	t.tokenStart = saveTokenStart
	t.mode = oldMode
	if nestedToken != nil {
		sb.addAll(t.script[dollarIndex:t.curIndex])
		*nested = append(*nested, nestedToken)
		return true
	}
	return false
}

func (t *tokenizer) scanStringExpandable() *Token {
	sb := make(sbuf, 0, 48)
	var nested []*Token
	flags := t.scanStringExpandableInto(&sb, &nested)
	return t.newStringExpandableToken(sb.String(), TkStringExpandable, nested, flags)
}

func (t *tokenizer) scanAfterHereStringHeader(header string) bool {
	headerOffset := t.curIndex - 2
	var c char
	for {
		c = t.getChar()
		if !isWhitespace(c) {
			break
		}
	}
	if c == '\r' {
		t.normalizeCRLF(c)
	} else if c != '\n' {
		if c == 0 && t.atEOF() {
			t.ungetChar()
			t.reportIncomplete(headerOffset, "TerminatorExpectedAtEndOfString")
			return false
		}
		t.ungetChar()
		t.reportError(t.curIndex, "UnexpectedCharactersAfterHereStringHeader")
		for {
			c = t.getChar()
			if c == char(header[1]) && t.peekChar() == '@' {
				t.skipChar()
				break
			}
			if c == '\r' || c == '\n' || (c == 0 && t.atEOF()) {
				t.ungetChar()
				break
			}
		}
		return false
	}
	return true
}

func (t *tokenizer) scanPossibleHereStringFooter(test func(char) bool, appendChar func(char), falseFooterOffset *int) bool {
	c := t.getChar()
	if test(c) && t.peekChar() == '@' {
		t.skipChar()
		return true
	}
	for isWhitespace(c) {
		appendChar(c)
		c = t.getChar()
	}
	if c == '\r' || c == '\n' || (c == 0 && t.atEOF()) {
		t.ungetChar()
		return false
	}
	if test(c) && t.peekChar() == '@' {
		appendChar(c)
		if *falseFooterOffset == -1 {
			*falseFooterOffset = t.curIndex - 1
		}
		appendChar(t.getChar())
	} else {
		t.ungetChar()
	}
	return false
}

func (t *tokenizer) scanHereStringLiteral() *Token {
	headerOffset := t.curIndex - 2
	falseFooterOffset := -1
	if !t.scanAfterHereStringHeader("@'") {
		return t.newStringLiteralToken("", TkHereStringLiteral, tfTokenInError)
	}
	flags := TokenFlags(0)
	sb := make(sbuf, 0, 48)
	appendChar := func(c char) { sb.add(c) }
	if !t.scanPossibleHereStringFooter(isSingleQuote, appendChar, &falseFooterOffset) {
		for {
			c := t.getChar()
			if c == '\r' || c == '\n' {
				length := sb.length()
				sb.add(c)
				if c == '\r' && t.peekChar() == '\n' {
					t.skipChar()
					sb.add('\n')
				}
				if t.scanPossibleHereStringFooter(isSingleQuote, appendChar, &falseFooterOffset) {
					sb.truncate(length)
					break
				}
			} else if c != 0 || !t.atEOF() {
				sb.add(c)
			} else {
				t.ungetChar()
				if falseFooterOffset != -1 {
					t.reportIncomplete(falseFooterOffset, "WhitespaceBeforeHereStringFooter")
				} else {
					t.reportIncomplete(headerOffset, "TerminatorExpectedAtEndOfString")
				}
				flags = tfTokenInError
				break
			}
		}
	}
	return t.newStringLiteralToken(sb.String(), TkHereStringLiteral, flags)
}

func (t *tokenizer) scanHereStringExpandable() *Token {
	headerOffset := t.curIndex - 2
	if !t.scanAfterHereStringHeader("@\"") {
		return t.newStringExpandableToken("", TkHereStringExpandable, nil, tfTokenInError)
	}
	flags := TokenFlags(0)
	var nested []*Token
	falseFooterOffset := -1
	sb := make(sbuf, 0, 48)
	appendChar := func(c char) { sb.add(c) }
	if !t.scanPossibleHereStringFooter(isDoubleQuote, appendChar, &falseFooterOffset) {
		for {
			c := t.getChar()
			if c == '\r' || c == '\n' {
				length := sb.length()
				sb.add(c)
				if c == '\r' && t.peekChar() == '\n' {
					t.skipChar()
					sb.add('\n')
				}
				if t.scanPossibleHereStringFooter(isDoubleQuote, appendChar, &falseFooterOffset) {
					sb.truncate(length)
					break
				}
				continue
			}
			if c == '$' {
				if t.scanDollarInStringExpandable(&sb, true, &nested) {
					continue
				}
			} else if c == '`' {
				c1 := t.peekChar()
				if c1 != 0 {
					t.skipChar()
					var sur char
					c, sur = t.backtick(c1)
					if sur != invalidChar {
						sb.add(c)
						sb.add(sur)
						continue
					}
				}
			}
			if c != 0 || !t.atEOF() {
				sb.add(c)
			} else {
				t.ungetChar()
				if falseFooterOffset != -1 {
					t.reportIncomplete(falseFooterOffset, "WhitespaceBeforeHereStringFooter")
				} else {
					t.reportIncomplete(headerOffset, "TerminatorExpectedAtEndOfString")
				}
				flags = tfTokenInError
				break
			}
		}
	}
	return t.newStringExpandableToken(sb.String(), TkHereStringExpandable, nested, flags)
}
