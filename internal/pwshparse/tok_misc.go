// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

func (t *tokenizer) getMemberAccessOperator(allowLBracket bool) *Token {
	c := t.peekChar()
	for c == '<' {
		t.tokenStart = t.curIndex
		t.skipChar()
		if t.peekChar() == '#' {
			t.skipChar()
			t.scanBlockComment()
			c = t.peekChar()
		} else {
			t.ungetChar()
			return nil
		}
	}
	if c == '.' {
		t.tokenStart = t.curIndex
		t.skipChar()
		c = t.peekChar()
		if c != '.' {
			if t.inCommandMode() && (isWhitespace(c) || c == 0 || c == '\r' || c == '\n') {
				t.ungetChar()
				return nil
			}
			return t.newToken(TkDot)
		}
		t.ungetChar()
		return nil
	}
	if c == ':' {
		t.tokenStart = t.curIndex
		t.skipChar()
		c = t.peekChar()
		if c == ':' {
			t.skipChar()
			c = t.peekChar()
			if t.inCommandMode() && (isWhitespace(c) || c == 0 || c == '\r' || c == '\n') {
				t.ungetChar()
				t.ungetChar()
				return nil
			}
			return t.newToken(TkColonColon)
		}
		t.ungetChar()
		return nil
	}
	if c == '[' && allowLBracket {
		t.tokenStart = t.curIndex
		t.skipChar()
		return t.newToken(TkLBracket)
	}
	if c == '?' {
		t.tokenStart = t.curIndex
		t.skipChar()
		c = t.peekChar()
		if c == '.' {
			t.skipChar()
			return t.newToken(TkQuestionDot)
		} else if c == '[' && allowLBracket {
			t.skipChar()
			return t.newToken(TkQuestionLBracket)
		}
		t.ungetChar()
		return nil
	}
	return nil
}

func (t *tokenizer) getInvokeMemberOpenParen() *Token {
	c := t.peekChar()
	if c == '(' {
		t.tokenStart = t.curIndex
		t.skipChar()
		return t.newToken(TkLParen)
	}
	if c == '{' {
		t.tokenStart = t.curIndex
		t.skipChar()
		return t.newToken(TkLCurly)
	}
	return nil
}

func (t *tokenizer) getLBracket() *Token {
	resyncPoint := t.curIndex
	resyncIfMemberAccess := false
again:
	t.tokenStart = t.curIndex
	c := t.getChar()
	switch c {
	case ' ', '\t', '\f', '\v', noBreakSpace, nextLine:
		resyncIfMemberAccess = true
		t.skipWhiteSpace()
		goto again
	case '#':
		resyncIfMemberAccess = true
		t.scanLineComment()
		goto again
	case '<':
		if t.peekChar() == '#' {
			resyncIfMemberAccess = false
			t.skipChar()
			t.scanBlockComment()
			goto again
		}
		t.ungetChar()
	case '[':
		return t.newToken(TkLBracket)
	case '.', ':':
		if resyncIfMemberAccess {
			t.resync(resyncPoint)
		} else {
			t.ungetChar()
		}
	default:
		if isWhitespace(c) {
			resyncIfMemberAccess = true
			t.skipWhiteSpace()
			goto again
		}
		t.ungetChar()
	}
	return nil
}

func (t *tokenizer) scanDot() *Token {
	c := t.peekChar()
	if c == '.' {
		t.skipChar()
		c = t.peekChar()
		if t.inCommandMode() && !forceStartNewToken(c) {
			t.ungetChar()
			return t.scanGenericToken('.')
		}
		return t.newToken(TkDotDot)
	}
	if isDecimalDigit(c) {
		return t.scanNumber('.')
	}
	if t.inCommandMode() && !forceStartNewToken(c) && c != '$' && c != '"' && c != '\'' {
		return t.scanGenericToken('.')
	}
	return t.newToken(TkDot)
}

func (t *tokenizer) scanIdentifier(first char) *Token {
	var c char
	for {
		c = t.getChar()
		if !isIdentifierFollow(c) {
			t.ungetChar()
			break
		}
	}
	if t.inTypeNameMode() {
		return t.scanTypeName()
	}
	if !t.wantSimpleName && t.inCommandMode() && !forceStartNewToken(c) {
		// a generic token that starts like an identifier: the identifier text so far is the buffer
		sb := make(sbuf, 0, 48)
		sb.addAll(t.script[t.tokenStart:t.curIndex])
		return t.scanGenericTokenSB(sb)
	}
	if !t.wantSimpleName && (t.inCommandMode() || t.inSignatureMode()) {
		if k, ok := lookupKeywordChars(t.script[t.tokenStart:t.curIndex]); ok {
			if k != TkInlineScript {
				return t.newToken(k)
			}
		}
	}
	return t.newToken(TkIdentifier)
}

func (t *tokenizer) scanTypeName() *Token {
	for {
		c := t.getChar()
		switch c {
		case '.', '`', '_', '+', '#', '\\':
			continue
		default:
			if isLetterOrDigit(c) {
				continue
			}
		}
		t.ungetChar()
		break
	}
	result := t.newToken(TkIdentifier)
	result.Flags |= tfTypeName
	return result
}

func (t *tokenizer) scanAssemblyNameSpecToken(sb *sbuf) {
	t.skipWhiteSpace()
	t.tokenStart = t.curIndex
	for {
		c := t.getChar()
		if forceStartNewTokenInAssemblyNameSpec(c) {
			t.ungetChar()
			break
		}
		sb.add(c)
	}
	tok := t.newToken(TkIdentifier)
	tok.Flags |= tfTypeName
	t.skipWhiteSpace()
}

func (t *tokenizer) getAssemblyNameSpec() string {
	sb := make(sbuf, 0, 48)
	t.scanAssemblyNameSpecToken(&sb)
	for t.peekChar() == ',' {
		t.tokenStart = t.curIndex
		sb.addStr(", ")
		t.skipChar()
		t.newToken(TkComma)
		t.scanAssemblyNameSpecToken(&sb)
		if t.peekChar() == '=' {
			t.tokenStart = t.curIndex
			sb.add('=')
			t.skipChar()
			t.newToken(TkEquals)
			t.scanAssemblyNameSpecToken(&sb)
		}
	}
	return sb.String()
}

func (t *tokenizer) scanLabel() *Token {
	sb := make(sbuf, 0, 48)
	c := t.getChar()
	if !isIdentifierStart(c) {
		sb.add(':')
		if c == 0 {
			t.ungetChar()
			return t.newGenericToken(sb.String())
		}
		t.ungetChar()
		return t.scanGenericTokenSB(sb)
	}
	for isIdentifierFollow(c) {
		sb.add(c)
		c = t.getChar()
	}
	if t.inCommandMode() && !forceStartNewToken(c) {
		sb = append(newSbuf(':'), sb...)
		sb.add(c)
		return t.scanGenericTokenSB(sb)
	}
	t.ungetChar()
	return t.newLabelToken(sb.String())
}
