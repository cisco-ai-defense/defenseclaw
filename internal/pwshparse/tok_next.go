// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "unicode"

func (t *tokenizer) nextToken() *Token {
	var c1 char
again:
	t.tokenStart = t.curIndex
	c := t.getChar()
	switch {
	case c == ' ' || c == '\t' || c == '\f' || c == '\v' || c == noBreakSpace || c == nextLine:
		t.skipWhiteSpace()
		goto again
	case isSingleQuote(c):
		return t.scanStringLiteral()
	case isDoubleQuote(c):
		return t.scanStringExpandable()
	}
	switch c {
	case '@':
		c1 = t.getChar()
		if c1 == '{' {
			return t.newToken(TkAtCurly)
		}
		if c1 == '(' {
			return t.newToken(TkAtParen)
		}
		if isSingleQuote(c1) {
			return t.scanHereStringLiteral()
		}
		if isDoubleQuote(c1) {
			return t.scanHereStringExpandable()
		}
		t.ungetChar()
		if isVariableStart(c1) {
			return t.scanVariable(true, false)
		}
		t.reportError(t.curIndex-1, "UnrecognizedToken")
		return t.newToken(TkUnknown)
	case '#':
		t.scanLineComment()
		goto again
	case '\n':
		return t.newToken(TkNewLine)
	case '\r':
		t.normalizeCRLF(c)
		return t.newToken(TkNewLine)
	case '`':
		c1 = t.getChar()
		if c1 == '\r' {
			t.normalizeCRLF(c1)
		}
		if c1 == '\n' || c1 == '\r' {
			t.newToken(TkLineContinuation)
			goto again
		}
		if isWhitespace(c1) {
			t.skipWhiteSpace()
			goto again
		}
		if c1 == 0 && t.atEOF() {
			t.reportIncomplete(t.curIndex, "IncompleteString")
			t.ungetChar()
			goto again
		}
		cc, sur := t.backtick(c1)
		return t.scanGenericTokenSur(cc, sur)
	case '=':
		return t.checkOperatorInCommandMode(c, TkEquals)
	case '+':
		c1 = t.peekChar()
		if c1 == '+' {
			t.skipChar()
			return t.checkOperatorInCommandMode2(c, c1, TkPlusPlus)
		}
		if c1 == '=' {
			t.skipChar()
			return t.checkOperatorInCommandMode2(c, c1, TkPlusEquals)
		}
		if t.allowSignedNumbers && (unicode.IsDigit(rune(c1)) || c1 == '.') {
			return t.scanNumber(c)
		}
		return t.checkOperatorInCommandMode(c, TkPlus)
	case '-', emDash, enDash, horizontalBar:
		c1 = t.peekChar()
		if isDash(c1) {
			t.skipChar()
			return t.checkOperatorInCommandMode2(c, c1, TkMinusMinus)
		}
		if c1 == '=' {
			t.skipChar()
			return t.checkOperatorInCommandMode2(c, c1, TkMinusEquals)
		}
		if isLetter(c1) || c1 == '_' || c1 == '?' {
			return t.scanParameter()
		}
		if t.allowSignedNumbers && (unicode.IsDigit(rune(c1)) || c1 == '.') {
			return t.scanNumber(c)
		}
		return t.checkOperatorInCommandMode(c, TkMinus)
	case '*':
		c1 = t.peekChar()
		if c1 == '=' {
			t.skipChar()
			return t.checkOperatorInCommandMode2(c, c1, TkMultiplyEquals)
		}
		if c1 == '>' {
			t.skipChar()
			c1 = t.peekChar()
			if c1 == '>' {
				t.skipChar()
				return t.newFileRedirectionToken(0, true, false)
			}
			if c1 == '&' {
				t.skipChar()
				c1 = t.peekChar()
				if c1 == '1' {
					t.skipChar()
					return t.newMergingRedirectionToken(0, 1)
				}
				t.ungetChar()
			}
			return t.newFileRedirectionToken(0, false, false)
		}
		return t.checkOperatorInCommandMode(c, TkMultiply)
	case '/':
		c1 = t.peekChar()
		if c1 == '=' {
			t.skipChar()
			return t.checkOperatorInCommandMode2(c, c1, TkDivideEquals)
		}
		return t.checkOperatorInCommandMode(c, TkDivide)
	case '%':
		c1 = t.peekChar()
		if c1 == '=' {
			t.skipChar()
			return t.checkOperatorInCommandMode2(c, c1, TkRemainderEquals)
		}
		return t.checkOperatorInCommandMode(c, TkRem)
	case '$':
		if t.peekChar() == '(' {
			t.skipChar()
			return t.newToken(TkDollarParen)
		}
		return t.scanVariable(false, false)
	case '<':
		if t.peekChar() == '#' {
			t.skipChar()
			t.scanBlockComment()
			goto again
		}
		return t.newInputRedirectionToken()
	case '>':
		if t.peekChar() == '>' {
			t.skipChar()
			return t.newFileRedirectionToken(1, true, false)
		}
		return t.newFileRedirectionToken(1, false, false)
	case '(':
		return t.newToken(TkLParen)
	case ')':
		return t.newToken(TkRParen)
	case '[':
		if t.inCommandMode() && !forceStartNewToken(t.peekChar()) {
			return t.scanGenericToken('[')
		}
		return t.newToken(TkLBracket)
	case ']':
		return t.newToken(TkRBracket)
	case '{':
		return t.newToken(TkLCurly)
	case '}':
		return t.newToken(TkRCurly)
	case '.':
		return t.scanDot()
	case ';':
		return t.newToken(TkSemi)
	case ',':
		return t.newToken(TkComma)
	case '0', '7', '8', '9':
		return t.scanNumber(c)
	case '1', '2', '3', '4', '5', '6':
		if t.peekChar() == '>' {
			t.skipChar()
			c1 = t.peekChar()
			if c1 == '>' {
				t.skipChar()
				return t.newFileRedirectionToken(int(c-'0'), true, true)
			}
			if c1 == '&' {
				t.skipChar()
				c1 = t.peekChar()
				if c1 == '1' || c1 == '2' {
					t.skipChar()
					return t.newMergingRedirectionToken(int(c-'0'), int(c1-'0'))
				}
				t.ungetChar()
			}
			return t.newFileRedirectionToken(int(c-'0'), false, true)
		}
		return t.scanNumber(c)
	case '&':
		if t.peekChar() == '&' {
			t.skipChar()
			return t.newToken(TkAndAnd)
		}
		return t.newToken(TkAmpersand)
	case '|':
		if t.peekChar() == '|' {
			t.skipChar()
			return t.newToken(TkOrOr)
		}
		return t.newToken(TkPipe)
	case '!':
		c1 = t.peekChar()
		if (t.inCommandMode() && !forceStartNewToken(c1)) || (t.inExpressionMode() && isIdentifierStart(c1)) {
			return t.scanGenericToken(c)
		}
		if t.inExpressionMode() && (unicode.IsDigit(rune(c1)) || c1 == '.') {
			_, _, _, _, _, ok := t.scanNumberHelper(c)
			t.curIndex = t.tokenStart
			c = t.getChar()
			if !ok {
				return t.scanGenericToken(c)
			}
		}
		return t.newToken(TkExclaim)
	case ':':
		if t.peekChar() == ':' {
			t.skipChar()
			if t.inCommandMode() && !t.wantSimpleName && !forceStartNewToken(t.peekChar()) {
				return t.scanGenericTokenSB(newSbuf(':', ':'))
			}
			return t.newToken(TkColonColon)
		}
		if t.inCommandMode() {
			return t.scanLabel()
		}
		return t.newToken(TkColon)
	case '?':
		if t.inExpressionMode() {
			c1 = t.peekChar()
			if c1 == '?' {
				t.skipChar()
				c1 = t.peekChar()
				if c1 == '=' {
					t.skipChar()
					return t.newToken(TkQuestionQuestionEquals)
				}
				return t.newToken(TkQuestionQuestion)
			}
			return t.newToken(TkQuestionMark)
		}
		return t.scanGenericToken(c)
	case 0:
		if t.atEOF() {
			e := t.newExtent(t.tokenStart+1, t.tokenStart+1)
			tok := &Token{Kind: TkEndOfInput, Flags: staticTokenFlags[TkEndOfInput], Start: e.Start, End: e.End}
			return t.saveToken(tok)
		}
		return t.scanGenericToken(c)
	}
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
		return t.scanIdentifier(c)
	}
	if isWhitespace(c) {
		t.skipWhiteSpace()
		goto again
	}
	if isLetter(c) {
		return t.scanIdentifier(c)
	}
	return t.scanGenericToken(c)
}
