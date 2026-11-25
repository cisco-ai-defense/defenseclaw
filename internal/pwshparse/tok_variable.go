// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "strings"

func newVariablePath(userPath string) *VariablePath { return &VariablePath{UserPath: userPath} }

var variableScopes = map[string]bool{"global": true, "local": true, "private": true, "script": true, "using": true, "variable": true}

// UnqualifiedPath is the name after a scope or drive prefix.
func (v *VariablePath) UnqualifiedPath() string {
	i := strings.IndexByte(v.UserPath, ':')
	if i < 0 {
		return v.UserPath
	}
	return v.UserPath[i+1:]
}

// IsDriveQualified reports whether the prefix names a drive rather than a scope.
func (v *VariablePath) IsDriveQualified() bool {
	i := strings.IndexByte(v.UserPath, ':')
	if i <= 0 {
		return false
	}
	return !variableScopes[strings.ToLower(v.UserPath[:i])]
}

func isASCIIAlnum(c char) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func (t *tokenizer) scanVariable(splatted, inStringExpandable bool) *Token {
	errorStart := t.curIndex
	sb := make(sbuf, 0, 48)
	c := t.getChar()
	if c == '{' {
	braced:
		for {
			c = t.getChar()
			switch c {
			case '}':
				break braced
			case '`':
				c1 := t.getChar()
				if c1 == 0 && t.atEOF() {
					t.ungetChar()
					break braced
				}
				var sur char
				c, sur = t.backtick(c1)
				if sur != invalidChar {
					sb.add(c)
					sb.add(sur)
					continue
				}
			case '"', quoteDoubleLeft, quoteDoubleRight, quoteLowDoubleLft:
				if inStringExpandable {
					c1 := t.getChar()
					if c1 == 0 && t.atEOF() {
						t.ungetChar()
						break braced
					}
					if isDoubleQuote(c1) {
						c = c1
					} else {
						t.ungetChar()
					}
				}
			case '{':
				t.reportError(t.curIndex, "OpenBraceNeedsToBeBackTickedInVariableName")
			case 0:
				if t.atEOF() {
					t.ungetChar()
					break braced
				}
			}
			sb.add(c)
		}
		name := sb.String()
		if c != '}' {
			t.reportIncomplete(errorStart, "IncompleteDollarVariableReference")
		}
		if len(name) == 0 {
			if c == '}' {
				t.reportError(t.curIndex-1, "EmptyVariableReference")
			}
			name = ":Error:"
		}
		if t.inCommandMode() {
			c1 := t.peekChar()
			if !forceStartNewToken(c1) && c1 != '.' && c1 != '[' {
				t.curIndex = t.tokenStart
				return t.scanGenericTokenSB(sbuf(nil))
			}
		}
		path := newVariablePath(name)
		if path.UnqualifiedPath() == "" {
			t.reportErrorExtent(t.newExtent(t.tokenStart, t.curIndex), "InvalidBracedVariableReference")
		}
		return t.newVariableToken(path, false)
	}
	if !isVariableStart(c) {
		t.ungetChar()
		sb.add('$')
		return t.scanGenericTokenSB(sb)
	}
	sb.add(c)
	if c != '$' && c != '?' && c != '^' {
		scanning := true
		for scanning {
			c = t.getChar()
			switch {
			case isASCIIAlnum(c) || c == '_' || c == '?':
				sb.add(c)
			case c == ':':
				if t.peekChar() == ':' {
					t.ungetChar()
					scanning = false
				} else {
					sb.add(c)
				}
			case c == 0 || c == '\t' || c == '\r' || c == '\n' || c == ' ' || c == '&' || c == '(' || c == ')' ||
				c == ',' || c == ';' || c == '{' || c == '}' || c == '|' || c == '.' || c == '[' || c == '=':
				t.ungetChar()
				scanning = false
			default:
				if isLetterOrDigit(c) {
					sb.add(c)
				} else if t.inCommandMode() && !forceStartNewToken(c) {
					t.curIndex = t.tokenStart
					return t.scanGenericTokenSB(sbuf(nil))
				} else {
					t.ungetChar()
					scanning = false
				}
			}
		}
	} else if t.inCommandMode() && !forceStartNewToken(t.peekChar()) {
		t.curIndex = t.tokenStart
		return t.scanGenericTokenSB(sbuf(nil))
	}
	path := newVariablePath(sb.String())
	if path.UnqualifiedPath() == "" {
		id := "InvalidVariableReference"
		if path.IsDriveQualified() {
			id = "InvalidVariableReferenceWithDrive"
		}
		t.reportErrorExtent(t.newExtent(t.tokenStart, t.curIndex), id)
	}
	return t.newVariableToken(path, splatted)
}
