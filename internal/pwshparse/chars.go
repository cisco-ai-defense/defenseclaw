// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "unicode"

// char is a UTF-16 code unit, the unit the reference parser indexes by.
type char = uint16

const (
	noBreakSpace      char = 0x00a0
	nextLine          char = 0x0085
	enDash            char = 0x2013
	emDash            char = 0x2014
	horizontalBar     char = 0x2015
	quoteSingleLeft   char = 0x2018
	quoteSingleRight  char = 0x2019
	quoteSingleBase   char = 0x201a
	quoteReversed     char = 0x201b
	quoteDoubleLeft   char = 0x201c
	quoteDoubleRight  char = 0x201d
	quoteLowDoubleLft char = 0x201e
)

func isLetter(c char) bool { return unicode.IsLetter(rune(c)) }
func isLetterOrDigit(c char) bool {
	return unicode.IsLetter(rune(c)) || unicode.Is(unicode.Nd, rune(c))
}

func isWhitespace(c char) bool {
	if c < 128 {
		return charTraitsTable[c]&ctWhitespace != 0
	}
	if c <= 256 {
		return c == noBreakSpace || c == nextLine
	}
	return unicode.Is(unicode.Z, rune(c))
}

func isDash(c char) bool {
	return c == '-' || c == enDash || c == emDash || c == horizontalBar
}

func isSingleQuote(c char) bool {
	return c == '\'' || c == quoteSingleLeft || c == quoteSingleRight || c == quoteSingleBase || c == quoteReversed
}

func isDoubleQuote(c char) bool {
	return c == '"' || c == quoteDoubleLeft || c == quoteDoubleRight || c == quoteLowDoubleLft
}

func isVariableStart(c char) bool {
	if c < 128 {
		return charTraitsTable[c]&ctVarNameFirst != 0
	}
	return isLetterOrDigit(c)
}

func isIdentifierStart(c char) bool {
	if c < 128 {
		return charTraitsTable[c]&ctIdentifierStart != 0
	}
	return isLetter(c)
}

func isIdentifierFollow(c char) bool {
	if c < 128 {
		return charTraitsTable[c]&(ctIdentifierStart|ctDigit) != 0
	}
	return isLetterOrDigit(c)
}

func isHexDigit(c char) bool {
	return c < 128 && charTraitsTable[c]&ctHexDigit != 0
}

func isDecimalDigit(c char) bool { return c >= '0' && c <= '9' }
func isBinaryDigit(c char) bool  { return c == '0' || c == '1' }

func isTypeSuffix(c char) bool {
	return c < 128 && charTraitsTable[c]&ctTypeSuffix != 0
}

func isMultiplierStart(c char) bool {
	return c < 128 && charTraitsTable[c]&ctMultiplierStart != 0
}

func forceStartNewToken(c char) bool {
	if c < 128 {
		return charTraitsTable[c]&ctForceStartNewToken != 0
	}
	return isWhitespace(c)
}

func forceStartNewTokenAfterNumber(c char, endOnTernary bool) bool {
	if c < 128 {
		if charTraitsTable[c]&ctForceStartNewTokenAfterNumber != 0 {
			return true
		}
		return endOnTernary && (c == '?' || c == ':')
	}
	return isDash(c)
}

func forceStartNewTokenInAssemblyNameSpec(c char) bool {
	if c < 128 {
		return charTraitsTable[c]&ctForceStartNewAssemblyNameSpecToken != 0
	}
	return isWhitespace(c)
}
