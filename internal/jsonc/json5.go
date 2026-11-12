// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package jsonc

import (
	"bytes"
	"math/big"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// JSON5ToJSON rewrites a JSON5 document into strict JSON for encoding/json.
// OpenClaw reads openclaw.json as JSON5, so a reader that only takes strict
// JSON misreads a file the product itself accepts, and one unusual value
// anywhere in the file must not hide the value the reader wants.
//
// Rewritten: comments and trailing commas go; unquoted object keys and
// single-quoted strings are quoted; string escapes JSON lacks (\x41, \0, \v,
// a backslash before an ordinary character, a backslash-newline continuation)
// become JSON escapes; raw control characters in a string are escaped;
// numbers become JSON numbers (hexadecimal, a leading +, a leading or
// trailing decimal point); Infinity and NaN, which JSON cannot represent,
// become null; a byte order mark and the other JSON5 whitespace characters
// are dropped or become spaces.
//
// It is a normalizer, not a validator: input that is not JSON5 stays invalid
// (an unterminated string or container, a bare '-', a malformed hex number),
// and the caller's strict parse then fails, which the caller must treat as
// "could not read".
func JSON5ToJSON(data []byte) []byte {
	out, finished := rewriteJSON5(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), nil)
	if !finished {
		return out
	}
	return stripJSONCTrailingCommas(out)
}

// rewriteMark records that out[outAt:] was produced from data[srcAt:]. When
// marks is not nil, rewriteJSON5 appends one before every token it rewrites,
// so a position in the rewritten text maps back to the original text.
type rewriteMark struct{ outAt, srcAt int }

// rewriteJSON5 is the rewrite of JSON5ToJSON before the trailing commas go.
// It reports false when the text ended inside a block comment and the rest
// was copied as it is.
func rewriteJSON5(data []byte, marks *[]rewriteMark) ([]byte, bool) {
	out := make([]byte, 0, len(data)+16)
	for i := 0; i < len(data); {
		if marks != nil {
			*marks = append(*marks, rewriteMark{len(out), i})
		}
		b := data[i]
		switch {
		case b == '"' || b == '\'':
			var next int
			out, next = appendJSON5String(out, data, i)
			i = next
		case b == '/' && i+1 < len(data) && (data[i+1] == '/' || data[i+1] == '*'):
			next, closed := skipJSON5Comment(data, i)
			if !closed {
				// An unterminated block comment is not JSON5. Keep the rest
				// as it is so the strict parse fails instead of reading the
				// text before it as the whole document.
				return append(out, data[i:]...), false
			}
			i = next
			out = append(out, ' ')
		case b == '+' || b == '-' || b == '.' || b >= '0' && b <= '9':
			var next int
			if out, next = appendJSON5Number(out, data, i); next == i {
				out = append(out, b)
				next = i + 1
			}
			i = next
		case b == '\v' || b == '\f':
			out = append(out, ' ')
			i++
		case b < utf8.RuneSelf && b != '\\' && !isJSON5IdentStart(b):
			out = append(out, b)
			i++
		default:
			if end := scanJSON5Identifier(data, i); end > i {
				out = appendJSON5Word(out, data, i, end)
				i = end
				continue
			}
			r, size := utf8.DecodeRune(data[i:])
			if isJSON5Space(r) {
				out = append(out, ' ')
			} else {
				out = append(out, data[i:i+size]...)
			}
			i += size
		}
	}
	return out, true
}

// skipJSON5Comment returns the index after the comment that starts at
// data[start] and whether the comment is well formed. A line comment ends
// before any JSON5 line terminator (LF, CR, U+2028, U+2029); a block comment
// without its closing "*/" is not well formed.
func skipJSON5Comment(data []byte, start int) (int, bool) {
	i := start + 2
	if data[start+1] == '*' {
		for i+1 < len(data) {
			if data[i] == '*' && data[i+1] == '/' {
				return i + 2, true
			}
			i++
		}
		return len(data), false
	}
	for i < len(data) && data[i] != '\n' && data[i] != '\r' && !isJSON5LineSeparator(data[i:]) {
		i++
	}
	return i, true
}

// isJSON5LineSeparator reports whether data starts with U+2028 or U+2029.
func isJSON5LineSeparator(data []byte) bool {
	return len(data) >= 3 && data[0] == 0xe2 && data[1] == 0x80 && (data[2] == 0xa8 || data[2] == 0xa9)
}

// scanJSON5Identifier returns the end of the ECMAScript IdentifierName that
// starts at data[start], or start when none does. A Unicode escape (backslash,
// u, four hex digits) is part of an identifier when it names an identifier
// character.
func scanJSON5Identifier(data []byte, start int) int {
	i := start
	for i < len(data) {
		var r rune
		size := 0
		if data[i] == '\\' {
			if i+6 > len(data) || data[i+1] != 'u' || !isJSON5Hex(data[i+2]) || !isJSON5Hex(data[i+3]) || !isJSON5Hex(data[i+4]) || !isJSON5Hex(data[i+5]) {
				break
			}
			v, _ := strconv.ParseUint(string(data[i+2:i+6]), 16, 32)
			r, size = rune(v), 6
		} else {
			r, size = utf8.DecodeRune(data[i:])
		}
		if !isJSON5IdentRune(r, i == start) {
			break
		}
		i += size
	}
	return i
}

// appendJSON5Word appends the identifier or word data[start:end]: a key is
// quoted, Infinity and NaN become null, true, false and null stay words.
func appendJSON5Word(out, data []byte, start, end int) []byte {
	k := end
	for k < len(data) {
		if data[k] == '/' && k+1 < len(data) && (data[k+1] == '/' || data[k+1] == '*') {
			next, closed := skipJSON5Comment(data, k)
			if !closed {
				break
			}
			k = next
			continue
		}
		if data[k] == ' ' || data[k] == '\t' || data[k] == '\n' || data[k] == '\r' || data[k] == '\v' || data[k] == '\f' {
			k++
			continue
		}
		if r, size := utf8.DecodeRune(data[k:]); r >= utf8.RuneSelf && isJSON5Space(r) {
			k += size
			continue
		}
		break
	}
	word := data[start:end]
	switch {
	case k < len(data) && data[k] == ':':
		out = append(out, '"')
		out = append(out, word...)
		return append(out, '"')
	case string(word) == "Infinity" || string(word) == "NaN":
		return append(out, "null"...)
	}
	return append(out, word...)
}

func isJSON5IdentStart(b byte) bool {
	return b == '_' || b == '$' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= utf8.RuneSelf
}

func isJSON5IdentRune(r rune, first bool) bool {
	switch {
	case r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
		return true
	case r < utf8.RuneSelf:
		return !first && r >= '0' && r <= '9'
	case unicode.IsLetter(r) || unicode.Is(unicode.Nl, r):
		return true
	}
	return !first && (unicode.IsOneOf([]*unicode.RangeTable{unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc}, r) ||
		r == '\u200c' || r == '\u200d')
}

// isJSON5Space reports a non-ASCII JSON5 whitespace or line terminator.
func isJSON5Space(r rune) bool {
	return r == '\ufeff' || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Zs, r)
}

func isJSON5Digit(b byte) bool { return b >= '0' && b <= '9' }

func isJSON5Hex(b byte) bool {
	return isJSON5Digit(b) || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

// appendJSON5Number appends the JSON5 number that starts at data[start] as a
// JSON number and returns the index after it. It returns start when no
// number starts there.
func appendJSON5Number(out, data []byte, start int) ([]byte, int) {
	i := start
	sign := ""
	if data[i] == '+' || data[i] == '-' {
		if data[i] == '-' {
			sign = "-"
		}
		i++
	}
	rest := data[i:]
	for _, word := range []string{"Infinity", "NaN"} {
		if bytes.HasPrefix(rest, []byte(word)) {
			end := i + len(word)
			if r, _ := utf8.DecodeRune(data[end:]); end < len(data) && isJSON5IdentRune(r, false) {
				return out, start
			}
			return append(out, "null"...), end
		}
	}
	if len(rest) > 2 && rest[0] == '0' && (rest[1] == 'x' || rest[1] == 'X') {
		end := i + 2
		for end < len(data) && isJSON5Hex(data[end]) {
			end++
		}
		if end == i+2 {
			return out, start
		}
		value, _ := new(big.Int).SetString(string(data[i+2:end]), 16)
		return append(append(out, sign...), value.String()...), end
	}
	end := i
	for end < len(data) && isJSON5Digit(data[end]) {
		end++
	}
	whole := data[i:end]
	frac, dot := []byte(nil), false
	if end < len(data) && data[end] == '.' {
		dot = true
		fracStart := end + 1
		end = fracStart
		for end < len(data) && isJSON5Digit(data[end]) {
			end++
		}
		frac = data[fracStart:end]
	}
	if len(whole) == 0 && len(frac) == 0 {
		return out, start
	}
	out = append(out, sign...)
	if len(whole) == 0 {
		whole = []byte("0")
	}
	out = append(out, whole...)
	if dot {
		if len(frac) == 0 {
			frac = []byte("0")
		}
		out = append(append(out, '.'), frac...)
	}
	if end < len(data) && (data[end] == 'e' || data[end] == 'E') {
		exp := end + 1
		if exp < len(data) && (data[exp] == '+' || data[exp] == '-') {
			exp++
		}
		digits := exp
		for digits < len(data) && isJSON5Digit(data[digits]) {
			digits++
		}
		if digits > exp {
			out = append(out, data[end:digits]...)
			end = digits
		}
	}
	return out, end
}

// appendJSON5String copies the string that starts at data[start] as a
// double-quoted JSON string and returns the index after its closing quote.
func appendJSON5String(out, data []byte, start int) ([]byte, int) {
	quote := data[start]
	out = append(out, '"')
	i := start + 1
	for i < len(data) {
		b := data[i]
		switch {
		case b == quote:
			return append(out, '"'), i + 1
		case b == '\\' && i+1 < len(data):
			out, i = appendJSON5Escape(out, data, i)
		case b == '"':
			out = append(out, '\\', '"')
			i++
		case b < 0x20 && b != '\n' && b != '\r':
			out = appendJSONUnicodeEscape(out, rune(b))
			i++
		default:
			out = append(out, b)
			i++
		}
	}
	// Unterminated: hand back what was read; the strict parse rejects it.
	return out, i
}

// appendJSON5Escape rewrites the escape sequence at data[at] (a backslash)
// and returns the index after it.
func appendJSON5Escape(out, data []byte, at int) ([]byte, int) {
	next := data[at+1]
	i := at + 2
	switch next {
	case '\n':
		return out, i
	case '\r':
		if i < len(data) && data[i] == '\n' {
			i++
		}
		return out, i
	case 'b', 'f', 'n', 'r', 't', 'u', '\\', '/', '"':
		return append(out, '\\', next), i
	case '\'':
		return append(out, '\''), i
	case 'v':
		return appendJSONUnicodeEscape(out, '\v'), i
	case 'x':
		if i+1 < len(data) && isJSON5Hex(data[i]) && isJSON5Hex(data[i+1]) {
			return append(append(out, `\u00`...), data[i:i+2]...), i + 2
		}
	case '0':
		if i >= len(data) || !isJSON5Digit(data[i]) {
			return appendJSONUnicodeEscape(out, 0), i
		}
	}
	if next >= utf8.RuneSelf {
		// A backslash before a multi-byte character stands for the character;
		// U+2028 and U+2029 are line continuations.
		if r, size := utf8.DecodeRune(data[at+1:]); r == '\u2028' || r == '\u2029' {
			return out, at + 1 + size
		}
		return out, at + 1
	}
	if next == 'x' || next >= '0' && next <= '9' || next < 0x20 {
		// Not valid JSON5: keep the backslash so the strict parse fails.
		return append(out, '\\', next), i
	}
	return append(out, next), i
}

func appendJSONUnicodeEscape(out []byte, r rune) []byte {
	const hexDigits = "0123456789abcdef"
	return append(out, '\\', 'u', '0', '0', hexDigits[r>>4&0xf], hexDigits[r&0xf])
}
