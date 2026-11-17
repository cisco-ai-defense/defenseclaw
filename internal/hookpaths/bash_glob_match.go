// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"unicode"
	"unicode/utf8"
)

// bashGlobMatch matches one path component (no separator) the way bash's
// pathname expansion does with extglob off: * and ?, a backslash escape, and
// a bracket expression with ! or ^ negation, ] as its first member, - first
// or last as a member, ranges, POSIX classes ([:alpha:] and the others),
// equivalence classes ([=c=]) and collating symbols ([.c.]). A [ with no
// closing ] is a literal [. Go's filepath.Match reads several of these
// differently (! is a member, a class is a different set), so a name bash
// selects was read as no match and the word fell to its literal value
// (rel-1-0-10:GAP-0378). The leading-dot rule is the caller's
// (actionGlobSkipsDotName).
//
// exact is false when the answer depends on what this process cannot know
// about the user's shell: the locale (a name with non-ASCII text that a
// multibyte and a single-byte reading match differently, a class or
// equivalence class tested on a non-ASCII character, a range whose ends are
// not both digits or both letters of one case), whether globasciiranges is
// on (a letter range that a collation order of interleaved cases, as bash 4
// uses in a UTF-8 locale, reads differently), and, with fold, an [:upper:]
// or [:lower:] class. The caller treats an inexact answer as a match it
// cannot prove (the walk is not complete): never as a proof either way.
//
// A doubtful bracket makes the answer inexact only when it can change it:
// the match is read again with every doubtful bracket a member and with none
// (a match only grows with a bracket's members), and the answer is exact when
// both readings agree. [3-m] against a name of another length is no match in
// any locale; reading every such test as a doubt made an assignment of a
// list in brackets a possible key name (the owner A/B of s7/hlinkport-r2).
func bashGlobMatch(pattern, name string, fold bool) (matched, exact bool) {
	readings := []bashGlobReading{
		{fold: fold},
		{fold: fold, bytes: true},
		{fold: fold, interleaved: true},
	}
	exact = true
	for i := range readings {
		got := readings[i].match(pattern, name)
		if i == 0 {
			matched = got
		} else if got != matched {
			exact = false
		}
		if readings[i].doubt {
			none, all := readings[i], readings[i]
			none.doubt, none.force = false, -1
			all.doubt, all.force = false, 1
			if none.match(pattern, name) != all.match(pattern, name) {
				exact = false
			}
		}
	}
	return matched, exact
}

// bashGlobReading is one reading of a pattern: multibyte (runes) or single
// byte (C locale) characters, ASCII or interleaved-case letter ranges, and
// case folding (nocaseglob). doubt records a test whose answer no reading
// here settles.
type bashGlobReading struct {
	fold, bytes, interleaved bool
	doubt                    bool
	// force, when set, answers every bracket with a doubtful test: a member
	// (1) or not (-1), after its negation (bashGlobMatch).
	force int8
}

// chars splits text into the characters this reading compares: runes, or
// bytes for the C locale (each byte one character).
func (r *bashGlobReading) chars(text string) []rune {
	if r.bytes {
		out := make([]rune, len(text))
		for i := 0; i < len(text); i++ {
			out[i] = rune(text[i])
		}
		return out
	}
	out := make([]rune, 0, len(text))
	for _, c := range text {
		out = append(out, c)
	}
	return out
}

func (r *bashGlobReading) match(pattern, name string) bool {
	p, s := r.chars(pattern), r.chars(name)
	// Iterative match with one backtrack point for the last *.
	pi, si := 0, 0
	starP, starS := -1, 0
	for si < len(s) {
		if pi < len(p) {
			switch p[pi] {
			case '*':
				for pi < len(p) && p[pi] == '*' {
					pi++
				}
				starP, starS = pi, si
				continue
			case '?':
				pi++
				si++
				continue
			case '[':
				if ok, width, closed := r.bracket(p[pi+1:], s[si]); closed {
					if ok {
						pi += 1 + width
						si++
						continue
					}
				} else if s[si] == '[' {
					pi++
					si++
					continue
				}
			case '\\':
				if pi+1 < len(p) && r.same(p[pi+1], s[si]) {
					pi += 2
					si++
					continue
				}
				if pi+1 == len(p) && s[si] == '\\' {
					pi++
					si++
					continue
				}
			default:
				if r.same(p[pi], s[si]) {
					pi++
					si++
					continue
				}
			}
		}
		if starP < 0 {
			return false
		}
		starS++
		pi, si = starP, starS
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// same compares two literal characters, without case when folding.
func (r *bashGlobReading) same(a, b rune) bool {
	if a == b {
		return true
	}
	return r.fold && unicode.SimpleFold(a) != a && foldEqual(a, b)
}

func foldEqual(a, b rune) bool {
	for f := unicode.SimpleFold(a); f != a; f = unicode.SimpleFold(f) {
		if f == b {
			return true
		}
	}
	return false
}

// bracket reads the bracket expression after a [ (p starts past it) and
// tests c. width is the length of the expression including its closing ].
// closed is false when there is no closing ]: the [ is then a literal.
func (r *bashGlobReading) bracket(p []rune, c rune) (matched bool, width int, closed bool) {
	outer := r.doubt
	r.doubt = false
	defer func() {
		if closed && r.doubt && r.force != 0 {
			matched = r.force > 0
		}
		r.doubt = outer || closed && r.doubt
	}()
	i := 0
	negate := false
	if i < len(p) && (p[i] == '!' || p[i] == '^') {
		negate = true
		i++
	}
	first := true
	for i < len(p) {
		ch := p[i]
		if ch == ']' && !first {
			if negate {
				matched = !matched
			}
			return matched, i + 1, true
		}
		first = false
		if ch == '[' && i+1 < len(p) && (p[i+1] == ':' || p[i+1] == '=' || p[i+1] == '.') {
			kind := p[i+1]
			if end := bashGlobClassEnd(p, i+2, kind); end >= 0 {
				if r.classMember(kind, string(p[i+2:end]), c) {
					matched = true
				}
				i = end + 2
				continue
			}
		}
		lo := ch
		if ch == '\\' && i+1 < len(p) {
			i++
			lo = p[i]
		}
		i++
		if i+1 < len(p) && p[i] == '-' && p[i+1] != ']' {
			hi := p[i+1]
			i += 2
			if hi == '\\' && i < len(p) {
				hi = p[i]
				i++
			}
			if r.inRange(lo, hi, c) {
				matched = true
			}
			continue
		}
		if r.same(lo, c) {
			matched = true
		}
	}
	return false, 0, false
}

// bashGlobClassEnd is the index of the kind character that closes a
// [:name:], [=c=] or [.c.] form starting at from, or -1.
func bashGlobClassEnd(p []rune, from int, kind rune) int {
	for j := from; j+1 < len(p); j++ {
		if p[j] == kind && p[j+1] == ']' {
			return j
		}
	}
	return -1
}

func (r *bashGlobReading) inRange(lo, hi, c rune) bool {
	digits := isASCIIDigitRune(lo) && isASCIIDigitRune(hi)
	letters := isASCIILetter(lo) && isASCIILetter(hi) && unicode.IsUpper(lo) == unicode.IsUpper(hi)
	if !digits && !letters && c != lo && c != hi {
		r.doubt = true // a collation order this process cannot know
	}
	if c >= utf8.RuneSelf {
		r.doubt = true
	}
	test := func(x rune) bool {
		if r.interleaved && letters && isASCIILetter(x) {
			return interleavedOrder(lo) <= interleavedOrder(x) && interleavedOrder(x) <= interleavedOrder(hi)
		}
		return lo <= x && x <= hi
	}
	if test(c) {
		return true
	}
	if r.fold {
		return test(unicode.ToLower(c)) || test(unicode.ToUpper(c))
	}
	return false
}

// interleavedOrder is a letter's place in the a A b B ... z Z order of a
// UTF-8 collation (bash 4 without globasciiranges).
func interleavedOrder(c rune) int {
	if unicode.IsUpper(c) {
		return int(unicode.ToLower(c)-'a')*2 + 1
	}
	return int(c-'a') * 2
}

func isASCIIDigitRune(c rune) bool { return c >= '0' && c <= '9' }

func isASCIILetter(c rune) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// classMember tests c against [:name:], [=x=] or [.x.].
func (r *bashGlobReading) classMember(kind rune, text string, c rune) bool {
	if kind != ':' {
		member := []rune(text)
		if len(member) != 1 || member[0] >= utf8.RuneSelf || c >= utf8.RuneSelf {
			// A multi-character collating name, or a non-ASCII character
			// whose equivalence class follows the locale.
			r.doubt = true
			return false
		}
		return r.same(member[0], c)
	}
	if c >= utf8.RuneSelf {
		r.doubt = true
		return false
	}
	if r.fold && (text == "upper" || text == "lower") {
		r.doubt = true
	}
	switch text {
	case "alpha":
		return isASCIILetter(c)
	case "digit":
		return isASCIIDigitRune(c)
	case "alnum":
		return isASCIILetter(c) || isASCIIDigitRune(c)
	case "upper":
		return c >= 'A' && c <= 'Z'
	case "lower":
		return c >= 'a' && c <= 'z'
	case "space":
		return c == ' ' || c >= '\t' && c <= '\r'
	case "blank":
		return c == ' ' || c == '\t'
	case "punct":
		return c > ' ' && c < 0x7f && !isASCIILetter(c) && !isASCIIDigitRune(c)
	case "xdigit":
		return isASCIIDigitRune(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
	case "cntrl":
		return c < ' ' || c == 0x7f
	case "graph":
		return c > ' ' && c < 0x7f
	case "print":
		return c >= ' ' && c < 0x7f
	case "word":
		return isASCIILetter(c) || isASCIIDigitRune(c) || c == '_'
	}
	// An unknown class name: bash matches nothing with it.
	return false
}
