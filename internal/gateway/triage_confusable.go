// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// triageConfusables maps the lowercase letters of other scripts that render
// like an ASCII letter to that letter. normalizeForTriage applies it only
// inside a word that already holds an ASCII letter (a mixed-script word such
// as "pаssword" with a Cyrillic а), never to a word written wholly in another
// script, so Cyrillic, Greek or any other prose keeps its own letters and
// cannot newly spell an English pattern word (rel-1-0-10:GAP-1952).
//
// Every entry maps a letter to a letter, so word boundaries never move and
// the fold stays idempotent. The set is bounded on purpose: the common
// Cyrillic, Greek and Latin-extension lookalikes, not the whole UTS #39
// confusables table. NFKC (step 1 of normalizeForTriage) already folds the
// compatibility forms (fullwidth letters, U+017F long s, ligatures).
var triageConfusables = map[rune]byte{
	// Cyrillic.
	'а': 'a', 'в': 'b', 'е': 'e', 'һ': 'h', 'н': 'h',
	'і': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'о': 'o',
	'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x',
	'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ӏ': 'l',
	// Greek.
	'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
	'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
	// Latin letters NFKC leaves alone.
	'ı': 'i', 'ȷ': 'j', 'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i',
}

// foldTriageConfusables is step 4 of normalizeForTriage. In each word (a run
// of letters and combining marks) that holds an ASCII letter it replaces the
// triageConfusables letters with their ASCII twin and drops the combining
// marks that sit on an ASCII letter ("fi̇nd" reads as "find"; NFKC has
// already composed every mark that has a precomposed form, so only marks a
// reader sees as decoration on the ASCII letter remain). Words with no ASCII
// letter, and every byte outside a word (invalid UTF-8 included), are copied
// unchanged. Pure ASCII input is returned as is without allocating.
func foldTriageConfusables(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	var b strings.Builder
	copied := 0 // s[:copied] is already in b
	for pos := 0; pos < len(s); {
		r, size := utf8.DecodeRuneInString(s[pos:])
		if !isTriageWordRune(r) {
			pos += size
			continue
		}
		end, hasASCII, foldable := pos, false, false
		for end < len(s) {
			wr, ws := utf8.DecodeRuneInString(s[end:])
			if !isTriageWordRune(wr) {
				break
			}
			if wr < utf8.RuneSelf {
				hasASCII = true
			} else if _, ok := triageConfusables[wr]; ok || unicode.Is(unicode.M, wr) {
				foldable = true
			}
			end += ws
		}
		if hasASCII && foldable {
			if copied == 0 {
				b.Grow(len(s))
			}
			b.WriteString(s[copied:pos])
			writeFoldedTriageWord(&b, s[pos:end])
			copied = end
		}
		pos = end
	}
	if copied == 0 {
		return s
	}
	b.WriteString(s[copied:])
	return b.String()
}

// isTriageWordRune reports whether r belongs to a word for
// foldTriageConfusables: an ASCII letter, any other letter, or a combining
// mark. RuneError from invalid UTF-8 is not a letter, so a bad byte ends a word.
func isTriageWordRune(r rune) bool {
	if r < utf8.RuneSelf {
		return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z'
	}
	return unicode.IsLetter(r) || unicode.Is(unicode.M, r)
}

func writeFoldedTriageWord(b *strings.Builder, word string) {
	onASCII := false // the last letter written is ASCII
	for _, r := range word {
		if r < utf8.RuneSelf {
			b.WriteByte(byte(r))
			onASCII = true
			continue
		}
		if c, ok := triageConfusables[r]; ok {
			b.WriteByte(c)
			onASCII = true
			continue
		}
		if onASCII && unicode.Is(unicode.M, r) {
			continue // a mark stacked on an ASCII letter
		}
		b.WriteRune(r)
		onASCII = false
	}
}
