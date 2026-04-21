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
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// slashWhitespaceRegex matches a `/` or `\` together with any
// whitespace immediately surrounding it on EITHER side in a single
// match. The character class combines Go's `\s` (ASCII whitespace)
// with `\p{Z}` (Unicode whitespace property: NBSP, ideographic space,
// line/paragraph separators, etc.) so attacks substituting U+00A0
// for ASCII space still collapse. Non-overlapping scan from the
// engine guarantees we handle each slash exactly once, which is
// what makes normalization idempotent even with runs like
// "   /   etc   /   passwd   ".
//
// Side-effect on benign prose: "I love / hate" collapses to
// "I love/hate". Acceptable because (a) the original content is
// preserved for the judge, and (b) any path-rooted triage regex that
// cared about the collapse would also have cared about the original
// form anyway.
var slashWhitespaceRegex = regexp.MustCompile(`[\s\p{Z}]*([/\\])[\s\p{Z}]*`)

// forwardSlashRunRegex and backSlashRunRegex collapse runs of 2+
// forward OR back slashes down to a single slash of the SAME kind.
// Without these, an evasion like "/etc//passwd" or "/etc////passwd"
// would slip past a regex anchored on `\betc/pas{1,4}wd\b`. We keep
// forward vs back slashes separate on purpose — normalizing
// "C:\Users\x" to "C:/Users/x" would break Windows-path regexes
// callers may legitimately need to match. Split into two regexes
// because Go's RE2 engine does not support backreferences so
// `([/\\])\1+` is not expressible in a single pattern.
var forwardSlashRunRegex = regexp.MustCompile(`/{2,}`)
var backSlashRunRegex = regexp.MustCompile(`\\{2,}`)

// stripZeroWidth drops zero-width / format characters that a human
// reader does not see but that break ASCII fast paths. Covers the
// Unicode `Cf` format code points most commonly used for prompt-
// injection evasion plus a few `Mn` mark helpers that are also
// rendered as zero-width:
//
//   - U+00AD SOFT HYPHEN
//   - U+034F COMBINING GRAPHEME JOINER
//   - U+061C ARABIC LETTER MARK
//   - U+115F HANGUL CHOSEONG FILLER
//   - U+1160 HANGUL JUNGSEONG FILLER
//   - U+17B4 KHMER VOWEL INHERENT AQ
//   - U+17B5 KHMER VOWEL INHERENT AA
//   - U+180E MONGOLIAN VOWEL SEPARATOR
//   - U+200B ZERO WIDTH SPACE
//   - U+200C ZERO WIDTH NON-JOINER
//   - U+200D ZERO WIDTH JOINER
//   - U+200E LEFT-TO-RIGHT MARK
//   - U+200F RIGHT-TO-LEFT MARK
//   - U+202A..U+202E bidi embedding/override controls
//   - U+2060 WORD JOINER
//   - U+2061..U+2064 invisible math operators
//   - U+2066..U+2069 bidi isolate controls
//   - U+206A..U+206F deprecated format controls (inhibit / activate
//     symmetric swapping, inhibit / activate Arabic form shaping, etc.)
//   - U+3164 HANGUL FILLER
//   - U+FEFF BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
//   - U+FFA0 HALFWIDTH HANGUL FILLER
//   - U+FFF9..U+FFFB interlinear annotation anchors
//
// Implementation uses strings.Map so the scan is single-pass and
// allocation-free when no zero-width chars are present (the common
// case). These are stripped before the slash-adjacent whitespace
// collapse because `\p{Z}` deliberately does NOT cover zero-width
// chars (Unicode classifies them as `Cf` format, not `Z` separator).
func stripZeroWidth(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\u00AD',
			r == '\u034F',
			r == '\u061C',
			r == '\u115F',
			r == '\u1160',
			r == '\u17B4',
			r == '\u17B5',
			r == '\u180E',
			r == '\u200B',
			r == '\u200C',
			r == '\u200D',
			r == '\u200E',
			r == '\u200F',
			r >= '\u202A' && r <= '\u202E',
			r == '\u2060',
			r >= '\u2061' && r <= '\u2064',
			r >= '\u2066' && r <= '\u2069',
			r >= '\u206A' && r <= '\u206F',
			r == '\u3164',
			r == '\uFEFF',
			r == '\uFFA0',
			r >= '\uFFF9' && r <= '\uFFFB':
			return -1
		}
		return r
	}, s)
}

// normalizeForTriage returns a canonicalized form of content suitable
// for running whole-word and path-anchored regexes against. The
// normalizations applied, in order:
//
//  1. Unicode NFC composition so that pre-composed "é" and
//     decomposed "e\u0301" are treated identically. Without this,
//     "se\u0301nsitive" with a combining mark slips past every regex
//     scanning the ASCII fast path, even though a human reader treats
//     the rendered string as "sensitive".
//  2. Zero-width strip — removes common invisible format characters
//     (soft hyphen, bidi controls, ZWSP/ZWJ/ZWNJ, word joiner, BOM,
//     invisible math operators, deprecated format controls, etc.)
//     which are invisible to the reader but break ASCII fast paths
//     ("/et\u200Bc/pass\u00ADwd" → "/etc/passwd"). See stripZeroWidth
//     for the exact code-point coverage.
//  3. Lowercase via strings.ToLower. Substring scans with
//     strings.Contains (case-sensitive) operate on the normalized
//     string so a case-only mismatch does not leak past triage.
//  4. Whitespace-around-slash collapse — removes any ASCII whitespace
//     OR Unicode-Z whitespace (NBSP, ideographic space, etc.) on
//     either side of `/` or `\`. Defeats the "/ etc / passwd" visual
//     evasion and its NBSP variant.
//  5. Duplicate-slash collapse — collapses `//…//` and `\\…\\` runs
//     down to a single separator of the same kind, preserving the
//     distinction between POSIX and Windows paths.
//
// NOT covered (explicit non-goals — documented so operators know
// what to expect when choosing between relying on normalization and
// relying on the LLM judge as defense-in-depth):
//
//   - Homoglyph folding (Cyrillic/Greek lookalikes, full-width Latin).
//     An attacker can still send Cyrillic `еtc/passwd` (first byte
//     U+0435) and miss the regex. Mitigation is the LLM judge via
//     judge_sweep, not this helper.
//   - Case-folding beyond strings.ToLower. Unicode full case-folding
//     (e.g. German ß → ss) is not applied because it breaks round-
//     tripping for token-level evidence extraction.
//   - Diacritic stripping. "é" stays "é"; only decomposed forms are
//     composed.
//
// IMPORTANT: this function is intended for triage regex matching ONLY.
// The guardrail deliberately does NOT pass the normalized string to
// the LLM judge because (a) normalization strips information the
// judge may need to weigh intent ("is this a typo or an evasion?"),
// and (b) if the normalizer ever introduces a false-positive the
// judge's subsequent verdict would inherit the error. Callers must
// keep the original content in scope and pass IT — not the return
// value — to the judge.
//
// Idempotency: normalizeForTriage(normalizeForTriage(x)) ==
// normalizeForTriage(x) for all x. Relied on by the triage verdict
// cache so cache lookups don't have to re-normalize before hashing.
func normalizeForTriage(content string) string {
	if content == "" {
		return ""
	}
	// Step 1: NFC — composes any decomposed forms. Hot path for
	// ASCII-only inputs returns the original string unchanged (the
	// x/text package fast-paths the common case).
	s := norm.NFC.String(content)
	// Step 2: strip zero-width / format characters. Allocation-free
	// when none are present.
	s = stripZeroWidth(s)
	// Step 3: lowercase.
	s = strings.ToLower(s)
	// Step 4: collapse whitespace (ASCII and Unicode-Z) adjacent to
	// slashes. $1 is the captured slash character so a run like
	// "   /\u00A0" collapses to just "/" while preserving `/` vs `\`.
	s = slashWhitespaceRegex.ReplaceAllString(s, "$1")
	// Step 5: collapse duplicate slashes of the same kind.
	s = forwardSlashRunRegex.ReplaceAllString(s, `/`)
	s = backSlashRunRegex.ReplaceAllString(s, `\`)
	return s
}
