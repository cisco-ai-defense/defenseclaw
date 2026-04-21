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
// match. `\s*` on both sides is fine — for the common no-whitespace
// case (e.g. `/etc/passwd`) the zero-width match replaces the slash
// with itself and the scan advances a byte at a time. Non-overlapping
// scan from the engine guarantees we handle each slash exactly once,
// which is what makes normalization idempotent even with runs like
// "   /   etc   /   passwd   ".
//
// Side-effect on benign prose: "I love / hate" collapses to
// "I love/hate". Acceptable because (a) the original content is
// preserved for the judge, and (b) any path-rooted triage regex that
// cared about the collapse would also have cared about the original
// form anyway.
var slashWhitespaceRegex = regexp.MustCompile(`\s*([/\\])\s*`)

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

// normalizeForTriage returns a canonicalized form of content suitable
// for running whole-word and path-anchored regexes against. The
// normalizations applied, in order:
//
//  1. Unicode NFC composition so that pre-composed "é" and
//     decomposed "e\u0301" are treated identically. Without this,
//     "sén̈sitivie" with a combining mark slips past every regex
//     scanning the ASCII fast path, even though a human reader treats
//     the rendered string as "sensitive".
//  2. Lowercase via strings.ToLower. All triage regexes are already
//     `(?i)` but the cheap lowercase makes follow-on substring
//     scans with strings.Contains (which is case-sensitive) work
//     correctly too.
//  3. Whitespace-around-slash collapse — removes spaces/tabs/newlines
//     on either side of `/` or `\`. This defeats the "/ etc / passwd"
//     visual evasion.
//  4. Duplicate-slash collapse — collapses `//…//` and `\\…\\` runs
//     down to a single separator of the same kind, preserving the
//     distinction between POSIX and Windows paths.
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
	// Step 2: lowercase.
	s = strings.ToLower(s)
	// Step 3: collapse whitespace adjacent to slashes. $1 is the
	// captured slash character so a run like "   /   " collapses to
	// just "/" while preserving `/` vs `\` distinction.
	s = slashWhitespaceRegex.ReplaceAllString(s, "$1")
	// Step 4: collapse duplicate slashes of the same kind.
	s = forwardSlashRunRegex.ReplaceAllString(s, `/`)
	s = backSlashRunRegex.ReplaceAllString(s, `\`)
	return s
}
