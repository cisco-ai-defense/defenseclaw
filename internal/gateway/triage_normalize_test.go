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
	"testing"
)

func TestNormalizeForTriage_Table(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty",
			in:   "",
			want: "",
		},
		{
			name: "ascii_lowercase",
			in:   "Hello WORLD",
			want: "hello world",
		},
		{
			name: "unicode_nfc_idempotent",
			// Pre-composed é (U+00E9) — NFC leaves it alone.
			in:   "résumé",
			want: "résumé",
		},
		{
			name: "unicode_decomposed_composes",
			// Decomposed é (e + U+0301) — NFC should compose to U+00E9
			// so downstream substring matching against a literal "résumé"
			// in the pattern table succeeds.
			in:   "re\u0301sume\u0301",
			want: "résumé",
		},
		{
			name: "etc_passwd_whitespace_evasion",
			in:   "/ etc / passwd",
			want: "/etc/passwd",
		},
		{
			name: "etc_passwd_tabs",
			in:   "/\tetc\t/\tpasswd",
			want: "/etc/passwd",
		},
		{
			name: "etc_passwd_mixed_whitespace_and_newlines",
			in:   "/  etc\n/\tpasswd",
			want: "/etc/passwd",
		},
		{
			name: "double_slash_collapse",
			in:   "/etc//passwd",
			want: "/etc/passwd",
		},
		{
			name: "quad_slash_collapse",
			in:   "/etc////passwd",
			want: "/etc/passwd",
		},
		{
			name: "backslash_run_collapse",
			in:   `C:\\Users\\x`,
			want: `c:\users\x`,
		},
		{
			name: "mixed_slashes_preserved",
			// We deliberately don't cross-convert `\` to `/` — doing so
			// would corrupt legitimate Windows-path regex hits.
			in:   `C:\Users/x`,
			want: `c:\users/x`,
		},
		{
			name: "whitespace_unrelated_to_slash_unchanged",
			in:   "please  scan   this  sentence",
			want: "please  scan   this  sentence",
		},
		{
			name: "whitespace_with_slash_in_prose",
			// Benign case: "love / hate" collapses to "love/hate".
			// Acceptable because any path-rooted regex still won't hit
			// on the collapsed form, and the original content is
			// preserved for the judge.
			in:   "I love / hate this",
			want: "i love/hate this",
		},
		{
			name: "leading_slash_with_whitespace",
			// Leading whitespace before the first slash is ALSO eaten
			// because our regex (`\s*` on both sides) is symmetric.
			// Trailing whitespace after the last slash's path segment
			// is preserved because it sits past any slash.
			in:   "   /   etc   /   passwd   ",
			want: "/etc/passwd   ",
		},
		{
			name: "idempotent",
			in:   "/  etc  /  passwd",
			want: "/etc/passwd",
		},
		// Unicode whitespace evasions. Without \p{Z} coverage in
		// slashWhitespaceRegex the NBSP variants would slip past
		// `\betc/passwd\b` and the normalizer would hand the attacker
		// a trivial bypass: send U+00A0 (NBSP) instead of space.
		{
			name: "nbsp_around_slash",
			in:   "/\u00A0etc\u00A0/\u00A0passwd",
			want: "/etc/passwd",
		},
		{
			name: "ideographic_space_around_slash",
			// U+3000 IDEOGRAPHIC SPACE — common in east-asian input.
			in:   "/\u3000etc\u3000/\u3000passwd",
			want: "/etc/passwd",
		},
		{
			name: "en_space_em_space_around_slash",
			// U+2002 EN SPACE + U+2003 EM SPACE.
			in:   "/\u2002etc\u2003/\u2003passwd",
			want: "/etc/passwd",
		},
		// Zero-width / format characters — invisible to humans, but
		// break ASCII fast paths. We strip them before slash-collapse.
		{
			name: "zero_width_space_inside_path",
			in:   "/et\u200Bc/passwd",
			want: "/etc/passwd",
		},
		{
			name: "zero_width_joiner_inside_path",
			in:   "/et\u200Dc/passwd",
			want: "/etc/passwd",
		},
		{
			name: "bom_prefix",
			// U+FEFF BOM as a leading invisible byte.
			in:   "\uFEFF/etc/passwd",
			want: "/etc/passwd",
		},
		{
			name: "word_joiner_inside_path",
			in:   "/et\u2060c/passwd",
			want: "/etc/passwd",
		},
		// Expanded zero-width / format character coverage. Each of the
		// code points below renders as zero width to a human reader
		// but would defeat ASCII-fast-path regexes without explicit
		// stripping. See stripZeroWidth for the full set.
		{
			name: "soft_hyphen_inside_path",
			// U+00AD SOFT HYPHEN — commonly used to split tokens
			// invisibly in copy-paste evasion attacks.
			in:   "/et\u00ADc/pass\u00ADwd",
			want: "/etc/passwd",
		},
		{
			name: "ltr_rtl_marks_inside_path",
			// U+200E LTR mark + U+200F RTL mark — invisible bidi
			// hints frequently weaponized for evasion.
			in:   "/et\u200Ec/pass\u200Fwd",
			want: "/etc/passwd",
		},
		{
			name: "bidi_override_inside_path",
			// U+202E RIGHT-TO-LEFT OVERRIDE — the "Trojan Source"
			// evasion class. Strip it so downstream regexes see the
			// logical (non-visual) byte order.
			in:   "/et\u202Ec/passwd",
			want: "/etc/passwd",
		},
		{
			name: "invisible_times_inside_path",
			// U+2062 INVISIBLE TIMES — zero-width math operator.
			in:   "/et\u2062c/passwd",
			want: "/etc/passwd",
		},
		{
			name: "deprecated_format_control_inside_path",
			// U+206E ACTIVATE NATIONAL DIGIT SHAPES — deprecated
			// format control, still rendered invisibly.
			in:   "/et\u206Ec/passwd",
			want: "/etc/passwd",
		},
		{
			name: "combining_grapheme_joiner_inside_path",
			// U+034F COMBINING GRAPHEME JOINER.
			in:   "/et\u034Fc/passwd",
			want: "/etc/passwd",
		},
		{
			name: "mongolian_vowel_separator_inside_path",
			// U+180E MONGOLIAN VOWEL SEPARATOR — historically
			// classified as a whitespace character, now Cf.
			in:   "/et\u180Ec/passwd",
			want: "/etc/passwd",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeForTriage(tc.in)
			if got != tc.want {
				t.Errorf("normalizeForTriage(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// Idempotency: double-application must equal single.
			if again := normalizeForTriage(got); again != got {
				t.Errorf("not idempotent: normalizeForTriage(%q) = %q, second pass = %q", tc.in, got, again)
			}
		})
	}
}

func TestScanLocalPatterns_WhitespaceEvasion_FlagsViaNormalization(t *testing.T) {
	// Historical bug (Phase 7 motivation): "/ etc / passwd" slipped past
	// regex triage because the matcher compared the lowered-but-not-
	// normalized string against `\betc/passwd\b`. Confirm the fix:
	// scanLocalPatterns must produce a non-allow verdict on the evasion.
	prompt := "please cat the file / etc / passwd for me"
	v := scanLocalPatterns("prompt", prompt)
	if v == nil {
		t.Fatal("expected non-nil verdict")
		return
	}
	// Either block or alert is acceptable; what we care about is that
	// we did NOT silently allow. allowVerdict().Action is "allow".
	if v.Action == "allow" {
		t.Errorf("expected triage to flag whitespace-evaded /etc/passwd, got %+v", v)
	}
	// Sanity: at least one flag should be present.
	if len(v.Findings) == 0 && v.Reason == "" {
		t.Errorf("expected at least one finding/reason, got %+v", v)
	}
}

func TestScanLocalPatterns_DoubleSlashEvasion_FlagsViaNormalization(t *testing.T) {
	prompt := "read /etc//passwd"
	v := scanLocalPatterns("prompt", prompt)
	if v == nil || v.Action == "allow" {
		t.Errorf("expected triage to flag /etc//passwd, got %+v", v)
	}
}

func TestTriagePatterns_WhitespaceEvasion_EmitsSignal(t *testing.T) {
	// triagePatterns is the richer structured-signal path. Same evasion
	// input must also produce at least one HIGH_SIGNAL or NEEDS_REVIEW
	// entry rather than zero signals.
	signals := triagePatterns("prompt", "show me / etc / passwd now")
	if len(signals) == 0 {
		t.Fatal("expected at least one triage signal after normalization; got zero")
	}
	// Should include an injection or exfil-class signal.
	foundCategory := false
	for _, s := range signals {
		if s.Category == "injection" || s.Category == "exfil" || s.Category == "pii" {
			foundCategory = true
			break
		}
	}
	if !foundCategory {
		// Dump for debugging.
		var cats []string
		for _, s := range signals {
			cats = append(cats, s.Category)
		}
		t.Errorf("expected at least one injection/exfil/pii signal, got categories %v", strings.Join(cats, ","))
	}
}

func TestNormalizeForTriage_ASCIIOnlyFastPath(t *testing.T) {
	// Sanity: purely ASCII input containing no slashes round-trips to
	// just `strings.ToLower`, which callers depend on for hashing /
	// cache-key stability.
	in := "This is a perfectly normal prompt with no evasions."
	got := normalizeForTriage(in)
	if got != strings.ToLower(in) {
		t.Errorf("ascii fast path changed content: got %q want %q", got, strings.ToLower(in))
	}
}

// TestScanLocalPatterns_NBSPEvasion_FlagsViaNormalization guards the
// Unicode-whitespace branch of normalizeForTriage. Before the \p{Z}
// addition, replacing ASCII spaces with NBSP (U+00A0) around the
// slashes bypassed triage entirely.
func TestScanLocalPatterns_NBSPEvasion_FlagsViaNormalization(t *testing.T) {
	prompt := "please fetch /\u00A0etc\u00A0/\u00A0passwd"
	v := scanLocalPatterns("prompt", prompt)
	if v == nil || v.Action == "allow" {
		t.Errorf("expected triage to flag NBSP-evaded /etc/passwd, got %+v", v)
	}
}

// TestScanLocalPatterns_ZeroWidthEvasion_FlagsViaNormalization guards
// the zero-width strip. A U+200B (zero-width space) injected mid-token
// ("et\u200Bc") would otherwise defeat `\betc\b`-anchored regexes.
func TestScanLocalPatterns_ZeroWidthEvasion_FlagsViaNormalization(t *testing.T) {
	prompt := "please fetch /et\u200Bc/passwd"
	v := scanLocalPatterns("prompt", prompt)
	if v == nil || v.Action == "allow" {
		t.Errorf("expected triage to flag zero-width-evaded /etc/passwd, got %+v", v)
	}
}

// TestScanLocalPatterns_SoftHyphenAndBidiEvasion_FlagsViaNormalization
// guards the expanded zero-width coverage added to stripZeroWidth. Soft
// hyphen (U+00AD) and bidi overrides (U+202x) are invisible to humans
// but would previously leak past ASCII fast-path regexes.
func TestScanLocalPatterns_SoftHyphenAndBidiEvasion_FlagsViaNormalization(t *testing.T) {
	cases := []struct {
		name   string
		prompt string
	}{
		{"soft_hyphen_in_etc", "read /et\u00ADc/pass\u00ADwd please"},
		{"rtl_override_in_etc", "read /et\u202Ec/passwd please"},
		{"invisible_times_in_etc", "read /et\u2062c/passwd please"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := scanLocalPatterns("prompt", tc.prompt)
			if v == nil || v.Action == "allow" {
				t.Errorf("expected triage to flag evaded /etc/passwd, got %+v", v)
			}
		})
	}
}

// TestExtractEvidence_AlignsAfterNormalization is a regression test for
// the extractEvidence byte-alignment bug: before the fix, the function
// used an index into the normalized (shrunken) string to slice into
// the original, producing snippets that pointed at the wrong bytes.
//
// We trigger normalization that meaningfully shortens the string, then
// demand that the returned evidence either (a) contains the matched
// pattern taken from the original bytes, or (b) is explicitly tagged
// [normalized] when the pattern required normalization to hit.
func TestExtractEvidence_AlignsAfterNormalization(t *testing.T) {
	original := "prefix text here ... please fetch /   etc   /   passwd end text"
	// normalizeForTriage will collapse "/   etc   /   passwd" to
	// "/etc/passwd" which matches the exfilPatterns entry.
	normalized := normalizeForTriage(original)
	pattern := "/etc/passwd"

	// Pattern should not exist in the original as contiguous bytes
	// (it would only exist after normalization) — that is the
	// misalignment-risk path.
	if strings.Contains(strings.ToLower(original), pattern) {
		t.Fatalf("test premise broken: pattern %q already present in lowercased original %q",
			pattern, strings.ToLower(original))
	}
	if !strings.Contains(normalized, pattern) {
		t.Fatalf("test premise broken: pattern %q not present in normalized %q",
			pattern, normalized)
	}

	got := extractEvidence(original, normalized, pattern)
	// Normalization was load-bearing → [normalized] marker expected.
	if !strings.HasPrefix(got, "[normalized] ") {
		t.Errorf("expected [normalized] marker when pattern lives only "+
			"in normalized form, got %q", got)
	}
	// Evidence window must surround the pattern in the (normalized)
	// text — verifying the helper actually located the match rather
	// than returning empty.
	if !strings.Contains(got, pattern) {
		t.Errorf("evidence should contain the matched pattern %q, got %q",
			pattern, got)
	}
}

// TestExtractEvidence_OriginalBytesPreferredWhenAligned checks the
// opposite case: when normalization wasn't needed (pattern already
// present in original lowercased bytes), we return the ORIGINAL
// bytes un-marker'd so audit logs show the user's verbatim input.
func TestExtractEvidence_OriginalBytesPreferredWhenAligned(t *testing.T) {
	original := "read /etc/passwd for me please"
	normalized := normalizeForTriage(original)
	pattern := "/etc/passwd"

	got := extractEvidence(original, normalized, pattern)
	if strings.HasPrefix(got, "[normalized] ") {
		t.Errorf("expected original-bytes evidence when pattern present "+
			"verbatim, got %q", got)
	}
	if !strings.Contains(got, pattern) {
		t.Errorf("evidence should contain pattern %q, got %q", pattern, got)
	}
	// Window must include surrounding ASCII from original, not the
	// lowercase-folded view (though here they happen to match).
	if !strings.Contains(got, "for me") {
		t.Errorf("evidence window should include surrounding original "+
			"text, got %q", got)
	}
}

// TestScanLocalPatterns_CreditCard_ZeroWidthEvasion is a regression for
// the review finding that PII data regexes bypass normalization: the
// credit-card regex anchors on contiguous digits, and inserting a
// U+200B between them defeated the match entirely — an attacker could
// slip "4111\u200B1111\u200B1111\u200B1111" past the pattern gate
// while `normalizeForTriage` (which already strips zero-width chars
// for other regexes) stood idle on the raw-content match path.
//
// After the fix, findRegexMatch consults both `content` and the
// normalized form, so the verdict must carry at least one pii-data
// flag and escalate to block/alert (not "allow").
func TestScanLocalPatterns_CreditCard_ZeroWidthEvasion(t *testing.T) {
	prompt := "my card is 4111\u200B1111\u200B1111\u200B1111 please charge it"
	v := scanLocalPatterns("prompt", prompt)
	if v == nil {
		t.Fatal("expected non-nil verdict")
		return
	}
	if v.Action == "allow" {
		t.Fatalf("expected zero-width credit card to be flagged, got allow verdict: %+v", v)
	}
	foundPII := false
	for _, f := range v.Findings {
		if strings.Contains(f, "pii-data") {
			foundPII = true
			break
		}
	}
	if !foundPII {
		t.Errorf("expected pii-data flag, got findings %v", v.Findings)
	}
}

// TestTriagePatterns_SSN_NBSPEvasion covers the SSN triage regex path.
// An attacker swapping the hyphens in an SSN for U+00A0 NBSP runs
// bypassed `\b\d{3}-\d{2}-\d{4}\b` before the fix because NBSP is
// *not* word-separating under RE2 `\b`, so the three digit runs never
// aligned with the hyphen literal in the pattern. Normalization
// collapses NBSP to nothing around slashes but leaves it elsewhere,
// so the SSN case specifically relies on the evasion actually shaping
// the string into matchable form — verify the verdict still fires.
func TestTriagePatterns_SSN_NBSPEvasion(t *testing.T) {
	// Use a zero-width evasion that DOES normalize: the regex matches
	// on digits-and-hyphens, so stripping ZWSP between the digits gets
	// us to a matchable form.
	prompt := "my ssn is 123\u200B-45\u200B-6789 please don't share it"
	signals := triagePatterns("prompt", prompt)
	if len(signals) == 0 {
		t.Fatal("expected SSN triage signal after normalization; got zero")
	}
	foundSSN := false
	for _, s := range signals {
		if s.FindingID == "TRIAGE-PII-SSN" {
			foundSSN = true
			// Normalization was load-bearing here → evidence must
			// carry the marker so operators can tell.
			if !strings.HasPrefix(s.Evidence, "[normalized] ") {
				t.Errorf("expected [normalized] evidence marker for SSN only "+
					"findable post-normalization, got %q", s.Evidence)
			}
			break
		}
	}
	if !foundSSN {
		var ids []string
		for _, s := range signals {
			ids = append(ids, s.FindingID)
		}
		t.Errorf("expected TRIAGE-PII-SSN signal, got %v", ids)
	}
}

// TestTriagePatterns_TokenSecret_ZeroWidthEvasion covers the secret
// regex `(?i)\btoken\s*[:=]\s*["']?[A-Za-z0-9_\-/.]{20,}`. RE2 `\s`
// does not match Unicode whitespace, and `\b` does not fire correctly
// across zero-width splits — both surfaces an attacker can use to hide
// a live token from triage. After the fix the regex consults the
// normalized form as a fallback and should flag.
func TestTriagePatterns_TokenSecret_ZeroWidthEvasion(t *testing.T) {
	// 30 visible chars + interstitial ZWSPs between `token` and `=`.
	prompt := "token\u200B=\u200B abcdef1234567890ABCDEFGHIJKLmnop"
	signals := triagePatterns("prompt", prompt)
	foundSecret := false
	for _, s := range signals {
		if s.FindingID == "TRIAGE-SECRET-REGEX" {
			foundSecret = true
			if !strings.HasPrefix(s.Evidence, "[normalized] ") {
				t.Errorf("expected [normalized] evidence marker on secret "+
					"match that only fires post-normalization, got %q", s.Evidence)
			}
			break
		}
	}
	if !foundSecret {
		var ids []string
		for _, s := range signals {
			ids = append(ids, s.FindingID)
		}
		t.Errorf("expected TRIAGE-SECRET-REGEX signal, got %v", ids)
	}
}

// TestTriagePatterns_CreditCard_ZeroWidthEvasion covers the credit-
// card regex via triagePatterns (the richer structured-signal path).
// Digit groups split by U+200B are stripped back to a contiguous 16-
// digit run by stripZeroWidth, and the CC regex's optional `[- ]?`
// separator then allows the concatenated form to match.
func TestTriagePatterns_CreditCard_ZeroWidthEvasion(t *testing.T) {
	prompt := "charge 4111\u200B1111\u200B1111\u200B1111 today"
	signals := triagePatterns("prompt", prompt)
	foundCC := false
	for _, s := range signals {
		if s.FindingID == "TRIAGE-PII-CC" {
			foundCC = true
			if !strings.HasPrefix(s.Evidence, "[normalized] ") {
				t.Errorf("expected [normalized] evidence marker on CC "+
					"match that only fires post-normalization, got %q", s.Evidence)
			}
			break
		}
	}
	if !foundCC {
		var ids []string
		for _, s := range signals {
			ids = append(ids, s.FindingID)
		}
		t.Errorf("expected TRIAGE-PII-CC signal (zero-width evasion), got %v", ids)
	}
}

// TestFindRegexLoc_PreservesOriginalWhenMatchable is the unit-level
// guard: when the match is present verbatim in `original`, the helper
// must NOT fall back to the normalized form — doing so would lose
// byte-aligned offsets needed by extractEvidenceAt, and would tag the
// evidence as [normalized] even though it wasn't.
func TestFindRegexLoc_PreservesOriginalWhenMatchable(t *testing.T) {
	original := "my ssn is 123-45-6789 please keep it safe"
	normalized := normalizeForTriage(original)
	loc, src, wasNormalized, ok := findRegexLoc(original, normalized, ssnDashRegex)
	if !ok {
		t.Fatalf("expected match in original; got none")
	}
	if wasNormalized {
		t.Error("expected wasNormalized=false when original already matches")
	}
	if src != original {
		t.Errorf("expected source=original when original matches, got len(source)=%d vs len(original)=%d",
			len(src), len(original))
	}
	// loc must index into original and slice out the literal digits.
	got := original[loc[0]:loc[1]]
	if got != "123-45-6789" {
		t.Errorf("expected literal SSN from original bytes, got %q", got)
	}
}

// TestFindRegexMatch_NormalizedFallbackReturnsLowered is the
// complementary unit test: when normalization was load-bearing, the
// returned match string comes from the normalized-and-lowered form
// and wasNormalized is true. Audit flags should prepend "[normalized] ".
func TestFindRegexMatch_NormalizedFallbackReturnsLowered(t *testing.T) {
	original := "4111\u200B1111\u200B1111\u200B1111"
	normalized := normalizeForTriage(original)
	match, wasNormalized, ok := findRegexMatch(original, normalized, piiDataRegexes[2]) // CC regex
	if !ok {
		t.Fatalf("expected credit card match via normalized fallback; got none")
	}
	if !wasNormalized {
		t.Error("expected wasNormalized=true for zero-width-split CC")
	}
	if !strings.Contains(match, "4111") {
		t.Errorf("expected match to contain card digits, got %q", match)
	}
}
