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
