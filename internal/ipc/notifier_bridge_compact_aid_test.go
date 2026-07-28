// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import "testing"

// TestCompactAIDCategories locks the SecureClient toast contract: the
// IPC body should carry ONLY the SCREAMING_SNAKE_CASE category tokens
// from a "Cisco AI Defense: ..." verdict body, dropping per-rule
// signals (Title Case) so the toast doesn't overflow. The full
// per-rule detail still reaches the audit sink via BlockEvent.Reason;
// this transform only applies to the IPC-to-SecureClient wire.
func TestCompactAIDCategories(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "mixed categories + rule names (the reported bug)",
			in:   "Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION, SAFETY_VIOLATION, Prompt Injection, PII",
			want: "Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION, SAFETY_VIOLATION",
		},
		{
			name: "categories only — passes through",
			in:   "Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION",
			want: "Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION",
		},
		{
			name: "single category + trailing whitespace tolerance",
			in:   "Cisco AI Defense:  SAFETY_VIOLATION ",
			want: "Cisco AI Defense: SAFETY_VIOLATION",
		},
		{
			name: "rule names only — preserve original (better than empty)",
			in:   "Cisco AI Defense: Prompt Injection, PII, Malicious URL Detection",
			want: "Cisco AI Defense: Prompt Injection, PII, Malicious URL Detection",
		},
		{
			name: "non-AID body (asset policy) — untouched",
			in:   "Blocked because mcp:untrusted-server is not on the allowlist",
			want: "Blocked because mcp:untrusted-server is not on the allowlist",
		},
		{
			name: "non-AID body (hook guardian) — untouched",
			in:   "hook guardian: connector cursor rejected shell execution",
			want: "hook guardian: connector cursor rejected shell execution",
		},
		{
			name: "empty body — untouched",
			in:   "",
			want: "",
		},
		{
			name: "AID prefix with empty tail — untouched",
			in:   "Cisco AI Defense:",
			want: "Cisco AI Defense:",
		},
		{
			name: "extra whitespace inside comma list",
			in:   "Cisco AI Defense:  SECURITY_VIOLATION,   PRIVACY_VIOLATION,  Custom Rule",
			want: "Cisco AI Defense: SECURITY_VIOLATION, PRIVACY_VIOLATION",
		},
		{
			name: "categories with digits are accepted (NONE_ATTACK_TECHNIQUE-style enum future-proofing)",
			in:   "Cisco AI Defense: LOW_SEVERITY_2, SECURITY_VIOLATION, Prompt Injection",
			want: "Cisco AI Defense: LOW_SEVERITY_2, SECURITY_VIOLATION",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := compactAIDCategories(tc.in)
			if got != tc.want {
				t.Fatalf("compactAIDCategories(%q):\n  got  %q\n  want %q", tc.in, got, tc.want)
			}
		})
	}
}
