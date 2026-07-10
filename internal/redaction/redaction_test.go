// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package redaction

import (
	"strings"
	"testing"
)

func TestReveal(t *testing.T) {
	t.Run("unset defaults to false", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_REVEAL_PII", "")
		if Reveal() {
			t.Fatal("Reveal() = true; want false when env var unset")
		}
	})
	for _, val := range []string{"1", "true", "TRUE", "yes", "YES", "on", "On"} {
		val := val
		t.Run("truthy "+val, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_REVEAL_PII", val)
			if !Reveal() {
				t.Fatalf("Reveal()=false for env=%q; want true", val)
			}
		})
	}
	for _, val := range []string{"0", "false", "no", "off", "bogus"} {
		val := val
		t.Run("falsy "+val, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_REVEAL_PII", val)
			if Reveal() {
				t.Fatalf("Reveal()=true for env=%q; want false", val)
			}
		})
	}
}

func TestString(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "<empty>"},
		{"short", "abcd", "<redacted len=4>"},
		{"normal", "hello world", ""},
		{"unicode", "héllo wörld 🚀", ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := String(tc.in)
			if tc.want != "" && got != tc.want {
				t.Fatalf("String(%q) = %q; want %q", tc.in, got, tc.want)
			}
			if tc.want == "" {
				if !strings.HasPrefix(got, "<redacted len=") || !strings.Contains(got, " sha=") {
					t.Fatalf("String(%q) = %q; want redacted shape", tc.in, got)
				}
				if strings.Contains(got, tc.in) {
					t.Fatalf("String(%q) = %q leaked input", tc.in, got)
				}
			}
		})
	}
}

func TestStringReveal(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	if got := String("leak me"); got != "leak me" {
		t.Fatalf("Reveal=1: String() = %q; want passthrough", got)
	}
}

func TestForSinkStringBypassesReveal(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	got := ForSinkString("sensitive")
	if strings.Contains(got, "sensitive") {
		t.Fatalf("ForSinkString leaked under reveal: %q", got)
	}
	if !strings.HasPrefix(got, "<redacted") {
		t.Fatalf("ForSinkString returned %q; want redacted", got)
	}
}

func TestForSinkStringIdempotent(t *testing.T) {
	once := ForSinkString("4155551234")
	twice := ForSinkString(once)
	if once != twice {
		t.Fatalf("not idempotent: %q -> %q", once, twice)
	}
}

func TestEntity(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	got := Entity("4155551234")
	if strings.Contains(got, "4155551234") {
		t.Fatalf("Entity leaked input: %q", got)
	}
	if !strings.Contains(got, "prefix=") {
		t.Fatalf("Entity missing prefix: %q", got)
	}
	if !strings.Contains(got, "len=10") {
		t.Fatalf("Entity len mismatch: %q", got)
	}
}

func TestEntityShort(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	got := Entity("ab")
	if !strings.HasPrefix(got, "<redacted len=2") {
		t.Fatalf("Entity short = %q", got)
	}
	if strings.Contains(got, "prefix=") {
		t.Fatalf("Entity short should not include prefix: %q", got)
	}
}

func TestEntityEmpty(t *testing.T) {
	if Entity("") != "<empty>" {
		t.Fatal("empty entity not marked")
	}
}

func TestEntityUnicode(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	got := Entity("héllo@exämple.com")
	if strings.Contains(got, "héllo") {
		t.Fatalf("Entity leaked: %q", got)
	}
	if !strings.Contains(got, `prefix="h"`) {
		t.Fatalf("Entity missing h prefix: %q", got)
	}
}

func TestEntityIdempotent(t *testing.T) {
	once := ForSinkEntity("4155551234")
	twice := ForSinkEntity(once)
	if once != twice {
		t.Fatalf("Entity not idempotent: %q -> %q", once, twice)
	}
}

func TestMessageContent(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	got := MessageContent("My SSN is 123-45-6789 please help")
	if strings.Contains(got, "SSN") || strings.Contains(got, "123-45-6789") {
		t.Fatalf("MessageContent leaked: %q", got)
	}
	if !strings.Contains(got, "len=") || !strings.Contains(got, "sha=") {
		t.Fatalf("MessageContent shape wrong: %q", got)
	}
}

func TestMessageContentReveal(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	if MessageContent("hi") != "hi" {
		t.Fatal("MessageContent Reveal=1 should passthrough")
	}
}

func TestEvidence(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	got := Evidence("before 4155551234 after", 7, 17)
	if strings.Contains(got, "4155551234") {
		t.Fatalf("Evidence leaked: %q", got)
	}
	if !strings.Contains(got, "match=[7:17]") {
		t.Fatalf("Evidence match range missing: %q", got)
	}
}

func TestEvidenceNoRange(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	got := Evidence("text", -1, -1)
	if strings.Contains(got, "match=") {
		t.Fatalf("Evidence should omit match range when unspecified: %q", got)
	}
}

func TestEvidenceIdempotent(t *testing.T) {
	once := ForSinkEvidence("4155551234", 0, 10)
	twice := ForSinkEvidence(once, 0, 10)
	if once != twice {
		t.Fatalf("Evidence not idempotent: %q -> %q", once, twice)
	}
}

func TestReason(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	tests := []struct {
		name          string
		in            string
		shouldContain []string
		shouldNot     []string
	}{
		{
			name:          "rule id with literal",
			in:            "pii.phone: matched 4155551234",
			shouldContain: []string{"pii.phone:"},
			shouldNot:     []string{"4155551234"},
		},
		{
			name:          "multiple clauses",
			in:            "pii.phone: 4155551234; pii.email: foo@bar.com",
			shouldContain: []string{"pii.phone", "pii.email"},
			shouldNot:     []string{"4155551234", "foo@bar.com"},
		},
		{
			name:          "key=value safe",
			in:            "direction=prompt action=allow severity=HIGH",
			shouldContain: []string{"direction=prompt", "action=allow", "severity=HIGH"},
		},
		{
			name:          "key=value unsafe value",
			in:            "args.recipient=4155551234",
			shouldContain: []string{"args.recipient=<redacted"},
			shouldNot:     []string{"4155551234"},
		},
		{
			name:          "bare word in whitespace run",
			in:            "matched hello world",
			shouldContain: []string{"<redacted"},
			shouldNot:     []string{"matched hello world"},
		},
		{
			name:          "long numeric rejected as key value",
			in:            "count=42 number=4155551234",
			shouldContain: []string{"count=42", "number=<redacted"},
			shouldNot:     []string{"4155551234"},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := Reason(tc.in)
			for _, want := range tc.shouldContain {
				if !strings.Contains(got, want) {
					t.Errorf("Reason(%q) = %q; missing %q", tc.in, got, want)
				}
			}
			for _, notWant := range tc.shouldNot {
				if strings.Contains(got, notWant) {
					t.Errorf("Reason(%q) = %q; should not contain %q", tc.in, got, notWant)
				}
			}
		})
	}
}

func TestReasonIdempotent(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	once := Reason("pii.phone: matched 4155551234")
	twice := Reason(once)
	if once != twice {
		t.Fatalf("Reason not idempotent:\n  once = %q\n  twice= %q", once, twice)
	}
}

func TestReasonReveal(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	in := "pii.phone: 4155551234"
	if Reason(in) != in {
		t.Fatal("Reason Reveal=1 should passthrough")
	}
}

func TestForSinkReasonBypassesReveal(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	got := ForSinkReason("pii.phone: 4155551234")
	if strings.Contains(got, "4155551234") {
		t.Fatalf("ForSinkReason leaked under reveal: %q", got)
	}
}

// TestForSinkReason_SecretShapes pins the high-severity bypasses
// turned up in the Phase 4 review. These strings all look like
// `<rule-id>:<literal>` where the literal would previously slip
// through because it happened to share the rule-id charset with
// the catalog identifiers. The sink barrier must redact each
// literal while preserving the rule-id prefix that operators
// rely on for triage.
func TestForSinkReason_SecretShapes(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	cases := []struct {
		name string
		in   string
		keep []string // substrings that MUST appear in the redacted form
		leak []string // substrings that MUST NOT appear
	}{
		{
			name: "aws access key by rule id",
			in:   "SEC-AWS:AKIAIOSFODNN7EXAMPLE",
			keep: []string{"SEC-AWS", "<redacted"},
			leak: []string{"AKIAIOSFODNN7EXAMPLE"},
		},
		{
			name: "bare alphanumeric secret token",
			in:   "MySecretP4ssword",
			keep: []string{"<redacted"},
			leak: []string{"MySecretP4ssword"},
		},
		{
			name: "openai short project key",
			in:   "SEC-OPENAI:sk-proj-abcdefghij1234567",
			keep: []string{"SEC-OPENAI", "<redacted"},
			leak: []string{"sk-proj-abcdefghij1234567"},
		},
		{
			name: "partial-redacted carrier concatenated with new literal",
			// Attacker-style carrier: a string that already
			// contains a placeholder and a fresh literal.
			// The fresh literal must be scrubbed.
			in:   "PII-SECRET:<redacted len=10 sha=abc12345>; AnotherLiteralPayload",
			keep: []string{"PII-SECRET", "<redacted"},
			leak: []string{"AnotherLiteralPayload"},
		},
		{
			name: "matched wrapper preserves inner rule ids",
			in:   "matched: SEC-AWS-KEY:AWS access key, SEC-ANTHROPIC:Anthropic API key",
			keep: []string{"SEC-AWS-KEY", "SEC-ANTHROPIC", "matched"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := ForSinkReason(tc.in)
			for _, want := range tc.keep {
				if !strings.Contains(got, want) {
					t.Errorf("ForSinkReason(%q) = %q; missing %q", tc.in, got, want)
				}
			}
			for _, noLeak := range tc.leak {
				if strings.Contains(got, noLeak) {
					t.Errorf("ForSinkReason(%q) = %q; leaked %q", tc.in, got, noLeak)
				}
			}
		})
	}
}

// TestIsPlaceholder_Narrow pins the hardened idempotency check — a
// string that is only cosmetically wrapped in `<redacted…>` must
// not be honored as already-redacted.
func TestIsPlaceholder_Narrow(t *testing.T) {
	safe := []string{
		"<empty>",
		"<redacted len=10>",
		"<redacted len=32 sha=abcdef12>",
		"<redacted-evidence len=512 match=[3:20] sha=deadbeef>",
	}
	for _, s := range safe {
		if !isPlaceholder(s) {
			t.Errorf("isPlaceholder(%q) = false; want true", s)
		}
	}
	spoofs := []string{
		"<redacted len=10 sha=abc><script>alert(1)</script>",
		"<redacted " + strings.Repeat("A", 200) + ">",
		"<redacted\nlen=5>",
		"<redacted len=5> + extra",
	}
	for _, s := range spoofs {
		if isPlaceholder(s) {
			t.Errorf("isPlaceholder(%q) = true; want false (spoofed)", s)
		}
	}
}

// TestForSinkEntity_ShortValuesHideFirstRune ensures short entities
// (< entityPrefixRevealMinBytes bytes) do not leak their first
// character. 6-8 byte secrets are narrow enough that a single
// character is a meaningful fraction of the value.
func TestForSinkEntity_ShortValuesHideFirstRune(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	for _, in := range []string{"secret", "Abcdef1", "P4ssword"} {
		got := ForSinkEntity(in)
		if strings.Contains(got, "prefix=") {
			t.Errorf("ForSinkEntity(%q) = %q; leaked first rune", in, got)
		}
		if strings.Contains(got, in) {
			t.Errorf("ForSinkEntity(%q) = %q; leaked value", in, got)
		}
	}
	// Long enough to include the rune preview.
	got := ForSinkEntity("carol@example.com")
	if !strings.Contains(got, `prefix="c"`) {
		t.Errorf("ForSinkEntity long = %q; expected prefix", got)
	}
}

// TestIsPlaceholder_SpoofedFakeRedaction pins the
// `<redacted secret>` and `<redacted-evidence secret>` spoof
// rejection. The pre-fix grammar used a loose prefix/suffix check
// that treated any `<redacted...>` shape as already-safe; the
// strict grammar requires len= and sha= fields to match.
func TestIsPlaceholder_SpoofedFakeRedaction(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	spoofs := []string{
		"<redacted sk-ant-secret>",
		"<redacted alice@example.com>",
		"<redacted len=10>extra",
		"<redacted len=10 sha=zzzzzzzz>",     // sha not hex
		"<redacted len=10 sha=ABCDEF12>",     // sha not lowercase hex
		"<redacted len=foo sha=abcdef12>",    // len not numeric
		"<redacted-evidence sk-ant-secret>",  // missing len/sha
		"<redacted-evidence len=10>",         // missing sha
		"<redacted-evidence len=10 sha=zzz>", // sha wrong shape
	}
	for _, s := range spoofs {
		if isPlaceholder(s) {
			t.Errorf("isPlaceholder(%q) = true; want false (spoofed)", s)
		}
		if isEvidencePlaceholder(s) {
			t.Errorf("isEvidencePlaceholder(%q) = true; want false (spoofed)", s)
		}
		// ForSinkString MUST re-redact the spoof so the secret
		// suffix never reaches a persistent sink intact.
		got := ForSinkString(s)
		if got == s {
			t.Errorf("ForSinkString(%q) returned spoof unchanged", s)
		}
	}
	// ForSinkEvidence must also re-redact spoofed evidence shapes.
	got := ForSinkEvidence("<redacted-evidence sk-ant-secret>", -1, -1)
	if strings.Contains(got, "sk-ant-secret") {
		t.Errorf("ForSinkEvidence leaked spoofed input: %q", got)
	}
}

// TestForSinkReason_SeparatorSecretShapes pins the contract:
// short separator-bearing credentials must be redacted, not
// preserved by the safe-token allow-list.
func TestForSinkReason_SeparatorSecretShapes(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	cases := []struct {
		in   string
		leak []string
	}{
		{in: "sk-test-123", leak: []string{"sk-test-123"}},
		{in: "password=hunter-2", leak: []string{"hunter-2"}},
		{in: "api_key=dev/token", leak: []string{"dev/token"}},
		{in: "session=abc.def", leak: []string{"abc.def"}},
		{in: "token=AKIAIOSFODNN7EXAMPLE", leak: []string{"AKIAIOSFODNN7EXAMPLE"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			got := ForSinkReason(tc.in)
			for _, leak := range tc.leak {
				if strings.Contains(got, leak) {
					t.Errorf("ForSinkReason(%q) = %q; leaked %q", tc.in, got, leak)
				}
			}
			if !strings.Contains(got, "<redacted") {
				t.Errorf("ForSinkReason(%q) = %q; missing redacted marker", tc.in, got)
			}
		})
	}
}

// TestForSinkReason_PositiveCatalog pins the well-known enum
// constants and canonical-ID shapes that MUST continue to pass
// through verbatim so operator-facing reasons stay readable.
func TestForSinkReason_PositiveCatalog(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	cases := []string{
		"action=allow",
		"mode=observe",
		"severity=HIGH",
		"verdict=block",
		"canonical=SEC-AWS-KEY",
		"canonical=SEC-AWS-KEY,SEC-GITHUB-TOKEN",
		"count=42",
		"exit_code=0",
		"direction=prompt",
		"scanner=codeguard",
		"connector=openclaw",
		"rule=pii.phone",
	}
	for _, in := range cases {
		got := ForSinkReason(in)
		if got != in {
			t.Errorf("ForSinkReason(%q) = %q; want unchanged", in, got)
		}
	}
}

func TestDeterministicHash(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	a := String("4155551234")
	b := String("4155551234")
	if a != b {
		t.Fatalf("hash not deterministic: %q vs %q", a, b)
	}
	c := String("4155551235")
	if a == c {
		t.Fatalf("hash collided across distinct inputs: %q == %q", a, c)
	}
}

// TestForSinkReason_TrustedAIDPrefix pins the whitelist behavior for
// the "Cisco AI Defense: <rule>" reason shape emitted by the AID
// normalizer (see internal/gateway/cisco_inspect.go). Redaction must
// leave those reasons intact so operators + agent-side surfaces
// display the cloud rule name; otherwise Codex/Claude/etc. show a
// wall of <redacted len=... sha=...> tokens for what are actually
// hand-authored, ship-controlled labels.
func TestForSinkReason_TrustedAIDPrefix(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	SetDisableAll(false)
	t.Cleanup(func() { SetDisableAll(false) })
	cases := []struct {
		in   string
		want string
	}{
		{"Cisco AI Defense: Prompt Injection", "Cisco AI Defense: Prompt Injection"},
		{"Cisco AI Defense: PII Detection", "Cisco AI Defense: PII Detection"},
		{"Cisco AI Defense: Prompt Injection, Jailbreak", "Cisco AI Defense: Prompt Injection, Jailbreak"},
		{"Cisco AI Defense custom policy block", "Cisco AI Defense custom policy block"},
	}
	for _, tc := range cases {
		got := ForSinkReason(tc.in)
		if got != tc.want {
			t.Errorf("ForSinkReason(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestForSinkReason_TrustedAIDPrefix_RejectsBadShapes verifies the
// whitelist is narrow: any user-controllable content after "Cisco AI
// Defense: " that contains characters outside the catalog charset
// (letters/digits/space/hyphen/underscore/comma/period/&) must still
// be redacted. Prevents a prompt injection like
// "Cisco AI Defense: sk-ant-<literal secret>" from riding through.
func TestForSinkReason_TrustedAIDPrefix_RejectsBadShapes(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	SetDisableAll(false)
	t.Cleanup(func() { SetDisableAll(false) })
	badShapes := []string{
		"Cisco AI Defense: sk-ant-api03-secret-KEY_XYZ!!!", // '!' rejected
		"Cisco AI Defense: /etc/passwd content leaked",     // '/' rejected
		"Cisco AI Defense: some=key value",                 // '=' rejected
		"Cisco AI Defense:noSpace",                         // wrong shape (no ": ")
		"NotCisco AI Defense: Prompt Injection",            // wrong prefix
	}
	for _, in := range badShapes {
		got := ForSinkReason(in)
		if got == in {
			t.Errorf("ForSinkReason(%q) MUST have redacted, but got the input verbatim", in)
		}
	}
}
