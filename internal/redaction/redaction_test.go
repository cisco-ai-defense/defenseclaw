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
