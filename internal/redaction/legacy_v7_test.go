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

func TestLegacyV7PureHelpersGoldens(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "string empty", got: LegacyV7String(""), want: "<empty>"},
		{name: "string short", got: LegacyV7String("abcd"), want: "<redacted len=4>"},
		{name: "string standard", got: LegacyV7String("hello world"), want: "<redacted len=11 sha=b94d27b9>"},
		{name: "entity empty", got: LegacyV7Entity(""), want: "<empty>"},
		{name: "entity short", got: LegacyV7Entity("abcd"), want: "<redacted len=4>"},
		{name: "entity middle", got: LegacyV7Entity("abcdef"), want: "<redacted len=6 sha=bef57ec7>"},
		{name: "entity long", got: LegacyV7Entity("hello world"), want: `<redacted len=11 prefix="h" sha=b94d27b9>`},
		{name: "content empty", got: LegacyV7MessageContent(""), want: "<empty>"},
		{name: "content standard", got: LegacyV7MessageContent("hello world"), want: "<redacted len=11 sha=b94d27b9>"},
		{name: "reason empty", got: LegacyV7Reason(""), want: ""},
		{name: "reason safe enum", got: LegacyV7Reason("action=allow"), want: "action=allow"},
		{name: "reason dynamic value", got: LegacyV7Reason("RULE:hello world"), want: "RULE:<redacted len=11 sha=b94d27b9>"},
		{name: "evidence empty", got: LegacyV7Evidence("", 0, 1), want: "<empty>"},
		{name: "evidence absent coordinates", got: LegacyV7Evidence("hello world", -1, -1), want: "<redacted-evidence len=11 sha=b94d27b9>"},
		{name: "evidence present coordinates", got: LegacyV7Evidence("hello world", 0, 5), want: "<redacted-evidence len=11 match=[0:5] sha=b94d27b9>"},
		{name: "evidence invalid coordinates", got: LegacyV7Evidence("hello world", 5, 5), want: "<redacted-evidence len=11 sha=b94d27b9>"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func TestLegacyV7PureHelpersIgnoreGlobalState(t *testing.T) {
	nestedReason := "matched: SEC-FIXTURE:dynamic explanation"
	whitespaceReason := "user=fixture-user password=FixturePassword123 role=operator"
	wantNested := LegacyV7Reason(nestedReason)
	wantWhitespace := LegacyV7Reason(whitespaceReason)
	if strings.Contains(wantNested, "dynamic explanation") {
		t.Fatalf("nested legacy-v7 reason fixture was not redacted: %q", wantNested)
	}
	if strings.Contains(wantWhitespace, "FixturePassword123") {
		t.Fatalf("whitespace legacy-v7 reason fixture was not redacted: %q", wantWhitespace)
	}
	scenarios := []struct {
		name      string
		revealEnv string
	}{
		{name: "reveal environment", revealEnv: "1"},
		{name: "default", revealEnv: ""},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Setenv(revealEnvVar, scenario.revealEnv)

			tests := []struct {
				name string
				got  string
				want string
			}{
				{name: "string", got: LegacyV7String("hello world"), want: "<redacted len=11 sha=b94d27b9>"},
				{name: "entity", got: LegacyV7Entity("hello world"), want: `<redacted len=11 prefix="h" sha=b94d27b9>`},
				{name: "content", got: LegacyV7MessageContent("hello world"), want: "<redacted len=11 sha=b94d27b9>"},
				{name: "reason", got: LegacyV7Reason("RULE:hello world"), want: "RULE:<redacted len=11 sha=b94d27b9>"},
				{name: "reason nested", got: LegacyV7Reason(nestedReason), want: wantNested},
				{name: "reason whitespace", got: LegacyV7Reason(whitespaceReason), want: wantWhitespace},
				{name: "evidence", got: LegacyV7Evidence("hello world", 0, 5), want: "<redacted-evidence len=11 match=[0:5] sha=b94d27b9>"},
			}

			for _, tc := range tests {
				if tc.got != tc.want {
					t.Fatalf("%s: global state changed pure helper output: got %q, want %q", tc.name, tc.got, tc.want)
				}
			}
		})
	}
}

func TestLegacyV7PureHelpersIdempotenceAndSpoofResistance(t *testing.T) {
	stringOnce := LegacyV7String("hello world")
	if got := LegacyV7String(stringOnce); got != stringOnce {
		t.Fatalf("string helper is not idempotent: %q -> %q", stringOnce, got)
	}

	entityOnce := LegacyV7Entity("hello world")
	if got := LegacyV7Entity(entityOnce); got != entityOnce {
		t.Fatalf("entity helper is not idempotent: %q -> %q", entityOnce, got)
	}

	contentOnce := LegacyV7MessageContent("hello world")
	if got := LegacyV7MessageContent(contentOnce); got != contentOnce {
		t.Fatalf("content helper is not idempotent: %q -> %q", contentOnce, got)
	}

	reasonOnce := LegacyV7Reason("RULE:hello world")
	if got := LegacyV7Reason(reasonOnce); got != reasonOnce {
		t.Fatalf("reason helper is not idempotent: %q -> %q", reasonOnce, got)
	}

	evidenceOnce := LegacyV7Evidence("hello world", 0, 5)
	if got := LegacyV7Evidence(evidenceOnce, 0, 5); got != evidenceOnce {
		t.Fatalf("evidence helper is not idempotent: %q -> %q", evidenceOnce, got)
	}

	spoof := "<redacted arbitrary>"
	if got := LegacyV7String(spoof); got == spoof {
		t.Fatalf("string helper trusted spoofed placeholder %q", spoof)
	}
	if got := LegacyV7Evidence(spoof, -1, -1); got == spoof {
		t.Fatalf("evidence helper trusted spoofed placeholder %q", spoof)
	}
}

func TestLegacyV7SinkWrappersDelegateAtGlobalBoundary(t *testing.T) {
	t.Setenv(revealEnvVar, "1")

	if got, want := ForSinkString("hello world"), LegacyV7String("hello world"); got != want {
		t.Fatalf("ForSinkString = %q, want pure helper output %q", got, want)
	}
	if got, want := ForSinkEntity("hello world"), LegacyV7Entity("hello world"); got != want {
		t.Fatalf("ForSinkEntity = %q, want pure helper output %q", got, want)
	}
	if got, want := ForSinkMessageContent("hello world"), LegacyV7MessageContent("hello world"); got != want {
		t.Fatalf("ForSinkMessageContent = %q, want pure helper output %q", got, want)
	}
	if got, want := ForSinkReason("RULE:hello world"), LegacyV7Reason("RULE:hello world"); got != want {
		t.Fatalf("ForSinkReason = %q, want pure helper output %q", got, want)
	}
	if got, want := ForSinkEvidence("hello world", 0, 5), LegacyV7Evidence("hello world", 0, 5); got != want {
		t.Fatalf("ForSinkEvidence = %q, want pure helper output %q", got, want)
	}

}
