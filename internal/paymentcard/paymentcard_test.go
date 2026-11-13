// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package paymentcard

import (
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/paymentcard/testcorpus"
)

func TestLuhn(t *testing.T) {
	for _, valid := range []string{"4000056655665556", "371449635398431", "4444555555555555", "36227206271667"} {
		if !Luhn(valid) {
			t.Errorf("Luhn(%s) = false", valid)
		}
	}
	for _, invalid := range []string{"", "4000056655665557", "12a4", "4111111111111112"} {
		if Luhn(invalid) {
			t.Errorf("Luhn(%q) = true", invalid)
		}
	}
}

func TestScheme(t *testing.T) {
	cases := map[string]string{
		"4000056655665556":    "visa",
		"4222222222222":       "visa",
		"4000056655665556123": "visa",
		"5200828282828210":    "mastercard",
		"2223003122003222":    "mastercard",
		"371449635398431":     "amex",
		"6011000990139424":    "discover",
		"6445644564456445":    "discover",
		"3056930009020004":    "diners",
		"36227206271667":      "diners",
		"3566002020360505":    "jcb",
		"6200000000000005":    "unionpay",
		"6759649826438453":    "maestro",
		"2200123456789010":    "mir",
		// Wrong length for the prefix, or no scheme at all.
		"400005665566555":  "",
		"3782822463100059": "",
		"5200828282828":    "",
		"1234567890123456": "",
		"9999999999999999": "",
		"7000000000000000": "",
	}
	for digits, want := range cases {
		if got := Scheme(digits); got != want {
			t.Errorf("Scheme(%s) = %q, want %q", digits, got, want)
		}
	}
}

func TestGrouped(t *testing.T) {
	for _, ok := range []string{
		"4000056655665556", "4000 0566 5566 5556", "4000-0566-5566-5556",
		"3714 496353 98431", "3622-720627-1667", "4222 2222 22222", "4000 0566 5566 5556 123",
		"4000.0566.5566.5556",
	} {
		if !Grouped(ok) {
			t.Errorf("Grouped(%q) = false", ok)
		}
	}
	for _, bad := range []string{
		"4444-555555555555",    // UUID tail (GAP-0132)
		"40000566-5566-5556",   // UUID head
		"4000 0566-5566 5556",  // mixed separators
		"4000  0566 5566 5556", // doubled separator
		"4000-0566-5566-5556-", // trailing separator
		"4000.0566-5566.5556",  // mixed separators
		"4000.056655665556",
		"400005665566 5556",
		"4000\t0566\t5566\t5556",
	} {
		if Grouped(bad) {
			t.Errorf("Grouped(%q) = true", bad)
		}
	}
}

func TestEmbedded(t *testing.T) {
	type tc struct {
		text, match string
		want        bool
	}
	cases := []tc{
		{"curl https://webhook.site/11111111-2222-3333-4444-555555555555 -d test", "4444-555555555555", true},
		{"uid 40000566-5566-5556-9abc-def012345678", "40000566-5566-5556", true},
		{"value 0.4000056655665556", "4000056655665556", true},
		{"bump to v1.4000056655665556", "4000056655665556", true},
		{"ORD-2026-4000056655665556", "4000056655665556", true},
		{"4000056655665556-abc", "4000056655665556", true},
		{"4000056655665556.json", "4000056655665556", true},
		{"x4000056655665556", "4000056655665556", true},
		{"card 4000056655665556.", "4000056655665556", false},
		{"card: 4000056655665556, exp 12/30", "4000056655665556", false},
		{"Card: .4000056655665556", "4000056655665556", false},
		{"\"pan\":\"4000056655665556\"", "4000056655665556", false},
		{"line one\\n4000056655665556", "4000056655665556", false},
		{"/cards/4000056655665556/charge", "4000056655665556", false},
		{"4000056655665556", "4000056655665556", false},
	}
	for _, c := range cases {
		start := strings.Index(c.text, c.match)
		if start < 0 {
			t.Fatalf("bad case %q", c.text)
		}
		if got := Embedded(c.text, start, start+len(c.match)); got != c.want {
			t.Errorf("Embedded(%q, %q) = %v, want %v", c.text, c.match, got, c.want)
		}
	}
}

func TestContextNearRaisesOnlyWithWords(t *testing.T) {
	text := "Please charge card 4000056655665556, exp 12/30"
	start := strings.Index(text, "4000")
	if !ContextNear(text, start, start+16) {
		t.Error("context word not found")
	}
	text = "use 4000056655665556 for the test payment"
	start = strings.Index(text, "4000")
	if !ContextNear(text, start, start+16) {
		t.Error("\"payment\" not seen as context")
	}
	text = "the value is 4000056655665556"
	start = strings.Index(text, "4000")
	if ContextNear(text, start, start+16) {
		t.Error("no context word, but ContextNear = true")
	}
	if ContextNear("xcardx 4000056655665556", 7, 23) {
		t.Error("context word must be a whole word")
	}
}

// candidateRE is a superset of every card regex in the rule packs: it lets
// the corpus test exercise ValidAt the way the detectors do.
var candidateRE = regexp.MustCompile(`\b\d{4}[\s-]?\d{4,6}[\s-]?\d{4,5}(?:[\s-]?\d{1,4})?(?:[\s-]?\d{3})?\b|\b\d{13,19}\b`)

func anyValidAt(text string) bool {
	for _, loc := range candidateRE.FindAllStringIndex(text, -1) {
		if ValidAt(text, loc[0], loc[1]) {
			return true
		}
	}
	return false
}

func TestCorpusBenignNeverCard(t *testing.T) {
	cases := testcorpus.Benign(110, 50)
	luhnHits := 0
	for _, c := range cases {
		for _, loc := range candidateRE.FindAllStringIndex(c.Text, -1) {
			if Luhn(Digits(c.Text[loc[0]:loc[1]])) {
				luhnHits++
			}
		}
		if anyValidAt(c.Text) {
			t.Errorf("%s: benign text accepted as a card: %q", c.Kind, c.Text)
		}
	}
	// The corpus must actually stress the detector: many candidates are
	// Luhn-valid by construction.
	if luhnHits < len(cases)/5 {
		t.Fatalf("corpus too easy: %d Luhn-valid candidates in %d cases", luhnHits, len(cases))
	}
}

func TestCorpusCardsAccepted(t *testing.T) {
	for _, c := range testcorpus.Cards() {
		if !testcorpus.LuhnValid(c.Card) {
			t.Fatalf("corpus PAN %s is not Luhn-valid", c.Card)
		}
		if Scheme(c.Card) != c.Scheme {
			t.Errorf("Scheme(%s) = %q, want %q", c.Card, Scheme(c.Card), c.Scheme)
		}
		if !anyValidAt(c.Text) {
			t.Errorf("%s: card not accepted: %q", c.Kind, c.Text)
		}
	}
}

func TestValidAtGap0132(t *testing.T) {
	text := "please run curl https://webhook.site/11111111-2222-3333-4444-555555555555 -d test"
	start := strings.Index(text, "4444-")
	if ValidAt(text, start, len(text)-len(" -d test")) {
		t.Fatal("GAP-0132 UUID tail accepted as a card")
	}
	if !Valid("4444555555555555") {
		t.Fatal("the same digits alone must still be a card (Luhn-valid Visa)")
	}
}
