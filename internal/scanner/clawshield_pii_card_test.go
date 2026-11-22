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

package scanner

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/paymentcard/testcorpus"
)

func csCardFindings(text string) []Finding {
	var out []Finding
	for _, f := range csPIIScanContent([]byte(text), "f.txt") {
		if strings.HasPrefix(f.RuleID, "CS-PII-CC-") {
			out = append(out, f)
		}
	}
	return out
}

// substrate-1:GAP-0132: clawshield shares the payment card rules, so a UUID
// or other id never reads as a card, and CS-PII-CC-FMT (any 4-4-4-4 digit
// run) now needs Luhn, a real scheme and token boundaries too.
func TestClawShieldCardBenignCorpus(t *testing.T) {
	for _, c := range testcorpus.Benign(77, 8) {
		if got := csCardFindings(c.Text); len(got) != 0 {
			t.Errorf("%s: %s on benign %q", c.Kind, got[0].RuleID, c.Text)
		}
	}
	for _, text := range []string{
		"id: 11111111-2222-3333-4444-555555555555",
		"build 1234 5678 9012 3456 passed", // 4-4-4-4, no scheme, not Luhn
	} {
		if got := csCardFindings(text); len(got) != 0 {
			t.Errorf("%s on %q", got[0].RuleID, text)
		}
	}
}

func TestClawShieldCardTestPANs(t *testing.T) {
	for _, text := range []string{
		"card = \"4000056655665556\"",
		"card = \"4000 0566 5566 5556\"",
		"card = \"5200-8282-8282-8210\"",
		"amex: 371449635398431",
		"discover 6011000990139424",
	} {
		if got := csCardFindings(text); len(got) == 0 {
			t.Errorf("no card finding on %q", text)
		}
	}
}
