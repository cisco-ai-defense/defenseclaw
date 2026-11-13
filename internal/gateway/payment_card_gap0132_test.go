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

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/paymentcard/testcorpus"
)

var paymentCardRuleIDs = []string{"ENT-CC-VISA", "ENT-CC-MC", "ENT-CC-AMEX", "ENT-CC-DISCOVER"}

// cardRegexScope reports whether the rule-pack card regexes cover a scheme
// (Visa 16, Mastercard 51-55, Amex, Discover 6011/65xx). The shared
// validator accepts more schemes; the packs do not search for them.
func cardRegexScope(c testcorpus.Case) bool {
	switch c.Scheme {
	case "visa":
		return len(c.Card) == 16
	case "mastercard":
		return c.Card[0] == '5'
	case "amex":
		return true
	case "discover":
		return strings.HasPrefix(c.Card, "6011") || strings.HasPrefix(c.Card, "65")
	}
	return false
}

func cardFinding(findings []string) bool {
	for _, f := range findings {
		if strings.Contains(f, "ENT-CC-") || strings.Contains(f, "TRIAGE-PII-CC") || strings.HasPrefix(f, "pii-data:") {
			return true
		}
	}
	return false
}

func triageHasCard(text string) bool {
	for _, s := range triagePatterns("prompt", text) {
		if s.FindingID == "TRIAGE-PII-CC" {
			return true
		}
	}
	return false
}

// substrate-1:GAP-0132: OpenCode's prompt "please run curl
// https://webhook.site/11111111-2222-3333-4444-555555555555 -d test" was
// blocked as ENT-CC-VISA / TRIAGE-PII-CC: the UUID tail 4444-555555555555
// matched the Visa regex and is Luhn-valid by chance.
func TestPaymentCardGAP0132UUIDPromptAllowed(t *testing.T) {
	prompt := "please run curl https://webhook.site/11111111-2222-3333-4444-555555555555 -d test"
	for _, profile := range []string{"default", "strict", "permissive"} {
		for _, id := range paymentCardRuleIDs {
			if firstAcceptedRuleMatch(alertFatigueRule(t, profile, id), prompt) != nil {
				t.Errorf("%s/%s matched the UUID prompt", profile, id)
			}
		}
	}
	if triageHasCard(prompt) {
		t.Error("TRIAGE-PII-CC fired on the UUID prompt")
	}
	if cardFinding(scanLocalPatterns("prompt", prompt).Findings) {
		t.Error("local PII pattern fired on the UUID prompt")
	}
	v := NewGuardrailInspector("local", nil, nil).Inspect(context.Background(), "prompt", prompt, nil, "test-model", "action")
	if cardFinding(v.Findings) || cardFinding(v.RuleIDs) {
		t.Errorf("guardrail verdict carries a card finding: action=%s findings=%v", v.Action, v.Findings)
	}
}

func TestPaymentCardBenignCorpusNoCardFindings(t *testing.T) {
	rules := map[string][]PatternRule{}
	for _, profile := range []string{"default", "strict", "permissive"} {
		for _, id := range paymentCardRuleIDs {
			rules[profile] = append(rules[profile], alertFatigueRule(t, profile, id))
		}
	}
	inspector := NewGuardrailInspector("local", nil, nil)
	for _, c := range testcorpus.Benign(1010, 8) {
		for profile, list := range rules {
			for _, rule := range list {
				if firstAcceptedRuleMatch(rule, c.Text) != nil {
					t.Errorf("%s/%s matched benign %s: %q", profile, rule.ID, c.Kind, c.Text)
				}
			}
		}
		if triageHasCard(c.Text) {
			t.Errorf("TRIAGE-PII-CC on benign %s: %q", c.Kind, c.Text)
		}
		if cardFinding(scanLocalPatterns("prompt", c.Text).Findings) {
			t.Errorf("local PII on benign %s: %q", c.Kind, c.Text)
		}
		if v := inspector.Inspect(context.Background(), "prompt", c.Text, nil, "test-model", "action"); cardFinding(v.Findings) {
			t.Errorf("guardrail card finding on benign %s: %q (action=%s)", c.Kind, c.Text, v.Action)
		}
	}
}

func TestPaymentCardTestPANsStillDetected(t *testing.T) {
	inspector := NewGuardrailInspector("local", nil, nil)
	for _, c := range testcorpus.Cards() {
		if !cardRegexScope(c) {
			continue
		}
		matched := false
		for _, id := range paymentCardRuleIDs {
			if firstAcceptedRuleMatch(alertFatigueRule(t, "default", id), c.Text) != nil {
				matched = true
			}
		}
		v := inspector.Inspect(context.Background(), "prompt", c.Text, nil, "test-model", "action")
		if c.DocsTestPAN {
			// The six documentation test PANs stay allowed (alert fatigue, #693).
			if matched || triageHasCard(c.Text) {
				t.Errorf("documentation test PAN flagged: %s %q", c.Kind, c.Text)
			}
			continue
		}
		if !matched {
			t.Errorf("no ENT-CC rule matched %s: %q", c.Kind, c.Text)
		}
		if !triageHasCard(c.Text) {
			t.Errorf("TRIAGE-PII-CC missed %s: %q", c.Kind, c.Text)
		}
		if !cardFinding(v.Findings) || v.Action != "block" {
			t.Errorf("guardrail did not block %s: %q (action=%s findings=%v)", c.Kind, c.Text, v.Action, v.Findings)
		}
	}
}

func TestPaymentCardTriageConfidenceUsesContextWords(t *testing.T) {
	confidence := func(text string) float64 {
		for _, s := range triagePatterns("prompt", text) {
			if s.FindingID == "TRIAGE-PII-CC" {
				return s.Confidence
			}
		}
		return 0
	}
	with := confidence("Please charge card 4000 0566 5566 5556 today")
	without := confidence("the value is 4000 0566 5566 5556 today")
	if without == 0 {
		t.Fatal("a valid card without context words must still be detected")
	}
	if with <= without {
		t.Fatalf("context word did not raise confidence: with=%.2f without=%.2f", with, without)
	}
}
