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
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/paymentcard/testcorpus"
)

func emailRulesFor(t *testing.T, root string) []PatternRule {
	t.Helper()
	pack, err := guardrail.LoadRulePack(root)
	if err != nil {
		t.Fatalf("load %s: %v", root, err)
	}
	var out []PatternRule
	for _, file := range pack.RuleFiles {
		for _, rule := range file.Rules {
			if strings.Contains(rule.ID, "EMAIL") && file.Category == "enterprise-data" {
				out = append(out, PatternRule{ID: rule.ID, Pattern: regexp.MustCompile(rule.Pattern), Severity: rule.Severity, Tags: rule.Tags})
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no email rules in %s", root)
	}
	return out
}

func emailMaxSeverity(rules []PatternRule, text string) (string, []string) {
	best, rank := "", 0
	var ids []string
	for _, rule := range rules {
		if firstAcceptedRuleMatch(rule, text) == nil {
			continue
		}
		ids = append(ids, rule.ID)
		if r := guardrailSeverityRank(rule.Severity); r > rank {
			best, rank = rule.Severity, r
		}
	}
	return best, ids
}

func packRoot(profile string) string {
	return filepath.Join("..", "..", "policies", "guardrail", profile)
}

// substrate-1:GAP-0149 / GAP-0159: one address (a vendor no-reply address
// in agent instructions, a git log of many authors) is LOW in every pack, so
// strict alerts and never blocks; five or more distinct addresses together or
// a labeled email field is MEDIUM, so strict blocks and default alerts.
func TestEmailRulesSingleAddressLowListAndFieldMedium(t *testing.T) {
	cases := append(testcorpus.EmailBenign(149, 6), testcorpus.EmailPositive(159, 3)...)
	for _, profile := range []string{"default", "strict", "permissive"} {
		rules := emailRulesFor(t, packRoot(profile))
		for _, c := range cases {
			got, ids := emailMaxSeverity(rules, c.Text)
			if got != c.Want {
				t.Errorf("%s %s: email severity %q (rules %v), want %q", profile, c.Kind, got, ids, c.Want)
			}
		}
	}
	strict := emailRulesFor(t, packRoot("strict"))
	for _, c := range testcorpus.EmailBenign(1149, 6) {
		sev, ids := emailMaxSeverity(strict, c.Text)
		if sev != "" && guardrailFallbackActionForProfile(sev, "strict") == "block" {
			t.Errorf("strict blocks benign %s (rules %v)", c.Kind, ids)
		}
	}
	for _, c := range testcorpus.EmailPositive(1159, 3) {
		sev, ids := emailMaxSeverity(strict, c.Text)
		if guardrailFallbackActionForProfile(sev, "strict") != "block" {
			t.Errorf("strict does not block %s (severity %q, rules %v)", c.Kind, sev, ids)
		}
		if a := guardrailFallbackActionForProfile(sev, "default"); a == "block" {
			t.Errorf("default blocks %s; want alert (balanced defaults)", c.Kind)
		}
	}
}

func TestEmailListNeedsFiveDistinctAddresses(t *testing.T) {
	rule := alertFatigueRule(t, "strict", "PII-EMAIL-LIST")
	four := "a1@corp-mail.test, b2@corp-mail.test, c3@corp-mail.test, d4@corp-mail.test"
	if firstAcceptedRuleMatch(rule, four) != nil {
		t.Error("four addresses matched the list rule")
	}
	if firstAcceptedRuleMatch(rule, strings.Repeat("noreply@anthropic.com ", 12)) != nil {
		t.Error("one address repeated matched the list rule")
	}
	if firstAcceptedRuleMatch(rule, four+", e5@corp-mail.test") == nil {
		t.Error("five distinct addresses did not match the list rule")
	}
	far := "a1@corp-mail.test " + strings.Repeat("x", emailListWindow) + " b2@corp-mail.test c3@corp-mail.test d4@corp-mail.test e5@corp-mail.test f6@corp-mail.test"
	if firstAcceptedRuleMatch(rule, far) == nil {
		t.Error("five addresses after a long gap did not match (window must slide)")
	}
	spread := "a1@corp-mail.test " + strings.Repeat("x", emailListWindow) + " b2@corp-mail.test c3@corp-mail.test d4@corp-mail.test e5@corp-mail.test"
	if firstAcceptedRuleMatch(rule, spread) != nil {
		t.Error("five addresses spread wider than the window matched the list rule")
	}
}

func TestEmailRulesPrivacyHighAssurance(t *testing.T) {
	rules := emailRulesFor(t, filepath.Join("..", "..", "policies", "guardrail-use-cases", "privacy-high-assurance"))
	for _, c := range testcorpus.EmailPositive(7, 1) {
		if sev, ids := emailMaxSeverity(rules, c.Text); sev != "CRITICAL" {
			t.Errorf("privacy-high-assurance %s: severity %q (rules %v), want CRITICAL", c.Kind, sev, ids)
		}
	}
	for _, c := range testcorpus.EmailBenign(7, 1) {
		if sev, ids := emailMaxSeverity(rules, c.Text); sev != "" {
			t.Errorf("privacy-high-assurance benign %s: severity %q (rules %v)", c.Kind, sev, ids)
		}
	}
}

// The stderr diagnostics hashed the static rule title next to the rule id,
// so "ENT-EMAIL-BULK:Email address" logged as a 13-byte "match" that is in
// no request. Rule-pack titles are kept; other text is still redacted.
func TestLogDisplayReasonKeepsRulePackTitles(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	ensureDefaultRuleGeneration()
	for _, reason := range []string{
		"matched: ENT-EMAIL-BULK:Email address",
		"matched: ENT-CC-VISA:Visa credit card number, ENT-EMAIL-BULK:Email address",
		"ENT-EMAIL-BULK:Email address",
	} {
		if got := logDisplayReason(reason); got != reason {
			t.Errorf("logDisplayReason(%q) = %q", reason, got)
		}
	}
	for _, reason := range []string{
		"matched: ENT-EMAIL-BULK:bob@corp-mail.test",
		"matched: SCANNER-X:Title with sk-live-123456",
		"judge: the user pasted alice@corp-mail.test",
	} {
		if got := logDisplayReason(reason); got == reason {
			t.Errorf("logDisplayReason(%q) kept non-rule text", reason)
		}
	}
}

// Review of GAP-0159: a log that repeats one address on every line makes
// every address a list candidate; each candidate reads a bounded window.
func TestEmailListBoundedOnLargeRepeatedLog(t *testing.T) {
	rule := alertFatigueRule(t, "strict", "PII-EMAIL-LIST")
	var b strings.Builder
	for i := 0; b.Len() < 512<<10; i++ {
		fmt.Fprintf(&b, "2026-11-13T00:00:%02dZ INFO login ok user=dana.reyes@contoso-mail.net req=%d\n", i%60, i)
	}
	began := time.Now()
	if firstAcceptedRuleMatch(rule, b.String()) != nil {
		t.Error("one repeated address matched the list rule")
	}
	if elapsed := time.Since(began); elapsed > 20*time.Second {
		t.Errorf("list rule took %s on a 512 KiB log", elapsed)
	}
	t.Logf("512 KiB repeated-address log: %s", time.Since(began))
}
