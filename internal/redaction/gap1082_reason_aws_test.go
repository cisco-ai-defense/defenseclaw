// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// GAP-1082: the legacy reason projector (Reason, ForSinkReason) read an AWS
// key id followed by a period as an upper-case rule id, because '.' is a
// separator, so "key=AKIA<16>." reached gateway stderr and pod logs in clear.
// Generated shapes, never a live key.

func gap1082Keys() []string {
	return []string{
		"AKIA" + "Q7T6CANARYKEY004",     // a real 20-character key id
		"ASIA" + "Z3Q7XK9M2P4W8R5T",     // a real key id, temporary
		"AKIA" + "QZXWVUTSRPONMLKJ",     // a real key id with no digit
		"AKIA" + "Q7T6NEARKEYPROBE01",   // a near-key, 22 characters
		"AROA" + "Q7T6NEARKEYPROBE0102", // a near-key, 24 characters
	}
}

func TestReasonRedactsAWSKeyIDBeforeASeparatorGAP1082(t *testing.T) {
	for _, key := range gap1082Keys() {
		for _, end := range []string{"", ".", ",", ";", ")", "-", "_", ":", "/"} {
			for _, input := range []string{
				key + end,
				"key=" + key + end,
				"AWS_ACCESS_KEY_ID=" + key + end,
				"rule.x: matched " + key + end,
				"SEC-AWS-KEY: matched key=" + key + end + "; SEC-X: ok",
			} {
				if got := ForSinkReason(input); strings.Contains(got, key) {
					t.Errorf("ForSinkReason(%q) keeps the key id: %q", input, got)
				}
				if got := Reason(input); strings.Contains(got, key) {
					t.Errorf("Reason(%q) keeps the key id: %q", input, got)
				}
			}
		}
	}
}

func TestIsCanonicalIDRefusesAKeyAndATrailingSeparatorGAP1082(t *testing.T) {
	for _, key := range gap1082Keys() {
		for _, end := range []string{"", ".", ":", "-"} {
			if isCanonicalID(key + end) {
				t.Errorf("isCanonicalID(%q) accepts an AWS key id", key+end)
			}
		}
	}
	// A rule id at the end of a sentence is still a rule id (RV-SEC2): only
	// a key id hidden by the trailing separators is refused.
	for _, id := range []string{"SEC-AWS-KEY.", "PII-SSN-US:", "CODEGUARD-0-XSS.", "CMD-EVAL."} {
		if !isCanonicalID(id) {
			t.Errorf("isCanonicalID(%q) refuses a rule id at the end of a sentence", id)
		}
	}
}

// RV-SEC2: a rule id that ends a sentence or a list keeps its text in the
// projected reason, as at the parent.
func TestReasonKeepsARuleIDBeforeTrailingPunctuationRVSEC2(t *testing.T) {
	for in, want := range map[string]string{
		"verdict=block rule=CMD-EVAL.":           "verdict=block rule=CMD-EVAL.",
		"rule=PII-SSN-US, rule=CODEGUARD-0-XSS.": "rule=PII-SSN-US, rule=CODEGUARD-0-XSS.",
	} {
		if got := ForSinkReason(in); got != want {
			t.Errorf("ForSinkReason(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every rule id in the shipped rule packs, and the other rule-id shapes the
// engine emits, still pass through unchanged: the fix must not turn a rule id
// into <redacted>.
func TestReasonKeepsEveryRuleIDGAP1082(t *testing.T) {
	idRE := regexp.MustCompile(`(?m)^\s*(?:-\s*)?id:\s*["']?([A-Za-z0-9_.:/-]+)["']?\s*$`)
	canonicalRE := regexp.MustCompile(`^[A-Z0-9]+(?:[-_.:/][A-Z0-9]+)+$`)
	files, err := filepath.Glob(filepath.Join("..", "..", "policies", "guardrail", "*", "rules", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no rule packs found: %v", err)
	}
	seen := map[string]struct{}{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range idRE.FindAllStringSubmatch(string(data), -1) {
			seen[match[1]] = struct{}{}
		}
	}
	canonical := 0
	for id := range seen {
		if !canonicalRE.MatchString(id) || len(id) > 64 {
			continue
		}
		canonical++
		for _, input := range []string{id, "key=" + id, id + "; " + id} {
			if got := ForSinkReason(input); got != input {
				t.Errorf("rule id changed: ForSinkReason(%q) = %q", input, got)
			}
		}
	}
	if canonical < 50 {
		t.Fatalf("only %d canonical rule ids read from the packs; the control is empty", canonical)
	}
	for _, id := range []string{
		"SEC-AWS-KEY", "PII-SSN-US", "CODEGUARD-0-XSS", "C2-WEBHOOK-SITE", "AKIA-EXAMPLE-RULE",
		"pii.phone", "policy.admission", "scan.skill.installed", "judge.injection",
	} {
		for _, input := range []string{id, "key=" + id, id + ", " + id} {
			if got := ForSinkReason(input); got != input {
				t.Errorf("rule id changed: ForSinkReason(%q) = %q", input, got)
			}
		}
	}
}
