// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// TestGuardrailSecretSpansCoverWhatTheHookFlagsGAP0426: the classifier the
// audit projection uses is the hook's own secret rules; it returns the value
// of a flagged assignment and leaves its key and plain text alone.
func TestGuardrailSecretSpansCoverWhatTheHookFlagsGAP0426(t *testing.T) {
	text := "created\nSERVICE_API_TOKEN=" + gap0426Hex + "\nsee commit " + gap0426SHA
	if findings := ScanAllRules(text, "Write"); !gap0426HasRule(findings, "SEC-HEX-SECRET") {
		t.Fatalf("precondition: the hook does not flag the hex assignment: %v", findings)
	}
	spans := guardrailSecretSpans(text)
	covered := func(value string) bool {
		at := strings.Index(text, value)
		for _, span := range spans {
			if span[0] <= at && at+len(value) <= span[1] {
				return true
			}
		}
		return false
	}
	if !covered(gap0426Hex) {
		t.Fatalf("hex secret not covered by %v", spans)
	}
	for _, span := range spans {
		if span[0] < strings.Index(text, gap0426Hex) {
			t.Fatalf("span %v starts before the value: the key SERVICE_API_TOKEN must stay readable", span)
		}
		if strings.Contains(text[span[0]:span[1]], gap0426SHA) {
			t.Fatalf("span %v covers the git SHA outside a credential context", span)
		}
	}
	if spans := guardrailSecretSpans("see commit " + gap0426SHA + " in rel"); len(spans) != 0 {
		t.Fatalf("plain text flagged: %v", spans)
	}
	// One value matched by several rules (SEC-HEX-SECRET, SEC-SECRET-ASSIGN)
	// is one span, so it costs one match of the field budget.
	if spans := guardrailSecretSpans("SERVICE_API_TOKEN=" + gap0426Hex); len(spans) != 1 {
		t.Fatalf("one value, spans %v", spans)
	}
	if got := mergeAuditSecretSpans([][2]int{{5, 9}, {0, 4}, {3, 6}, {9, 12}}); len(got) != 2 || got[0] != [2]int{0, 9} || got[1] != [2]int{9, 12} {
		t.Fatalf("merge = %v", got)
	}
}

func gap0426HasRule(findings []RuleFinding, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}
