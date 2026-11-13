// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestTrustedActionSendToolName(t *testing.T) {
	for tool, want := range map[string]bool{
		"mcp__bench__send_email":    true,
		"mcp__mail__send":           true,
		"mcp__slack__post_message":  true,
		"slack.publish":             true,
		"mcp__x__forward_message":   true,
		"mcp__bench__get_email":     false,
		"mcp__mail__read_inbox":     false,
		"mcp__mail__search_emails":  false,
		"mcp__mail__list_messages":  false,
		"mcp__bench__create_entity": false,
		"Bash":                      false,
		"Write":                     false,
		"mcp__mail__draft_email":    false,
	} {
		if got := trustedActionSendToolName(tool); got != want {
			t.Errorf("trustedActionSendToolName(%q) = %v, want %v", tool, got, want)
		}
	}
}

func TestOutboundPIIFindingsAlertOnLabelledCardAndPassport(t *testing.T) {
	card := runtimeDetectorSignature("4237-4252", "-7456-2574")
	for _, test := range []struct {
		name  string
		tool  string
		args  map[string]any
		rules []string
	}{
		{"plain fields", "mcp__bench__send_email",
			map[string]any{"recipients": []any{"hotel@booking.example"}, "subject": "Travel", "body": "Passport Number: HGK137803\nCredit Card Number: " + card},
			[]string{"PII-CARD-LABELED", "PII-PASSPORT-LABELED"}},
		{"dict rendering", "mcp__bench__send_email",
			map[string]any{"body": "{'First Name': 'Emma', 'Passport Number': 'HGK137803', 'Credit Card Number': '" + card + "'}"},
			[]string{"PII-CARD-LABELED", "PII-PASSPORT-LABELED"}},
		{"inline", "mcp__slack__post_message",
			map[string]any{"text": "Passport Number: HGK137803, Credit Card Number: " + card},
			[]string{"PII-CARD-LABELED", "PII-PASSPORT-LABELED"}},
		{"passport only", "mcp__bench__send_email", map[string]any{"body": "passport no. 561234789 attached"}, []string{"PII-PASSPORT-LABELED"}},
		{"not a send tool", "mcp__bench__get_email", map[string]any{"body": "Passport Number: HGK137803"}, nil},
		{"a file write", "Write", map[string]any{"content": "Passport Number: HGK137803"}, nil},
		{"unlabelled digits", "mcp__bench__send_email", map[string]any{"body": "Order 4237425274562574 shipped, tracking HGK137803"}, nil},
		{"label without value", "mcp__bench__send_email", map[string]any{"body": "Please send your passport number and credit card number."}, nil},
		{"passport word in prose", "mcp__bench__send_email", map[string]any{"body": "Your passport expires soon, renew it."}, nil},
		{"uuid glued digits", "mcp__bench__send_email", map[string]any{"body": "Credit card number: 5b6c1a2e-4237425274562574-ff"}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.args)
			if err != nil {
				t.Fatal(err)
			}
			findings := outboundPIIFindings(trustedActionRequest{
				Input:              actionfacts.Input{Tool: test.tool, Args: raw},
				EnforcementCapable: true,
			}, nil)
			got := map[string]bool{}
			for _, finding := range findings {
				got[finding.RuleID] = true
				if !finding.contributesToAlertOnly() || finding.contributesToEnforcement() {
					t.Errorf("%s is not alert-only", finding.RuleID)
				}
				if finding.Evidence != "" {
					t.Errorf("%s carries evidence text", finding.RuleID)
				}
			}
			if len(got) != len(test.rules) {
				t.Fatalf("rules = %v, want %v", got, test.rules)
			}
			for _, rule := range test.rules {
				if !got[rule] {
					t.Fatalf("rules = %v, want %v", got, test.rules)
				}
			}
		})
	}
}
