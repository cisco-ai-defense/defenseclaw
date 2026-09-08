// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestEvaluateDeterministicActionUsesProductionProofBoundary(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantAction string
		wantRule   string
		wantRoute  string
	}{
		{
			name:       "destructive action blocks",
			command:    "rm -rf /",
			wantAction: "block",
			wantRule:   "CMD-RM-RF",
			wantRoute:  "semantic",
		},
		{
			name:       "quoted command is inert",
			command:    "printf '%s\\n' 'rm -rf /'",
			wantAction: "allow",
			wantRoute:  "none",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := EvaluateDeterministicAction(
				context.Background(),
				actionfacts.Input{
					Tool:        "shell",
					Command:     test.command,
					CWD:         "/repo",
					ActiveHome:  "/home/alice",
					DialectHint: actionfacts.DialectPOSIX,
				},
				test.command,
				"",
				"default",
			)
			if got.Action != test.wantAction || got.Route != test.wantRoute {
				t.Fatalf("action=%q route=%q findings=%+v", got.Action, got.Route, got.Findings)
			}
			if test.wantRule != "" && !slices.Contains(got.RuleIDs, test.wantRule) {
				t.Fatalf("rule IDs=%v, want %q", got.RuleIDs, test.wantRule)
			}
			if got.ParseStatus == "" || got.Dialect == "" {
				t.Fatalf("missing value-free parser state: %+v", got)
			}
		})
	}
}

func TestEvaluateDeterministicTextSpansAreValueFreeAndValidated(t *testing.T) {
	content := "patient ssn 731-42-8065"
	spans := EvaluateDeterministicTextSpans(content)
	if len(spans) != 1 {
		t.Fatalf("spans=%+v, want one deduplicated production match", spans)
	}
	if got := content[spans[0].Start:spans[0].End]; got != "731-42-8065" {
		t.Fatalf("span points to %q", got)
	}
	if spans[0].RuleID != "ENT-BULK-SSN" {
		t.Fatalf("rule ID=%q", spans[0].RuleID)
	}
	if got := EvaluateDeterministicTextSpans("public placeholder 123-45-6789"); len(got) != 0 {
		t.Fatalf("placeholder spans=%+v, want none", got)
	}
}

func TestEvaluateDeterministicTextSpansReturnsEveryAcceptedMatch(t *testing.T) {
	first := alertFatiguePAN(t, "47", 16)
	second := alertFatiguePAN(t, "48", 16)
	content := "cards " + first + " and " + second
	spans := EvaluateDeterministicTextSpans(content)
	if len(spans) != 2 {
		t.Fatalf("spans=%+v, want both valid Visa values", spans)
	}
	for _, span := range spans {
		if span.RuleID != "ENT-CC-VISA" {
			t.Fatalf("unexpected rule ID %q", span.RuleID)
		}
	}
}

func TestEvaluateDeterministicSeparatesPIIContentFromActionIntent(t *testing.T) {
	connector := "benchmark-pii-action-isolation"
	pack := mustLoadRulePack(t, guardrailPoliciesRoot(t)+"/default")
	if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
		t.Fatalf("apply connector rule pack: %v", err)
	}
	defer RemoveConnectorRulePackOverrides(connector)

	command := "printf '%s\\n' analyst@example.com"
	for _, profile := range []string{"default", "permissive", "strict"} {
		got := EvaluateDeterministicAction(
			context.Background(),
			actionfacts.Input{
				Tool:        "shell",
				Command:     command,
				CWD:         "/repo",
				ActiveHome:  "/home/alice",
				DialectHint: actionfacts.DialectPOSIX,
			},
			command,
			connector,
			profile,
		)
		if slices.Contains(got.RuleIDs, "ENT-EMAIL-BULK") {
			t.Fatalf("profile %s treated content PII as action intent: %+v", profile, got)
		}
	}
}
