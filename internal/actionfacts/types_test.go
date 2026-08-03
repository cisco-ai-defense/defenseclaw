// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strconv"
	"testing"
)

func TestFactsAuthoritativeOnlyForCompleteParse(t *testing.T) {
	statuses := []ParseStatus{
		StatusNotApplicable,
		StatusComplete,
		StatusPartial,
		StatusUnsupported,
		StatusInvalid,
		StatusLimitExceeded,
		StatusAmbiguous,
	}
	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			facts := Facts{Parse: ParseResult{Status: status}}
			if got, want := facts.Authoritative(), status == StatusComplete; got != want {
				t.Fatalf("Authoritative() = %t, want %t", got, want)
			}
		})
	}
}

func TestFactsEnforcementEligibilityRequiresExecutedAuthoritativeCommands(t *testing.T) {
	tests := []struct {
		name  string
		facts Facts
		want  bool
	}{
		{
			name: "executed authoritative command",
			facts: Facts{
				Parse:    ParseResult{Status: StatusComplete},
				Commands: []CommandFact{{Effect: EffectExecute}},
			},
			want: true,
		},
		{
			name: "well formed structural redirect",
			facts: Facts{
				Parse: ParseResult{Status: StatusComplete},
				Commands: []CommandFact{{
					Kind:         CommandKindShellRedirect,
					Effect:       EffectExecute,
					ArgvComplete: true,
					Redirects: []RedirectFact{{
						Access: PathAccessWrite,
						Target: "/tmp/output",
					}},
				}},
			},
			want: true,
		},
		{
			name: "malformed structural redirect",
			facts: Facts{
				Parse: ParseResult{Status: StatusComplete},
				Commands: []CommandFact{{
					Kind:       CommandKindShellRedirect,
					Effect:     EffectExecute,
					Executable: "attacker-controlled",
					Redirects: []RedirectFact{{
						Access: PathAccessWrite,
						Target: "/tmp/output",
					}},
				}},
			},
		},
		{
			name: "unknown command kind",
			facts: Facts{
				Parse: ParseResult{Status: StatusComplete},
				Commands: []CommandFact{{
					Kind:   CommandKind("unknown"),
					Effect: EffectExecute,
				}},
			},
		},
		{
			name: "preview",
			facts: Facts{
				Parse:    ParseResult{Status: StatusComplete},
				Commands: []CommandFact{{Effect: EffectPreview}},
			},
		},
		{
			name: "uncertain",
			facts: Facts{
				Parse:    ParseResult{Status: StatusComplete},
				Commands: []CommandFact{{Effect: EffectUncertain}},
			},
		},
		{
			name: "partial",
			facts: Facts{
				Parse:    ParseResult{Status: StatusPartial},
				Commands: []CommandFact{{Effect: EffectExecute}},
			},
		},
		{
			name:  "no command",
			facts: Facts{Parse: ParseResult{Status: StatusComplete}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.facts.EnforcementEligible(); got != test.want {
				t.Fatalf("EnforcementEligible() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestParseOutputIssuesAreBoundedAndDeduplicated(t *testing.T) {
	out := newParseOutput(DialectPOSIX, 1)
	for range maxIssues + 4 {
		out.addIssue(IssueDynamicWord)
		out.addIssue(IssueUnknownOperandGrammar)
	}
	if got := len(out.issues); got != 2 {
		t.Fatalf("issues = %v, want two unique values", out.issues)
	}

	bounded := newParseOutput(DialectPOSIX, 1)
	for index := range maxIssues + 4 {
		bounded.addIssue(IssueCode("synthetic-" + strconv.Itoa(index)))
	}
	if got := len(bounded.issues); got != maxIssues {
		t.Fatalf("issues = %d, want exactly %d", got, maxIssues)
	}
}
