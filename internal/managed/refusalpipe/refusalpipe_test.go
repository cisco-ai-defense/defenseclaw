// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package refusalpipe

import "testing"

// GAP-2639: a CLI command report carries the refused command's fixed words
// and a command reason only; no argument, connector or hook label passes.
func TestCommandReportCarriesOnlyFixedWordsAndAReason(t *testing.T) {
	report := Report{Command: " guardrail  disable ", Reason: ReasonManagedDevice}
	message, err := Encode(report)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(message)
	if err != nil || decoded != (Report{Command: "guardrail disable", Reason: ReasonManagedDevice}) {
		t.Fatalf("decoded %+v, %v", decoded, err)
	}
	for _, bad := range []Report{
		{Command: "config set guardrail.mode=observe", Reason: ReasonManagedDevice},
		{Command: `scan skill C:\Users\x`, Reason: ReasonManagedDevice},
		{Command: "Setup", Reason: ReasonManagedDevice},
		{Command: "a b c d e", Reason: ReasonManagedDevice},
		{Command: "uninstall", Reason: ReasonSIDUnregistered},
		{Command: "uninstall", Reason: ReasonElevationRequired, Connector: "codex"},
		{Command: "uninstall", Reason: ReasonElevationRequired, Tool: "Bash"},
		{Connector: "codex", Reason: ReasonManagedDevice},
	} {
		if _, err := Encode(bad); err == nil {
			t.Fatalf("encoded %+v", bad)
		}
	}
}

// GAP-0722: a Windows standalone call refused for credentials the gateway has
// not accepted yet is a reportable refusal; an unknown reason is still dropped.
func TestNormalizeAcceptsTheCredentialPendingReason(t *testing.T) {
	report, ok := Report{Connector: "Claudecode", Reason: ReasonCredentialPending, Event: "UserPromptSubmit"}.Normalize()
	if !ok || report.Connector != "claudecode" || report.Reason != ReasonCredentialPending {
		t.Fatalf("Normalize = %+v, %v", report, ok)
	}
	if _, ok := (Report{Connector: "claudecode", Reason: "enterprise_managed_credential_other"}).Normalize(); ok {
		t.Error("an unknown reason was accepted")
	}
}

// Only exactly {"excluded":true} is an exclusion; an absent field, another
// type, extra fields, trailing data and an empty answer are errors or false.
func TestParseExcludedAnswerAcceptsOnlyAnExactExclusion(t *testing.T) {
	for _, tc := range []struct {
		answer  string
		want    bool
		wantErr bool
	}{
		{answer: string(ExcludedAnswer(true)), want: true},
		{answer: string(ExcludedAnswer(false))},
		{answer: `{"excluded":true,"extra":1}`, wantErr: true},
		{answer: `{"excluded":"true"}`, wantErr: true},
		{answer: `{"excluded":null}`, wantErr: true},
		{answer: `{}`, wantErr: true},
		{answer: `{"excluded":true}{"excluded":true}`, wantErr: true},
		{answer: `[]`, wantErr: true},
		{answer: ``, wantErr: true},
	} {
		got, err := ParseExcludedAnswer([]byte(tc.answer))
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("ParseExcludedAnswer(%q) = %t, %v; want %t, error=%t", tc.answer, got, err, tc.want, tc.wantErr)
		}
	}
}
