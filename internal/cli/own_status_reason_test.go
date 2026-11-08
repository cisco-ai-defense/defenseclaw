// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// Every row of `defenseclaw status` on a managed computer that is not
// protected says why and what to do next, whatever the gateway sent: a gateway
// that predates the reasons sends a bare "not protected", a bare "not
// confirmed" or no text.
func TestOwnStateTextGivesEveryNotProtectedRowAReasonAndNextStep(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     string
		protected bool
	}{
		{"no text", "", false},
		{"blank text", "  ", false},
		{"bare not protected", "not protected", false},
		{"bare not confirmed", "not confirmed", false},
		{"bare not protected with a space", " not protected ", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ownStateText(ownStatusRow{State: tc.state, Protected: tc.protected})
			if !strings.HasPrefix(got, "not ") || !strings.Contains(got, ": your gateway did not say why") ||
				!strings.Contains(got, "ask IT") || !strings.Contains(got, "defenseclaw status") {
				t.Fatalf("ownStateText(%q) = %q, want a reason and the next step", tc.state, got)
			}
		})
	}
}

// Benign twin: protected rows, and rows that already say why, print as sent.
func TestOwnStateTextKeepsProtectedAndReasonedRows(t *testing.T) {
	reasoned := "not protected: DefenseClaw has not set up protection for this agent on your account. Ask IT"
	for state, want := range map[string]string{
		"protected":                    "protected",
		"protected: Cowork runs hooks": "protected: Cowork runs hooks",
		reasoned:                       reasoned,
		"not confirmed: the record is old. Run defenseclaw status again": "not confirmed: the record is old. Run defenseclaw status again",
	} {
		protected := strings.HasPrefix(state, "protected")
		if got := ownStateText(ownStatusRow{State: state, Protected: protected}); got != want {
			t.Fatalf("ownStateText(%q) = %q, want %q", state, got, want)
		}
	}
	if got := ownStateText(ownStatusRow{Protected: true}); got != "protected" {
		t.Fatalf("a protected row with no text = %q", got)
	}
}

// The state is one word and the gateway sends the reason and the next step in
// their own fields; the row prints them after the state, once, with no double
// full stop.
func TestOwnStateTextJoinsStateReasonAndNextStep(t *testing.T) {
	for name, tc := range map[string]struct {
		row  ownStatusRow
		want string
	}{
		"reason and next step": {ownStatusRow{State: "not protected", ReasonCode: "no_setup", Reason: "DefenseClaw has not set up protection for this agent on your account", NextStep: "Ask IT"},
			"not protected: DefenseClaw has not set up protection for this agent on your account. Ask IT"},
		"trailing full stops": {ownStatusRow{State: "not confirmed", Reason: "the record is old. ", NextStep: "Run defenseclaw status again."},
			"not confirmed: the record is old. Run defenseclaw status again"},
		"reason without next step": {ownStatusRow{State: "refused", Reason: "this version is not allowed"},
			"refused: this version is not allowed"},
		"protected with a reason": {ownStatusRow{Protected: true, State: "protected", Reason: "Cowork runs the managed hooks"},
			"protected: Cowork runs the managed hooks"},
		"protected": {ownStatusRow{Protected: true, State: "protected"}, "protected"},
		"excluded account": {ownStatusRow{State: "excluded", ReasonCode: "excluded_users", Reason: "your account is listed in enterprise.enrollment.exclude_users, so DefenseClaw does not protect this agent for it", NextStep: "Ask IT to remove your account from enterprise.enrollment.exclude_users"},
			"excluded: your account is listed in enterprise.enrollment.exclude_users, so DefenseClaw does not protect this agent for it. Ask IT to remove your account from enterprise.enrollment.exclude_users"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ownStateText(tc.row); got != tc.want {
				t.Fatalf("ownStateText(%+v) = %q, want %q", tc.row, got, tc.want)
			}
		})
	}
}
