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
			got := ownStateText(tc.state, tc.protected)
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
		if got := ownStateText(state, protected); got != want {
			t.Fatalf("ownStateText(%q) = %q, want %q", state, got, want)
		}
	}
	if got := ownStateText("", true); got != "protected" {
		t.Fatalf("a protected row with no text = %q", got)
	}
}
