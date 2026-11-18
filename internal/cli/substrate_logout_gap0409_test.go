// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
)

// GAP-0409: the gateway verifies sign-in tokens statelessly, so logout says
// how long a copied token still works instead of implying it ended it.
func TestSubstrateLogoutNoteGAP0409(t *testing.T) {
	now := time.Date(2026, 11, 17, 16, 0, 0, 0, time.UTC)
	note := substrateLogoutNote(&auth.Token{AccessToken: "acc-marker", IDToken: "id-marker", Expiry: now.Add(282 * time.Second)}, now)
	for _, want := range []string{"until it expires at 16:04 UTC", "about 5 min", "does not revoke"} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q has no %q", note, want)
		}
	}
	if strings.Contains(note, "marker") {
		t.Fatalf("the note shows a token: %q", note)
	}
	for name, tok := range map[string]*auth.Token{
		"nothing stored": nil,
		"expired":        {AccessToken: "a", Expiry: now.Add(-time.Second)},
		"no token":       {Expiry: now.Add(time.Hour)},
	} {
		if got := substrateLogoutNote(tok, now); got != "" {
			t.Errorf("%s: note %q, want none", name, got)
		}
	}
	if got := substrateLogoutNote(&auth.Token{AccessToken: "a", Expiry: now.Add(10 * time.Second)}, now); !strings.Contains(got, "about 1 min") {
		t.Errorf("short remainder: %q", got)
	}
}
