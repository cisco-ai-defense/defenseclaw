// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
)

// GAP-0409: a gateway that can't end sign-ins (before 1.0.11, or with
// ending sign-ins off) answers 404, and logout says how long a copied
// token still works instead of implying it ended it.
func TestSubstrateLogoutNoteGAP0409(t *testing.T) {
	now := time.Date(2026, 11, 17, 16, 0, 0, 0, time.UTC)
	note := substrateLogoutNote(&auth.Token{AccessToken: "acc-marker", IDToken: "id-marker", Expiry: now.Add(282 * time.Second)}, now)
	for _, want := range []string{"works until 16:04 UTC", "about 5 min", "can't end sign-ins"} {
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

// With the 15-minute sign-in age limit, a copied token works until the
// earlier of its exp and iat + 15 minutes, and the note says so.
func TestSubstrateLogoutNoteSignInAgeGAP0409(t *testing.T) {
	now := time.Date(2026, 11, 17, 16, 0, 0, 0, time.UTC)
	jwt := func(iat time.Time) string {
		enc := base64.RawURLEncoding.EncodeToString
		body := fmt.Sprintf(`{"iat":%d,"exp":%d}`, iat.Unix(), now.Add(time.Hour).Unix())
		return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(body)) + ".sig"
	}
	// Issued 5 minutes ago with exp an hour ahead: works for 10 more minutes.
	tok := &auth.Token{AccessToken: jwt(now.Add(-5 * time.Minute)), IDToken: jwt(now.Add(-6 * time.Minute)), Expiry: now.Add(time.Hour)}
	note := substrateLogoutNote(tok, now)
	for _, want := range []string{"works until 16:10 UTC", "about 10 min", "at most 15 minutes", "can't end sign-ins"} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q has no %q", note, want)
		}
	}
	// Issued 20 minutes ago: the cluster already refuses it, no note.
	old := jwt(now.Add(-20 * time.Minute))
	if got := substrateLogoutNote(&auth.Token{AccessToken: old, IDToken: old, Expiry: now.Add(time.Hour)}, now); got != "" {
		t.Errorf("20-minute-old sign-in: note %q, want none", got)
	}
}
