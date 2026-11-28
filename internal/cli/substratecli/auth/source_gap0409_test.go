// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// GAP-0409: the admin listener accepts a sign-in for 15 minutes after its
// iat, whatever its exp says, so the launcher refreshes a stored sign-in
// issued more than 12 minutes ago before it uses it.
func TestSourceRefreshesAnOldSignInGAP0409(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	now := clk.Now()
	old := func(marker string) string {
		return testJWT(t, marker, map[string]any{"iat": now.Add(-13 * time.Minute).Unix(), "exp": now.Add(time.Hour).Unix()})
	}
	st := newMemStore()
	st.m["e1"] = Token{AccessToken: old("old-acc"), IDToken: old("old-id"), RefreshToken: "refresh-old",
		Expiry: now.Add(time.Hour), Kind: KindPerson}
	idp.refreshFn = func(map[string]string) (int, map[string]any) {
		fresh := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
		return 200, map[string]any{"access_token": testJWT(t, "new-acc", fresh), "id_token": testJWT(t, "new-id", fresh),
			"refresh_token": "refresh-new", "expires_in": 3600}
	}
	s := NewSource("e1", idp.context(), st, SourceOptions{HTTPClient: idp.srv.Client(), Now: clk.Now})
	b, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if decodeClaimsMarker(b) != "new-id" || idp.refreshes != 1 {
		t.Fatalf("bearer %q after %d refreshes: a 13-minute-old sign-in was used as it was", decodeClaimsMarker(b), idp.refreshes)
	}
	if st.m["e1"].RefreshToken != "refresh-new" {
		t.Error("the refreshed sign-in was not saved")
	}
	// A fresh sign-in is used without another refresh.
	clk.Add(5 * time.Minute)
	if b, err := s.Token(context.Background()); err != nil || decodeClaimsMarker(b) != "new-id" || idp.refreshes != 1 {
		t.Fatalf("5-minute-old sign-in: bearer %q err %v refreshes %d", decodeClaimsMarker(b), err, idp.refreshes)
	}
}

// Without a refresh token, a sign-in older than the gateway's 15-minute
// limit is a new sign-in, not a bearer the admin listener will refuse; an
// issuer outage while the sign-in is 13 minutes old keeps it.
func TestSourceOldSignInLimitsGAP0409(t *testing.T) {
	clk := newClock()
	now := clk.Now()
	tok := func(age time.Duration) string {
		return testJWT(t, "acc", map[string]any{"iat": now.Add(-age).Unix(), "exp": now.Add(time.Hour).Unix()})
	}
	st := newMemStore()
	st.m["e1"] = Token{AccessToken: tok(16 * time.Minute), Expiry: now.Add(time.Hour), Kind: KindPerson}
	s := NewSource("e1", Context{AdminURL: "https://admin.example.test"}, st, SourceOptions{Now: clk.Now})
	if _, err := s.Token(context.Background()); !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("16-minute-old sign-in without a refresh token: err = %v, want ErrNotSignedIn", err)
	}

	idp := newFakeIdP(t)
	idp.refreshFn = func(map[string]string) (int, map[string]any) { return 500, map[string]any{"error": "server_error"} }
	st.m["e1"] = Token{AccessToken: tok(13 * time.Minute), RefreshToken: "refresh-marker", Expiry: now.Add(time.Hour), Kind: KindPerson}
	s = NewSource("e1", idp.context(), st, SourceOptions{HTTPClient: idp.srv.Client(), Now: clk.Now})
	if b, err := s.Token(context.Background()); err != nil || decodeClaimsMarker(b) != "acc" || idp.refreshes != 1 {
		t.Fatalf("issuer down at 13 minutes: bearer %q err %v refreshes %d", decodeClaimsMarker(b), err, idp.refreshes)
	}
}
