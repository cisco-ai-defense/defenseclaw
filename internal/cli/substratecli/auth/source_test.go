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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSourcePick(t *testing.T) {
	clk := newClock()
	now := clk.Now()
	jwt := func(marker string, exp time.Time) string {
		return testJWT(t, marker, map[string]any{"exp": exp.Unix()})
	}
	tests := []struct {
		name    string
		tok     Token
		want    string
		wantErr error
	}{
		{name: "id token preferred", tok: Token{IDToken: jwt("id", now.Add(time.Hour)), AccessToken: jwt("acc", now.Add(time.Hour)), Expiry: now.Add(time.Hour)}, want: "id"},
		{name: "access when no id", tok: Token{AccessToken: jwt("acc", now.Add(time.Hour)), Expiry: now.Add(time.Hour)}, want: "acc"},
		{name: "access when id expired and no refresh", tok: Token{IDToken: jwt("id", now.Add(-time.Minute)), AccessToken: "opaque", Expiry: now.Add(time.Hour)}, want: "opaque"},
		{name: "inside skew without refresh", tok: Token{AccessToken: jwt("acc", now.Add(30*time.Second)), Expiry: now.Add(30 * time.Second)}, wantErr: ErrNotSignedIn},
		{name: "opaque access without expiry", tok: Token{AccessToken: "opaque"}, want: "opaque"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newMemStore()
			st.m["e1"] = tc.tok
			s := NewSource("e1", Context{AdminURL: "https://admin.example.test"}, st, SourceOptions{Now: clk.Now})
			got, err := s.Token(context.Background())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want && decodeClaimsMarker(got) != tc.want {
				t.Errorf("bearer is not %q", tc.want)
			}
		})
	}
}

func decodeClaimsMarker(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var out struct {
		Marker string `json:"marker"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.Marker
}

func TestSourceNotSignedIn(t *testing.T) {
	s := NewSource("e1", Context{AdminURL: "https://admin.example.test"}, newMemStore(), SourceOptions{})
	_, err := s.Token(context.Background())
	if !errors.Is(err, ErrNotSignedIn) || err.Error() != "you are not signed in; run: defenseclaw substrate login" {
		t.Fatalf("err = %v", err)
	}
}

func TestSourceOtherIssuer(t *testing.T) {
	st := newMemStore()
	st.m["e1"] = Token{AccessToken: "opaque", Issuer: "https://old.example.test/realms/r"}
	s := NewSource("e1", Context{AdminURL: "https://admin.example.test", Issuer: "https://new.example.test/realms/r"}, st, SourceOptions{})
	if _, err := s.Token(context.Background()); !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("err = %v", err)
	}
}

func TestSourceRefresh(t *testing.T) {
	idp := newFakeIdP(t)
	clk := newClock()
	now := clk.Now()
	st := newMemStore()
	st.m["e1"] = Token{
		AccessToken:  testJWT(t, "old-acc", map[string]any{"exp": now.Add(30 * time.Second).Unix()}),
		IDToken:      testJWT(t, "old-id", map[string]any{"exp": now.Add(30 * time.Second).Unix()}),
		RefreshToken: "refresh-old", Expiry: now.Add(30 * time.Second), Kind: KindPerson,
	}
	var gotForm map[string]string
	idp.refreshFn = func(form map[string]string) (int, map[string]any) {
		gotForm = form
		return 200, map[string]any{
			"access_token":  testJWT(t, "new-acc", map[string]any{"exp": now.Add(time.Hour).Unix()}),
			"id_token":      testJWT(t, "new-id", map[string]any{"exp": now.Add(time.Hour).Unix(), "preferred_username": "alice"}),
			"refresh_token": "refresh-new",
			"expires_in":    "3600",
		}
	}
	s := NewSource("e1", idp.context(), st, SourceOptions{HTTPClient: idp.srv.Client(), Now: clk.Now})
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := s.Token(context.Background())
			if err == nil && decodeClaimsMarker(b) != "new-id" {
				err = fmt.Errorf("bearer is not the new ID token")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if idp.refreshes != 1 {
		t.Errorf("refreshes = %d, want 1 (serialized)", idp.refreshes)
	}
	if gotForm["refresh_token"] != "refresh-old" || gotForm["client_id"] != "defenseclaw-launcher" {
		t.Errorf("refresh form = %v", gotForm)
	}
	saved := st.m["e1"]
	if saved.RefreshToken != "refresh-new" || saved.Principal != "alice" || !saved.Expiry.Equal(now.Add(time.Hour)) {
		t.Errorf("saved = %s", saved)
	}

	// Rotation without a new refresh token keeps the old one.
	clk.Add(2 * time.Hour)
	idp.refreshFn = func(map[string]string) (int, map[string]any) {
		return 200, map[string]any{"access_token": "opaque-2", "expires_in": 3600}
	}
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.m["e1"].RefreshToken != "refresh-new" {
		t.Error("refresh token was dropped")
	}
}

func TestSourceRefreshFailures(t *testing.T) {
	stale := func(t *testing.T, now time.Time) Token {
		return Token{AccessToken: testJWT(t, "acc-marker", map[string]any{"exp": now.Add(-time.Minute).Unix()}), RefreshToken: "refresh-marker", Expiry: now.Add(-time.Minute)}
	}
	t.Run("invalid_grant keeps the store", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.refreshFn = func(map[string]string) (int, map[string]any) {
			return 400, map[string]any{"error": "invalid_grant", "error_description": "Token is not active"}
		}
		clk := newClock()
		st := newMemStore()
		st.m["e1"] = stale(t, clk.Now())
		s := NewSource("e1", idp.context(), st, SourceOptions{HTTPClient: idp.srv.Client(), Now: clk.Now})
		_, err := s.Token(context.Background())
		if !errors.Is(err, ErrNotSignedIn) || !strings.Contains(err.Error(), "Token is not active") {
			t.Fatalf("err = %v", err)
		}
		noSecret(t, err, "acc-marker", "refresh-marker")
		if st.deletes != 0 || st.m["e1"].RefreshToken != "refresh-marker" {
			t.Error("the store was changed")
		}
	})
	t.Run("invalid_grant after another process rotated", func(t *testing.T) {
		idp := newFakeIdP(t)
		clk := newClock()
		st := newMemStore()
		st.m["e1"] = stale(t, clk.Now())
		s := NewSource("e1", idp.context(), st, SourceOptions{HTTPClient: idp.srv.Client(), Now: clk.Now})
		idp.refreshFn = func(map[string]string) (int, map[string]any) {
			st.m["e1"] = Token{AccessToken: "opaque-other", RefreshToken: "refresh-other", Expiry: clk.Now().Add(time.Hour)}
			return 400, map[string]any{"error": "invalid_grant"}
		}
		b, err := s.Token(context.Background())
		if err != nil || b != "opaque-other" {
			t.Fatalf("bearer/err = %q/%v", b, err)
		}
	})
	t.Run("network error is not ErrNotSignedIn", func(t *testing.T) {
		idp := newFakeIdP(t)
		clk := newClock()
		st := newMemStore()
		st.m["e1"] = stale(t, clk.Now())
		c := idp.context()
		hc := idp.srv.Client()
		idp.srv.Close()
		s := NewSource("e1", c, st, SourceOptions{HTTPClient: hc, Now: clk.Now})
		_, err := s.Token(context.Background())
		if err == nil || errors.Is(err, ErrNotSignedIn) {
			t.Fatalf("err = %v", err)
		}
		noSecret(t, err, "acc-marker", "refresh-marker")
	})
	t.Run("server error", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.refreshFn = func(map[string]string) (int, map[string]any) {
			return 500, map[string]any{"error": "server_error"}
		}
		clk := newClock()
		st := newMemStore()
		st.m["e1"] = stale(t, clk.Now())
		s := NewSource("e1", idp.context(), st, SourceOptions{HTTPClient: idp.srv.Client(), Now: clk.Now})
		_, err := s.Token(context.Background())
		if err == nil || errors.Is(err, ErrNotSignedIn) || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSourceWorkloadSkipsStore(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	f := writeTok(t, dir, "wl", testJWT(t, "wl-marker", map[string]any{"aud": "defenseclaw", "sub": "system:serviceaccount:t:ci-workload", "exp": clk.Now().Add(time.Hour).Unix()}))
	st := newMemStore()
	st.failAll = true
	s := NewSource("e1", Context{AdminURL: "https://admin.example.test"}, st, SourceOptions{Workload: &WorkloadOptions{TokenFile: f, Env: emptyEnv}, Now: clk.Now})
	b, err := s.Token(context.Background())
	if err != nil || decodeClaimsMarker(b) != "wl-marker" {
		t.Fatalf("bearer/err: %v", err)
	}
	cur, err := s.Current(context.Background())
	if err != nil || cur.Kind != KindWorkload || cur.Principal != "system:serviceaccount:t:ci-workload" {
		t.Fatalf("current = %v, %v", cur, err)
	}
	// Read fresh every call.
	writeTok(t, dir, "wl", testJWT(t, "wl-marker-2", map[string]any{"aud": "defenseclaw", "exp": clk.Now().Add(time.Hour).Unix()}))
	if b, _ := s.Token(context.Background()); decodeClaimsMarker(b) != "wl-marker-2" {
		t.Error("workload token was cached")
	}
	if st.loads != 0 || st.saves != 0 {
		t.Error("store was used in workload mode")
	}
}

func TestLogout(t *testing.T) {
	idp := newFakeIdP(t)
	st := newMemStore()
	st.m["e1"] = Token{AccessToken: "opaque", RefreshToken: "refresh-marker"}
	if err := Logout(context.Background(), "e1", idp.context(), st, idp.srv.Client()); err != nil {
		t.Fatal(err)
	}
	if len(idp.revoked) != 1 || idp.revoked[0] != "refresh-marker" {
		t.Errorf("revoked = %d calls", len(idp.revoked))
	}
	if _, ok := st.m["e1"]; ok {
		t.Error("not deleted")
	}
	// Unreachable issuer: still deletes.
	st.m["e1"] = Token{AccessToken: "opaque", RefreshToken: "refresh-marker"}
	c := idp.context()
	hc := idp.srv.Client()
	idp.srv.Close()
	if err := Logout(context.Background(), "e1", c, st, hc); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.m["e1"]; ok {
		t.Error("not deleted when the issuer is down")
	}
}

func TestTokenStringHidesValues(t *testing.T) {
	tok := Token{AccessToken: "acc-marker", IDToken: "id-marker", RefreshToken: "refresh-marker", Kind: KindPerson, Principal: "alice"}
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%#v", tok), fmt.Sprintf("%v", &tok)} {
		for _, m := range []string{"acc-marker", "id-marker", "refresh-marker"} {
			if strings.Contains(s, m) {
				t.Fatalf("String form shows %s", m)
			}
		}
	}
}

func TestDecodeClaimsTolerant(t *testing.T) {
	for _, raw := range []string{"", "x", "a.b.c", "a.!!!.c", "a." + "bm90IGpzb24" + ".c"} {
		if c := decodeClaims(raw); c.Sub != "" || !c.expiry().IsZero() {
			t.Errorf("decodeClaims(%q) = %+v", raw, c)
		}
	}
	tok := &Token{IDToken: testJWT(t, "m", map[string]any{"groups": "solo", "email": "a@example.test", "exp": "1900000000"})}
	tok.fillClaims()
	if tok.Principal != "a@example.test" || len(tok.Groups) != 1 || tok.Groups[0] != "solo" {
		t.Errorf("claims = %s %v", tok, tok.Groups)
	}
	if jwtExpiry(tok.IDToken).Unix() != 1900000000 {
		t.Error("string exp not read")
	}
}
