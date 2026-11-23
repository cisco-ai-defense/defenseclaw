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

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
)

func (f *revFixture) sessionOf(t *testing.T, tok string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"atespace": "eng-web", "name": "alice-1"})
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/session-cert", tok, string(b))
	var sess struct{ Token string }
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &sess) != nil || sess.Token == "" {
		t.Fatalf("session for %s: %d %s", tok, rec.Code, rec.Body)
	}
	return sess.Token
}

func (f *revFixture) relayVerifyOf(t *testing.T, session string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": session})
	rec := f.do(t, f.actor, http.MethodPost, substrateRelayVerify, "tok-alice", string(body))
	if rec.Code == 200 {
		return 200, ""
	}
	return rec.Code, reasonOf(t, rec)
}

// GAP-0744: relay verify checked only the session token's own issue time.
// A session handed out from a sign-in stayed good after a plain logout of
// that sign-in (until the session expired), and a session a lagging
// replica handed out after a logout --all or admin revoke stayed good for
// its life. The session token now names its sign-in, and relay verify
// checks that sign-in too.
func TestGAP0744RelaySessionEndsWithItsSignIn(t *testing.T) {
	t.Run("plain logout", func(t *testing.T) {
		f := newRevocationFixture(t, true)
		s1, s2 := f.sessionOf(t, "p-alice"), f.sessionOf(t, "p-alice2")
		if code, why := f.relayVerifyOf(t, s1); code != 200 {
			t.Fatalf("before logout: %d %s", code, why)
		}
		if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-alice", `{"scope":"this"}`); rec.Code != 200 {
			t.Fatalf("logout: %d %s", rec.Code, rec.Body)
		}
		if code, why := f.relayVerifyOf(t, s1); code != 401 || why != "signin_ended" {
			t.Fatalf("session of the ended sign-in: %d %s, want 401 signin_ended", code, why)
		}
		if code, why := f.relayVerifyOf(t, s2); code != 200 {
			t.Fatalf("session of alice's other sign-in: %d %s", code, why)
		}
	})
	t.Run("lagging replica after an end by time", func(t *testing.T) {
		f := newRevocationFixture(t, true)
		// The leader ends every sign-in of alice issued before 30 s ago;
		// this replica has not pulled it yet and hands out a session from
		// a sign-in made a minute ago.
		if _, err := f.store.Put(context.Background(), revocation.Entry{Person: alice.ID(), NotBefore: time.Now().Add(-30 * time.Second)}); err != nil {
			t.Fatal(err)
		}
		s := f.sessionOf(t, "p-alice")
		if err := f.snap.Pull(context.Background(), f.store); err != nil {
			t.Fatal(err)
		}
		if code, why := f.relayVerifyOf(t, s); code != 401 || why != "signin_ended" {
			t.Fatalf("session handed out after the end: %d %s, want 401 signin_ended", code, why)
		}
		if code, why := f.relayVerifyOf(t, f.sessionOf(t, "p-alice-new")); code != 200 {
			t.Fatalf("session of a sign-in after the end: %d %s", code, why)
		}
	})
}
