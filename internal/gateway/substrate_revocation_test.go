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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
)

// B5.1: ended sign-ins on one replica, with the leader's FileStore as the
// source. Tokens: p-alice and p-alice2 are two devices of alice, signed in
// a minute ago; p-alice-new is alice signed in after any end made now.
type revFixture struct {
	*substrateFixture
	store *revocation.FileStore
	snap  *revocation.Snapshot
}

func newRevocationFixture(t *testing.T, pull bool) *revFixture {
	t.Helper()
	store, err := revocation.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snap := revocation.NewSnapshot(time.Minute)
	past, later := time.Now().Add(-time.Minute), time.Now().Add(3*time.Second)
	dev := func(p identity.Person, key string, iat time.Time) identity.Person {
		p.TokenKey, p.IssuedAt = key, iat
		return p
	}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.People = fakePeople{
			"p-alice": dev(alice, "k-alice-1", past), "p-alice2": dev(alice, "k-alice-2", past),
			"p-alice-new": dev(alice, "k-alice-3", later),
			"p-bob":       dev(bob, "k-bob-1", past), "p-admin": dev(admin, "k-admin-1", past),
		}
		c.Revocations, c.RevocationSource, c.Streams = snap, store, revocation.NewStreams(snap)
	})
	if pull {
		if err := snap.Pull(context.Background(), store); err != nil {
			t.Fatal(err)
		}
	}
	return &revFixture{f, store, snap}
}

const revOwnActor = "/api/v1/substrate/actors/eng-web/alice-1"

func (f *revFixture) want(t *testing.T, tok string, code int, reason, what string) {
	t.Helper()
	rec := f.do(t, f.admin, http.MethodGet, revOwnActor, tok, "")
	if rec.Code != code || (reason != "" && reasonOf(t, rec) != reason) {
		t.Fatalf("%s: %s got %d %s, want %d %s", what, tok, rec.Code, strings.TrimSpace(rec.Body.String()), code, reason)
	}
}

func (f *revFixture) relayVerify(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	tok, _, err := f.sessions.Issue(identity.SignInOf(alice), identity.SessionActor{Atespace: "eng-web", Name: "alice-1", UID: subUID1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	return f.do(t, f.actor, http.MethodPost, substrateRelayVerify, "tok-alice", string(body))
}

func TestRevokedTokenRefusedOnAdminListener(t *testing.T) {
	f := newRevocationFixture(t, true)
	f.want(t, "p-alice", 200, "", "before logout")
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-alice", `{"scope":"this"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"scope":"this"`) || strings.Contains(rec.Body.String(), "k-alice-1") {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body)
	}
	f.want(t, "p-alice", 401, "signin_ended", "the ended token")
	f.want(t, "p-alice2", 200, "", "alice's other device (scope this)")
	// The ended token can't end anything more; a relay session minted
	// from an unended sign-in still verifies.
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-alice", `{"scope":"all"}`); rec.Code != 401 {
		t.Fatalf("ended token revokes: %d", rec.Code)
	}
	if rec := f.relayVerify(t); rec.Code != 200 {
		t.Fatalf("relay verify after a token-scope logout: %d %s", rec.Code, rec.Body)
	}
}

func TestLogoutAllRefusesOtherDeviceToken(t *testing.T) {
	f := newRevocationFixture(t, true)
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-alice2", `{"scope":"all"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"not_before"`) {
		t.Fatalf("logout --all: %d %s", rec.Code, rec.Body)
	}
	f.want(t, "p-alice", 401, "signin_ended", "alice's other device")
	f.want(t, "p-alice2", 401, "signin_ended", "the device that logged out")
	f.want(t, "p-alice-new", 200, "", "a sign-in after the end")
	f.want(t, "p-bob", 404, "", "bob (not his actor; not ended)")
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-bob", `{"scope":"everything"}`); rec.Code != 400 {
		t.Fatalf("bad scope: %d", rec.Code)
	}
}

func TestRelayVerifyRefusesSessionMintedBeforeRevoke(t *testing.T) {
	f := newRevocationFixture(t, true)
	if rec := f.relayVerify(t); rec.Code != 200 {
		t.Fatalf("before: %d %s", rec.Code, rec.Body)
	}
	tok, _, _ := f.sessions.Issue(identity.SignInOf(alice), identity.SessionActor{Atespace: "eng-web", Name: "alice-1", UID: subUID1}, 0)
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/admin/revocations", "p-admin", `{"user":"alice@example.com","reason":"laptop lost"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"person":"https://idp.example#alice"`) {
		t.Fatalf("admin revoke: %d %s", rec.Code, rec.Body)
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	rec = f.do(t, f.actor, http.MethodPost, substrateRelayVerify, "tok-alice", string(body))
	if rec.Code != 401 || reasonOf(t, rec) != "signin_ended" {
		t.Fatalf("session minted before the revoke: %d %s", rec.Code, rec.Body)
	}
	f.want(t, "p-alice-new", 200, "", "alice signed in again")
}

func TestReplicaRefusesBeforeFirstSync(t *testing.T) {
	f := newRevocationFixture(t, false)
	f.want(t, "p-alice", 503, "revocation_unavailable", "admin listener before the first pull")
	if rec := f.relayVerify(t); rec.Code != 503 || reasonOf(t, rec) != "revocation_unavailable" {
		t.Fatalf("relay verify before the first pull: %d %s", rec.Code, rec.Body)
	}
	if c := SubstrateRevocationCheck(f.snap, time.Now()); c.Status != "fail" {
		t.Fatalf("doctor before the first pull: %+v", c)
	}
}

func TestRelayVerifyRefusesWhenRevocationStale(t *testing.T) {
	f := newRevocationFixture(t, true)
	if c := SubstrateRevocationCheck(f.snap, time.Now()); c.Status != "pass" {
		t.Fatalf("doctor synced: %+v", c)
	}
	f.snap.SetClock(func() time.Time { return time.Now().Add(2 * time.Minute) })
	if rec := f.relayVerify(t); rec.Code != 503 || reasonOf(t, rec) != "revocation_unavailable" {
		t.Fatalf("relay verify on a stale list: %d %s", rec.Code, rec.Body)
	}
	f.want(t, "p-alice", 503, "revocation_unavailable", "admin listener on a stale list")
	if c := SubstrateRevocationCheck(f.snap, time.Now().Add(2*time.Minute)); c.Status != "fail" || !strings.Contains(c.Detail, "limit 1m0s") {
		t.Fatalf("doctor stale: %+v", c)
	}
	if c := SubstrateRevocationCheck(nil, time.Now()); c.Status != "warn" {
		t.Fatalf("doctor off: %+v", c)
	}
}

func TestAdminRevokeUnknownPerson(t *testing.T) {
	f := newRevocationFixture(t, true)
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/admin/revocations", "p-admin", `{"user":"carol@example.com"}`)
	if rec.Code != 404 || reasonOf(t, rec) != "person_unknown" {
		t.Fatalf("unknown principal: %d %s", rec.Code, rec.Body)
	}
	// Ahead of a first sign-in, by issuer#subject.
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/admin/revocations", "p-admin", `{"user":"https://idp.example#carol"}`); rec.Code != 200 {
		t.Fatalf("issuer#subject: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/admin/revocations", "p-admin", `{"user":"x#y","reason":"a\nb"}`); rec.Code != 400 {
		t.Fatalf("two-line reason: %d", rec.Code)
	}
}

func TestAdminRevocationsAdminOnly(t *testing.T) {
	f := newRevocationFixture(t, true)
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		if rec := f.do(t, f.admin, m, "/api/v1/substrate/admin/revocations?user=alice@example.com", "p-bob", `{"user":"alice@example.com"}`); rec.Code != 403 {
			t.Fatalf("%s by a person: %d", m, rec.Code)
		}
	}
	if rec := f.do(t, f.admin, http.MethodPut, "/api/v1/substrate/admin/revocations", "p-admin", `{}`); rec.Code != 405 {
		t.Fatalf("PUT: %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/admin/revocations", "p-admin", `{"user":"alice@example.com"}`); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/admin/revocations", "p-admin", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"person":"https://idp.example#alice"`) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	f.want(t, "p-alice", 401, "signin_ended", "after the admin revoke")
	if rec := f.do(t, f.admin, http.MethodDelete, "/api/v1/substrate/admin/revocations?user=alice@example.com", "p-admin", ""); rec.Code != 200 {
		t.Fatalf("lift: %d %s", rec.Code, rec.Body)
	}
	f.want(t, "p-alice", 200, "", "after the lift")
}

func TestRevocationOffKeepsOldBehavior(t *testing.T) {
	f := newSubstrateFixture(t)
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-alice", `{}`); rec.Code != 404 {
		t.Fatalf("revocation off: signin/revoke %d (the launcher keeps its old note on 404)", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodGet, revOwnActor, "p-alice", ""); rec.Code != 200 {
		t.Fatalf("revocation off: admin listener %d", rec.Code)
	}
}

func TestAttachClosedOnRevoke(t *testing.T) {
	f := newRevocationFixture(t, true)
	up := websocket.Upgrader{}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = c.WriteMessage(mt, msg)
		}
	}))
	defer relay.Close()
	f.api.substrateState().cfg.Relays = &dialRelay{addr: strings.TrimPrefix(relay.URL, "http://")}
	srv := httptest.NewServer(f.admin)
	defer srv.Close()
	dial := func(tok string) *websocket.Conn {
		h := http.Header{"Authorization": {"Bearer " + tok}, "Sec-WebSocket-Protocol": {"dcrelay.v1"}}
		ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+revOwnActor+"/attach", h)
		if err != nil {
			t.Fatalf("websocket %s: %v", tok, err)
		}
		if err := ws.WriteMessage(websocket.TextMessage, []byte("hi")); err != nil {
			t.Fatal(err)
		}
		if _, msg, err := ws.ReadMessage(); err != nil || string(msg) != "hi" {
			t.Fatalf("echo %q %v", msg, err)
		}
		return ws
	}
	ended, other := dial("p-alice"), dial("p-alice2")
	defer other.Close()
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-alice", `{"scope":"this"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"closed":1`) {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body)
	}
	_ = ended.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := ended.ReadMessage(); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("the ended sign-in's stream is still open: %v", err)
	}
	// The other device's stream stays open.
	if err := other.WriteMessage(websocket.TextMessage, []byte("still")); err != nil {
		t.Fatal(err)
	}
	if _, msg, err := other.ReadMessage(); err != nil || string(msg) != "still" {
		t.Fatalf("other device: %q %v", msg, err)
	}
}
