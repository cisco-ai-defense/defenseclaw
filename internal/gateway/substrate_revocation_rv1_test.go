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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
)

// Review RV-SECR1 fixes of B5.1 (lanes/tsecr/RV1.md).

// newRevocationPeopleFixture is a replica with the leader's store and the
// given tokens, already synced.
func newRevocationPeopleFixture(t *testing.T, people fakePeople) *revFixture {
	t.Helper()
	store, err := revocation.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snap := revocation.NewSnapshot(time.Minute)
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.People = people
		c.Revocations, c.RevocationSource, c.Streams = snap, store, revocation.NewStreams(snap)
	})
	if err := snap.Pull(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return &revFixture{f, store, snap}
}

func (f *revFixture) wantList(t *testing.T, tok string, code int, reason, what string) {
	t.Helper()
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", tok, "")
	if rec.Code != code || (reason != "" && reasonOf(t, rec) != reason) {
		t.Fatalf("%s: %s got %d %s, want %d %s", what, tok, rec.Code, strings.TrimSpace(rec.Body.String()), code, reason)
	}
}

func kubePerson(sub, key string, iat time.Time) identity.Person {
	return identity.Person{Kind: identity.PersonKube, Issuer: identity.KubeIssuer, Subject: sub, Principal: sub, TokenKey: key, IssuedAt: iat}
}

// RV1-01: a Kubernetes sign-in is ended like an OIDC one; one with no
// issue time can't end by time (it would also lock out the person's next
// sign-in), and says so.
func TestRV101KubeSigninEnds(t *testing.T) {
	past, later := time.Now().Add(-time.Minute), time.Now().Add(3*time.Second)
	f := newRevocationPeopleFixture(t, fakePeople{
		"k-static": kubePerson("carol", "tok:static", time.Time{}), "k-static2": kubePerson("dave", "tok:static2", time.Time{}),
		"k-sa": kubePerson("erin", "tok:sa", past), "k-sa2": kubePerson("erin", "tok:sa2", past), "k-sa-new": kubePerson("erin", "tok:sa3", later),
	})
	const revoke = "/api/v1/substrate/signin/revoke"
	if rec := f.do(t, f.admin, http.MethodPost, revoke, "k-static", `{"scope":"this"}`); rec.Code != 200 {
		t.Fatalf("logout of a static kube token: %d %s", rec.Code, rec.Body)
	}
	f.wantList(t, "k-static", 401, "signin_ended", "the ended static token")
	if rec := f.do(t, f.admin, http.MethodPost, revoke, "k-static2", `{"scope":"all"}`); rec.Code != 400 || reasonOf(t, rec) != "signin_no_issue_time" {
		t.Fatalf("logout --all with no iat: %d %s", rec.Code, rec.Body)
	}
	f.wantList(t, "k-static2", 200, "", "a refused --all ends nothing")
	if rec := f.do(t, f.admin, http.MethodPost, revoke, "k-sa", `{"scope":"all"}`); rec.Code != 200 {
		t.Fatalf("logout --all of a ServiceAccount sign-in: %d %s", rec.Code, rec.Body)
	}
	f.wantList(t, "k-sa", 401, "signin_ended", "the device that logged out")
	f.wantList(t, "k-sa2", 401, "signin_ended", "the other device")
	f.wantList(t, "k-sa-new", 200, "", "a sign-in after the end")
}

// RV1-06: logout --all covers the caller's own sign-in even when the
// sign-in server's clock is ahead of the gateway's.
func TestRV106CallerWatermarkCoversFastIdP(t *testing.T) {
	now := time.Now()
	fast := now.Add(30 * time.Second).Truncate(time.Second) // the IdP is 30 s ahead
	f := newRevocationPeopleFixture(t, fakePeople{
		"p-fast": func() identity.Person { p := alice; p.TokenKey, p.IssuedAt = "k-fast", fast; return p }(),
		"p-fast-before": func() identity.Person {
			p := alice
			p.TokenKey, p.IssuedAt = "k-fast-0", fast.Add(-10*time.Second) // issued 10 s before, by the fast clock
			return p
		}(),
	})
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-fast", `{"scope":"all"}`); rec.Code != 200 {
		t.Fatalf("logout --all: %d %s", rec.Code, rec.Body)
	}
	f.wantList(t, "p-fast", 401, "signin_ended", "the caller")
	f.wantList(t, "p-fast-before", 401, "signin_ended", "a token issued 10 s before by the fast clock")
}

// RV1-03: with api_audience set the gateway accepts the access token as
// well as the ID token; a logout ends both in one write. A token of
// another person, or one that does not verify, ends nothing.
func TestRV103LogoutEndsBothStoredTokens(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	dev := func(p identity.Person, key string) identity.Person { p.TokenKey, p.IssuedAt = key, past; return p }
	f := newRevocationPeopleFixture(t, fakePeople{
		"p-id": dev(alice, "k-id"), "p-acc": dev(alice, "k-acc"), "p-other-device": dev(alice, "k-2"), "p-bob": dev(bob, "k-bob"),
	})
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-id",
		`{"scope":"this","also":["p-id","p-acc","p-bob"]}`)
	if rec.Code != 200 {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body)
	}
	f.wantList(t, "p-id", 401, "signin_ended", "the bearer")
	f.wantList(t, "p-acc", 401, "signin_ended", "the other stored token")
	f.wantList(t, "p-other-device", 200, "", "another device (scope this)")
	f.wantList(t, "p-bob", 200, "", "another person's token in also")
	if _, seq := f.snap.Cursor(); seq != 2 {
		t.Fatalf("seq %d, want 2: both keys in one write", seq)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-other-device",
		`{"scope":"this","also":["a","b","c","d","e"]}`); rec.Code != 400 {
		t.Fatalf("five also tokens: %d", rec.Code)
	}
}

// RV1-07: the gateway logs and audits (HIGH) a reset of the leader's list.
func TestRV107ListResetIsAuditedHigh(t *testing.T) {
	f := newRevocationPeopleFixture(t, fakePeople{})
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	if _, err := f.store.Put(context.Background(), revocation.Entry{Person: alice.ID(), Token: "k-1"}); err != nil {
		t.Fatal(err)
	}
	if err := f.snap.Pull(context.Background(), f.store); err != nil {
		t.Fatal(err)
	}
	other, err := revocation.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.snap.Pull(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		events, err := store.ListEvents(100)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if strings.Contains(e.Details, `"event":"substrate.signin.list_reset"`) {
				if e.Severity != "HIGH" {
					t.Fatalf("list reset audited at %s", e.Severity)
				}
				return
			}
		}
	}
	t.Fatal("no substrate.signin.list_reset audit row")
}

// RV1-11: a person ending their own sign-in is audited at MEDIUM, as the
// docs say.
func TestRV111SelfLogoutAuditedMedium(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	f := newRevocationPeopleFixture(t, fakePeople{"p-alice": func() identity.Person { p := alice; p.TokenKey, p.IssuedAt = "k-1", past; return p }()})
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/signin/revoke", "p-alice", `{"scope":"this"}`); rec.Code != 200 {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		events, err := store.ListEvents(100)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if strings.Contains(e.Details, `"event":"substrate.signin.revoked"`) {
				if e.Severity != "MEDIUM" {
					t.Fatalf("self-logout audited at %s", e.Severity)
				}
				return
			}
		}
	}
	t.Fatal("no substrate.signin.revoked audit row")
}
