// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0435: a session on an agent is its own person's only. An
// administrator asking for a session certificate for another person's
// agent is refused (403 not_your_agent) and audited as the administrator;
// the relay check refuses a session token for the right actor that names
// anyone but the actor's person, however it was minted. Inventory reads
// stay open to administrators.
func TestSubstrateSessionsAreTheOwnersOnlyGAP0435(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger

	b, _ := json.Marshal(map[string]string{"atespace": "eng-web", "name": "alice-1"})
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/session-cert", "p-admin", string(b))
	if rec.Code != http.StatusForbidden || reasonOf(t, rec) != "not_your_agent" || strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("admin session for alice's agent: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/session-cert", "p-alice", string(b)); rec.Code != http.StatusOK {
		t.Fatalf("alice's own session: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/alice-1", "p-admin", ""); rec.Code != http.StatusOK {
		t.Fatalf("admin inventory read: %d %s", rec.Code, rec.Body)
	}
	rows := substrateRowsMatching(t, store, "access_denied", 1, `"reason":"not_your_agent"`)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "HIGH ") || !strings.Contains(rows[0], `"person_id":"https://idp.example#root"`) ||
		!strings.Contains(rows[0], `"target":"eng-web/alice-1"`) || strings.Contains(rows[0], "#alice") {
		t.Fatalf("admin session refusal rows %v", rows)
	}

	// A token for alice's actor that names bob, minted with the gateway's
	// own key: the relay check refuses it.
	tok, _, err := f.sessions.Issue(identity.SignInOf(bob), identity.SessionActor{Atespace: "eng-web", Name: "alice-1", UID: subUID1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	rec = f.do(t, f.actor, http.MethodPost, substrateRelayVerify, "tok-alice", string(body))
	if rec.Code != http.StatusForbidden || reasonOf(t, rec) != "session_not_owner" {
		t.Fatalf("a session token naming another person: %d %s", rec.Code, rec.Body)
	}
	relay := substrateRowsMatching(t, store, "access_denied", 1, `"reason":"session_not_owner"`)
	if len(relay) != 1 || !strings.Contains(relay[0], `"token_person":"https://idp.example#bob"`) || !strings.Contains(relay[0], `"actor":"eng-web/alice-1"`) {
		t.Fatalf("relay refusal rows %v", relay)
	}
}
