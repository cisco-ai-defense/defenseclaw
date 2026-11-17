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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

func substrateRows(t *testing.T, store *audit.Store, event string) []audit.Event {
	t.Helper()
	events, err := store.ListEvents(500)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range events {
		if strings.Contains(e.Details, `"event":"`+event+`"`) {
			out = append(out, e)
		}
	}
	return out
}

// GAP-0434: a refused attempt on another person's agent answers like a
// missing one (404 actor_not_found) and is audited as the person who tried,
// once per window with a count; nothing names the owner. A relay session
// check refused for another actor is audited too.
func TestSubstrateRefusedCrossPersonAttemptIsAuditedAsTheCallerGAP0434(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	missing := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/nobody", "p-alice", "")
	for range 5 {
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/bob-1", "p-alice", "")
		if rec.Code != missing.Code || reasonOf(t, rec) != reasonOf(t, missing) || rec.Code != http.StatusNotFound {
			t.Fatalf("another person's agent answers %d %s; a missing one %d %s", rec.Code, rec.Body, missing.Code, missing.Body)
		}
	}
	rows := substrateRows(t, store, "access_denied")
	if len(rows) != 1 {
		t.Fatalf("%d access_denied rows for 5 attempts in one window, want 1: %+v", len(rows), rows)
	}
	d := rows[0].Details
	for _, want := range []string{`"principal":"alice@example.com"`, `"person_id":"https://idp.example#alice"`,
		`"target":"eng-web/bob-1"`, `"outcome":"denied"`, `"reason":"not_owner"`, `"count":1,`, `GET /api/v1/substrate/actors/{atespace}/{name}`} {
		if !strings.Contains(d, want) {
			t.Errorf("row has no %s: %s", want, d)
		}
	}
	if strings.Contains(d, "#bob") || strings.Contains(d, "bob@example.com") || strings.Contains(d, "p-alice") {
		t.Errorf("row names the owner or carries the token: %s", d)
	}

	// The relay's session check: alice's session token presented by bob's
	// actor is refused and audited with the person the token names.
	tok, _, err := f.sessions.Issue(alice.ID(), identity.SessionActor{Atespace: "eng-web", Name: "alice-1", UID: subUID1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayVerify, "tok-bob", string(body)); rec.Code != http.StatusForbidden {
		t.Fatalf("relay verify for another actor: %d %s", rec.Code, rec.Body)
	}
	var relay []string
	for _, e := range substrateRows(t, store, "access_denied") {
		if strings.Contains(e.Details, `"reason":"session_for_another_actor"`) {
			relay = append(relay, e.Details)
		}
	}
	if len(relay) != 1 || !strings.Contains(relay[0], `"person_id":"https://idp.example#alice"`) || !strings.Contains(relay[0], `"target":"eng-web/bob-1"`) ||
		strings.Contains(relay[0], tok) {
		t.Fatalf("relay refusal rows %v", relay)
	}
}
