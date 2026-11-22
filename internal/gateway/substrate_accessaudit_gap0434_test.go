// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// substrateRowsMatching returns the rows of event whose details contain
// every want; the access rows are written off the request path, so it
// waits up to 3 s for at least min of them, then returns what it found.
func substrateRowsMatching(t *testing.T, store *audit.Store, event string, min int, want ...string) []string {
	t.Helper()
	var out []string
	for deadline := time.Now().Add(3 * time.Second); ; {
		out = out[:0]
		events, err := store.ListEvents(500)
		if err != nil {
			t.Fatal(err)
		}
	next:
		for _, e := range events {
			if !strings.Contains(e.Details, `"event":"`+event+`"`) {
				continue
			}
			for _, w := range want {
				if !strings.Contains(e.Details, w) {
					continue next
				}
			}
			out = append(out, e.Severity+" "+e.Details)
		}
		if len(out) >= min || time.Now().After(deadline) {
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// GAP-0434: a refused attempt on another person's agent answers like a
// missing one (404 actor_not_found) and is audited as the person who tried,
// once per window and target with a count; nothing names the owner. A relay
// session check refused for another actor is audited as the calling actor
// and its owner, with the token's person apart.
func TestSubstrateRefusedCrossPersonAttemptIsAuditedAsTheCallerGAP0434(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	const bob2 = "8f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4e"
	if err := f.regs.Put(context.Background(), registry.Registration{Atespace: "eng-web", Name: "bob-2", UID: bob2,
		Connector: "codex", Profile: "eng", Person: ownerOf(bob)}); err != nil {
		t.Fatal(err)
	}
	f.live["eng-web/bob-2"] = identity.LiveActor{UID: bob2, State: identity.ActorRunning}

	missing := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/nobody", "p-alice", "")
	for range 5 {
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/bob-1", "p-alice", "")
		if rec.Code != missing.Code || reasonOf(t, rec) != reasonOf(t, missing) || rec.Code != http.StatusNotFound {
			t.Fatalf("another person's agent answers %d %s; a missing one %d %s", rec.Code, rec.Body, missing.Code, missing.Body)
		}
	}
	// A probe of a second target in the same minute is not hidden by the
	// first.
	f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/bob-2", "p-alice", "")

	rows := substrateRowsMatching(t, store, "access_denied", 2, `"reason":"not_owner"`)
	if len(rows) != 2 {
		t.Fatalf("%d not_owner rows for 6 attempts on 2 agents in one window, want 2: %v", len(rows), rows)
	}
	all := strings.Join(rows, "\n")
	for _, want := range []string{`"principal":"alice@example.com"`, `"person_id":"https://idp.example#alice"`,
		`"target":"eng-web/bob-1"`, `"target":"eng-web/bob-2"`, `"outcome":"denied"`, `"count":1,`,
		`GET /api/v1/substrate/actors/{atespace}/{name}`} {
		if !strings.Contains(all, want) {
			t.Errorf("rows have no %s:\n%s", want, all)
		}
	}
	if strings.Contains(all, "#bob") || strings.Contains(all, "bob@example.com") || strings.Contains(all, "p-alice") {
		t.Errorf("a row names the owner or carries the token:\n%s", all)
	}

	// The relay's session check: alice's session token presented to bob's
	// actor is refused; the row is the calling actor's (and its owner's),
	// the token's person is recorded apart.
	tok, _, err := f.sessions.Issue(identity.SignInOf(alice), identity.SessionActor{Atespace: "eng-web", Name: "alice-1", UID: subUID1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayVerify, "tok-bob", string(body)); rec.Code != http.StatusForbidden {
		t.Fatalf("relay verify for another actor: %d %s", rec.Code, rec.Body)
	}
	relay := substrateRowsMatching(t, store, "access_denied", 1, `"reason":"session_for_another_actor"`)
	if len(relay) != 1 || !strings.Contains(relay[0], `"actor":"eng-web/bob-1"`) || !strings.Contains(relay[0], `"actor_uid":"`+subUID2+`"`) ||
		!strings.Contains(relay[0], `"person_id":"https://idp.example#bob"`) || !strings.Contains(relay[0], `"token_person":"https://idp.example#alice"`) ||
		strings.Contains(relay[0], tok) {
		t.Fatalf("relay refusal rows %v", relay)
	}
}
