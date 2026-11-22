// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-0120: a relay guard trip is a HIGH audit row naming the actor and
// the reason, not only a relay log line.
func TestSubstrateRelayTamperIsAudited(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	body := `{"connector":"antigravity","reason":"/sandbox/.gemini was moved, replaced or removed\u0007"}`
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTamper, "tok-bob", body); rec.Code != http.StatusNoContent {
		t.Fatalf("tamper report: %d %s", rec.Code, rec.Body)
	}
	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	var row *audit.Event
	for i := range events {
		if strings.Contains(events[i].Details, "relay_guard_tamper") {
			row = &events[i]
		}
	}
	if row == nil || row.Severity != "HIGH" || !strings.Contains(row.Details, "integrity guard stopped the agent of eng-web/bob-1") ||
		!strings.Contains(row.Details, "/sandbox/.gemini was moved, replaced or removed") || !strings.Contains(row.Details, `"connector":"antigravity"`) {
		t.Fatalf("audit row %+v (of %d)", row, len(events))
	}
	if rec := f.do(t, f.actor, http.MethodGet, substrateRelayTamper, "tok-bob", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTamper, "tok-bob", "{"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body: %d", rec.Code)
	}
}
