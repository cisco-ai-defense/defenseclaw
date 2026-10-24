// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func exemptAuditRows(t *testing.T, store *audit.Store) int {
	t.Helper()
	events, err := store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, ev := range events {
		if ev.Action == string(audit.ActionEnterpriseExemptUser) {
			rows++
		}
	}
	return rows
}

// GAP-1285: an exempt account's enterprise-exempt-user row says the call was
// allowed and inspected, so it is written after the hook handler answered
// the call, not for a call the handler refused. A row the audit store did
// not take leaves the interval open for the next call.
func TestExemptUserRowFollowsAnAnsweredCallAndAStoredWrite(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := fixture.store
	logger := audit.NewLogger(store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	api := &APIServer{logger: logger}
	peer := managedHookPeer{UID: 4285, Name: "dcm-exempt"}
	const route = "/api/v1/claudecode/hook"
	status := http.StatusBadRequest
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
	serve := func() {
		request := httptest.NewRequest(http.MethodPost, route, nil)
		api.serveEnterpriseExemptHookCall(httptest.NewRecorder(), request, handler, peer, "claudecode", route, false)
	}
	serve()
	if rows := exemptAuditRows(t, store); rows != 0 {
		t.Fatalf("a call the handler refused wrote %d enterprise-exempt-user rows, want 0", rows)
	}
	status = http.StatusOK
	serve()
	serve()
	if rows := exemptAuditRows(t, store); rows != 1 {
		t.Fatalf("answered calls wrote %d enterprise-exempt-user rows, want 1 in the interval", rows)
	}

	// A write the audit store refuses (here: a logger with no runtime) does
	// not start the interval.
	retry := &APIServer{logger: audit.NewLogger(store)}
	now := time.Now()
	if retry.auditEnterpriseExemptUser(t.Context(), peer, "codex", route, now) {
		t.Fatal("a refused audit write was reported as written")
	}
	retry.logger = logger
	if !retry.auditEnterpriseExemptUser(t.Context(), peer, "codex", route, now.Add(time.Second)) {
		t.Fatal("the call after a refused audit write wrote no row")
	}
}

// A Codex notification is recorded, not inspected: an exempt account's
// notification (malformed or not, the notifier answers 2xx) writes no
// enterprise-exempt-user row and does not start the interval, so the
// account's next inspected Codex call writes one.
func TestExemptUserNotificationLeavesTheAuditIntervalOpen(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := fixture.store
	logger := audit.NewLogger(store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	api := &APIServer{logger: logger}
	peer := managedHookPeer{UID: 4286, Name: "dcm-exempt"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	serve := func(route string, inspect bool) {
		request := httptest.NewRequest(http.MethodPost, route, bytes.NewBufferString("{not json"))
		api.serveEnterpriseExemptHookCall(httptest.NewRecorder(), request, handler, peer, "codex", route, inspect)
	}
	serve("/api/v1/codex/notify", false)
	if rows := exemptAuditRows(t, store); rows != 0 {
		t.Fatalf("a Codex notification wrote %d enterprise-exempt-user rows, want 0", rows)
	}
	serve("/api/v1/codex/hook", false)
	if rows := exemptAuditRows(t, store); rows != 1 {
		t.Fatalf("the inspected Codex call after a notification wrote %d rows, want 1", rows)
	}
	serve("/api/v1/inspect/tool", true)
	if rows := exemptAuditRows(t, store); rows != 1 {
		t.Fatalf("a second inspected call in the interval wrote %d rows in all, want 1", rows)
	}
}
