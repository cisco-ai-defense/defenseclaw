// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestAlertAcknowledgementV8UsesCanonicalCASAndPreservesEventSeverity(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{store: fixture.store, logger: fixture.logger}
	fixture.sidecar.setAPIServer(api)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, fixture.raw,
	)
	if err != nil || !bound || api.observabilityV8RuntimeEmitter() == nil {
		t.Fatalf("bootstrap bound=%t runtime=%T error=%v", bound, api.observabilityV8RuntimeEmitter(), err)
	}
	event := audit.Event{
		ID: "alert-target-1", Timestamp: time.Now().UTC(), Action: "scan-finding",
		Target: "skill://demo", Actor: "scanner", Details: "unsafe instruction", Severity: "HIGH",
	}
	if err := api.store.LogEvent(event); err != nil {
		t.Fatal(err)
	}
	if err := api.store.LogEvent(audit.Event{
		ID: "platform-event-1", Timestamp: time.Now().UTC(), Action: "sidecar-start",
		Target: "gateway", Actor: "system", Details: "not an alert", Severity: "HIGH",
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, alertAcknowledgementV8Path, strings.NewReader(
		`{"operation_id":"alert-review-test","disposition":"acknowledged","severity":"HIGH"}`,
	))
	response := httptest.NewRecorder()
	api.handleAlertAcknowledgementV8(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"matched":1`) ||
		!strings.Contains(response.Body.String(), `"applied":1`) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	alerts, err := api.store.ListAlerts(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("active finding-scoped alerts after acknowledgement = %+v", alerts)
	}
	events, err := api.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	foundOriginal, foundCompliance := false, false
	for _, stored := range events {
		if stored.ID == event.ID {
			foundOriginal = stored.Severity == "HIGH"
		}
		if stored.Action == "alert.acknowledgement.requested" {
			foundCompliance = true
		}
	}
	if !foundOriginal || !foundCompliance {
		t.Fatalf("original severity/compliance preserved=%t/%t", foundOriginal, foundCompliance)
	}
}

func TestDerivedAlertOperationIDRemainsBoundedAndStable(t *testing.T) {
	base := strings.Repeat("a", 192)
	first := derivedAlertOperationID(base, "alert-1")
	second := derivedAlertOperationID(base, "alert-1")
	if first != second || len(first) > 256 || !strings.HasPrefix(first, base+"-") {
		t.Fatalf("derived operation id length=%d stable=%t", len(first), first == second)
	}
}

func TestAlertAcknowledgementV8RejectsClientSuppliedActor(t *testing.T) {
	_, err := decodeAlertAcknowledgementV8Request(strings.NewReader(
		`{"operation_id":"alert-review-test","actor":"forged:admin","disposition":"dismissed","severity":"HIGH"}`,
	))
	if err == nil {
		t.Fatal("client-controlled compliance actor was accepted")
	}
}

func TestAlertAcknowledgementV8UnavailableServerFailsClosed(t *testing.T) {
	var api *APIServer
	request := httptest.NewRequest(http.MethodPost, alertAcknowledgementV8Path, strings.NewReader(
		`{"operation_id":"alert-review-test","disposition":"dismissed","severity":"HIGH"}`,
	))
	response := httptest.NewRecorder()
	api.handleAlertAcknowledgementV8(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}
