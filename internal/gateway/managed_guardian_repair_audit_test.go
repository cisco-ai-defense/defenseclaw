// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestManagedGuardianRepairAuditRequiresRootAndWritesRepairRow(t *testing.T) {
	fixture, api, _ := newCLIObservabilityV8Fixture(t)
	handler := api.managedHookPeerAuth(newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil), api.managedHookSocketMux())
	send := func(uid int, body string) int {
		request := httptest.NewRequest(http.MethodPost, managedGuardianRepairAuditPath, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "hook-guardian")
		request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{UID: uid}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	valid := `{"user":"alice","uid":1001,"connector":"opencode"}`
	if status := send(1001, valid); status != http.StatusForbidden {
		t.Fatalf("standard user report status=%d, want 403", status)
	}
	for _, invalid := range []string{
		`{"user":"","connector":"opencode"}`,
		`{"user":"alice","connector":"opencode"}`,
		`{"user":"alice","uid":-1,"connector":"opencode"}`,
		`{"user":"alice","uid":2147483648,"connector":"opencode"}`,
		`{"user":"alice","connector":"opencode","action":"allow"}`,
		valid + `{}`,
	} {
		if status := send(0, invalid); status != http.StatusBadRequest {
			t.Fatalf("invalid report %q status=%d, want 400", invalid, status)
		}
	}
	if status := send(0, valid); status != http.StatusNoContent {
		t.Fatalf("root guardian report status=%d, want 204", status)
	}
	events, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	var repairEvents []audit.Event
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHookRepaired) {
			repairEvents = append(repairEvents, event)
		}
	}
	if len(repairEvents) != 1 || repairEvents[0].Target != "opencode" || repairEvents[0].Connector != "opencode" ||
		repairEvents[0].Severity != "HIGH" || !strings.Contains(repairEvents[0].Details, "alice") ||
		repairEvents[0].Structured[auditUserIDKey] != "1001" ||
		repairEvents[0].Structured[auditUserIDKindKey] != "posix_uid" ||
		repairEvents[0].Structured[auditUserNameKey] != "alice" {
		t.Fatalf("repair audit events = %+v", repairEvents)
	}
}

// GAP-0754: a report that names the restored element is audited with it, and
// a report without one keeps the whole-target row.
func TestManagedGuardianRepairAuditNamesTheRestoredElement(t *testing.T) {
	fixture, api, _ := newCLIObservabilityV8Fixture(t)
	handler := api.managedHookPeerAuth(newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil), api.managedHookSocketMux())
	send := func(body string) int {
		request := httptest.NewRequest(http.MethodPost, managedGuardianRepairAuditPath, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "hook-guardian")
		request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{UID: 0}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	for _, invalid := range []string{
		`{"user":"alice","uid":1001,"connector":"hermes","element":"\n"}`,
		`{"user":"alice","uid":1001,"connector":"hermes","element":"` + strings.Repeat("x", 300) + `"}`,
		`{"user":"alice","uid":1001,"connector":"hermes","element":"hook entry","change":"overwritten"}`,
	} {
		if status := send(invalid); status != http.StatusBadRequest {
			t.Fatalf("invalid element report status=%d, want 400", status)
		}
	}
	for _, body := range []string{
		`{"user":"alice","uid":1001,"connector":"hermes","element":"hook runtime file hermes-hook.sh"}`,
		`{"user":"alice","uid":1001,"connector":"hermes","element":"hook entry"}`,
		`{"user":"alice","uid":1001,"connector":"hermes","element":"hook runtime file hermes-hook.sh","change":"appended"}`,
		`{"user":"alice","uid":1001,"connector":"hermes","element":"hook entry","change":"edited"}`,
		`{"user":"alice","uid":1001,"connector":"hermes","element":"hook runtime file hermes-hook.sh","change":"deleted"}`,
		`{"user":"alice","uid":1001,"connector":"opencode"}`,
	} {
		if status := send(body); status != http.StatusNoContent {
			t.Fatalf("report %s status=%d, want 204", body, status)
		}
	}
	events, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	details := map[string]string{}
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHookRepaired) {
			if event.Severity != "HIGH" {
				t.Fatalf("repair event severity = %q, want HIGH", event.Severity)
			}
			details[event.Details] = event.Connector
		}
	}
	want := map[string]string{
		"restored hook runtime file hermes-hook.sh for user alice":                  "hermes",
		"restored hook entry for user alice":                                        "hermes",
		"restored hook runtime file hermes-hook.sh after an append for user alice":  "hermes",
		"restored hook entry after an edit for user alice":                          "hermes",
		"restored hook runtime file hermes-hook.sh after a deletion for user alice": "hermes",
		"re-installed hook entries for user alice":                                  "opencode",
	}
	if len(details) != len(want) {
		t.Fatalf("repair events = %v, want %v", details, want)
	}
	for detail, connectorName := range want {
		if details[detail] != connectorName {
			t.Fatalf("repair events = %v, want %v", details, want)
		}
	}
}
