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
