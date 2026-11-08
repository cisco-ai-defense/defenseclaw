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

func TestGAP0693ManagedGuardianAccountRemovedAuditRequiresRoot(t *testing.T) {
	fixture, api, _ := newCLIObservabilityV8Fixture(t)
	handler := api.managedHookPeerAuth(newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil), api.managedHookSocketMux())
	send := func(uid int, body string) int {
		request := httptest.NewRequest(http.MethodPost, managedGuardianAccountRemovedAuditPath, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "hook-guardian")
		request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{UID: uid}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	valid := `{"user":"removed","uid":1001,"connector":"hermes"}`
	if status := send(1001, valid); status != http.StatusForbidden {
		t.Fatalf("non-guardian report status = %d", status)
	}
	for _, invalid := range []string{
		`{"user":"","connector":"hermes"}`,
		`{"user":"removed","uid":0,"connector":"hermes"}`,
		`{"user":"removed","uid":2147483648,"connector":"hermes"}`,
		`{"user":"removed","connector":"hermes","action":"allow"}`,
		valid + `{}`,
	} {
		if status := send(0, invalid); status != http.StatusBadRequest {
			t.Fatalf("invalid removal report %q status=%d", invalid, status)
		}
	}
	if status := send(0, valid); status != http.StatusNoContent {
		t.Fatalf("guardian removal report status=%d", status)
	}
	events, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	var removed []audit.Event
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHookAccountRemoved) {
			removed = append(removed, event)
		}
	}
	if len(removed) != 1 || removed[0].Connector != "hermes" || removed[0].Target != "hermes" ||
		removed[0].Structured[auditUserIDKey] != "1001" || removed[0].Structured[auditUserNameKey] != "removed" {
		t.Fatalf("removed target audit rows = %+v", removed)
	}
}
