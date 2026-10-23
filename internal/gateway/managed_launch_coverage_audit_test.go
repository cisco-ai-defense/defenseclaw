// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestManagedLaunchCoverageAuditRequiresRootAndRecordsTheUninspectedProcess(t *testing.T) {
	fixture, api, _ := newCLIObservabilityV8Fixture(t)
	handler := api.managedHookPeerAuth(newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil), api.managedHookSocketMux())
	send := func(uid int, body string) int {
		request := httptest.NewRequest(http.MethodPost, managed.LaunchCoverageReportPath, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "enterprise-lifecycle")
		request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{UID: uid}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	valid := `{"connector":"opencode","reason":"opencode_pure","pid":4242,"uid":3000000000,"started_at":"2026-10-22T23:30:00Z"}`
	if got := send(1001, valid); got != http.StatusForbidden {
		t.Fatalf("ordinary user wrote a launch audit: HTTP %d", got)
	}
	for _, invalid := range []string{
		`{"connector":"opencode","reason":"allow","pid":4242,"uid":1001,"started_at":"2026-10-22T23:30:00Z"}`,
		`{"connector":"opencode","reason":"opencode_pure","pid":0,"uid":1001,"started_at":"2026-10-22T23:30:00Z"}`,
		`{"connector":"opencode","reason":"opencode_pure","pid":4242,"uid":1001,"started_at":"invalid"}`,
		valid + `{}`,
	} {
		if got := send(0, invalid); got != http.StatusBadRequest {
			t.Fatalf("invalid report %q accepted: HTTP %d", invalid, got)
		}
	}
	if got := send(0, valid); got != http.StatusNoContent {
		t.Fatalf("root launch audit HTTP %d", got)
	}
	events, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	var matches int
	for _, event := range events {
		if event.Action == "alert" && event.Structured["defenseclaw.schema.error_code"] == "managed_launch_uninspected" {
			matches++
			if event.Structured["defenseclaw.health.subsystem"] != "managed-launch-coverage" ||
				!strings.Contains(event.Details, `"connector":"opencode"`) ||
				!strings.Contains(event.Details, `"coverage_reason":"opencode_pure"`) ||
				!strings.Contains(event.Details, `"process_pid":4242`) {
				t.Fatalf("incomplete audit row: %+v", event)
			}
		}
	}
	if matches != 1 {
		t.Fatalf("recorded %d OpenCode launch alerts, want one", matches)
	}
}
