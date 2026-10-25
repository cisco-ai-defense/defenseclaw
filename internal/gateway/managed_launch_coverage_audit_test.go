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
	kiro := `{"connector":"kiro","reason":"kiro_resume_placement_unverified","pid":7192,"uid":3000000000,"started_at":"2026-10-22T23:31:00Z"}`
	if got := send(0, kiro); got != http.StatusNoContent {
		t.Fatalf("Kiro resume launch audit HTTP %d", got)
	}
	events, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	var matches, kiroMatches int
	for _, event := range events {
		if event.Action == "alert" && event.Structured["defenseclaw.schema.error_code"] == "managed_launch_uninspected" {
			matches++
			if event.Structured["defenseclaw.health.subsystem"] != "managed-launch-coverage" {
				t.Fatalf("incomplete audit row: %+v", event)
			}
			if strings.Contains(event.Details, `"connector":"kiro"`) {
				kiroMatches++
				if !strings.Contains(event.Details, `"coverage_reason":"kiro_resume_placement_unverified"`) ||
					!strings.Contains(event.Details, `"process_pid":7192`) {
					t.Fatalf("Kiro resume audit row: %+v", event)
				}
			} else if !strings.Contains(event.Details, `"connector":"opencode"`) ||
				!strings.Contains(event.Details, `"coverage_reason":"opencode_pure"`) ||
				!strings.Contains(event.Details, `"process_pid":4242`) {
				t.Fatalf("OpenCode audit row: %+v", event)
			}
		}
	}
	if matches != 2 || kiroMatches != 1 {
		t.Fatalf("recorded %d launch alerts, %d Kiro resume alerts", matches, kiroMatches)
	}
}

func TestManagedInstallCoverageAuditNamesTheUnprotectedCopy(t *testing.T) {
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
	valid := `{"connector":"claudecode","reason":"unsupported_installed_version","uid":94404135,"install_path":"/home/eng1/sa104r8-old/node_modules/@anthropic-ai/claude-code","version":"2.0.77"}`
	if got := send(94404135, valid); got != http.StatusForbidden {
		t.Fatalf("user submitted install audit: HTTP %d", got)
	}
	for _, invalid := range []string{
		`{"connector":"claudecode","reason":"unsupported_installed_version","uid":94404135,"install_path":"../old","version":"2.0.77"}`,
		`{"connector":"claudecode","reason":"unsupported_installed_version","pid":42,"uid":94404135,"install_path":"/home/eng1/old","version":"2.0.77"}`,
	} {
		if got := send(0, invalid); got != http.StatusBadRequest {
			t.Fatalf("invalid install report accepted: HTTP %d", got)
		}
	}
	if got := send(0, valid); got != http.StatusNoContent {
		t.Fatalf("root install audit: HTTP %d", got)
	}
	events, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Structured["defenseclaw.schema.error_code"] != "managed_agent_install_unprotected" {
			continue
		}
		found = true
		if event.Structured["defenseclaw.health.subsystem"] != "managed-install-coverage" ||
			!strings.Contains(event.Details, `"agent_version":"2.0.77"`) ||
			!strings.Contains(event.Details, `"agent_install_path":"/home/eng1/sa104r8-old/node_modules/@anthropic-ai/claude-code"`) {
			t.Fatalf("install audit lost copy identity: %+v", event)
		}
	}
	if !found {
		t.Fatal("no unprotected install audit row")
	}
}

// GAP-1420: an installed Hermes the enumerator could not enroll is reported
// NOT COVERED and audited as an unprotected install, like Claude Code, Codex
// and Copilot; the gateway refused that report for Hermes (HTTP 400).
func TestManagedInstallCoverageAuditAcceptsAnUnenrolledHermes(t *testing.T) {
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
	valid := `{"connector":"hermes","reason":"unsupported_installed_version","uid":1001,"install_path":"/home/alice/.local/bin/hermes","version":"0.18.0"}`
	if got := send(1001, valid); got != http.StatusForbidden {
		t.Fatalf("user submitted a Hermes install audit: HTTP %d", got)
	}
	if got := send(0, `{"connector":"hermes","reason":"unsupported_installed_version","uid":1001,"install_path":"../hermes","version":"0.18.0"}`); got != http.StatusBadRequest {
		t.Fatalf("relative Hermes install path accepted: HTTP %d", got)
	}
	if got := send(0, valid); got != http.StatusNoContent {
		t.Fatalf("root Hermes install audit: HTTP %d", got)
	}
	if got := send(0, `{"connector":"hermes","reason":"installed_version_unverified","uid":1001,"install_path":"/home/alice/.local/bin/hermes"}`); got != http.StatusNoContent {
		t.Fatalf("root Hermes unknown-version install audit: HTTP %d", got)
	}
	events, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Structured["defenseclaw.schema.error_code"] == "managed_agent_install_unprotected" &&
			strings.Contains(event.Details, `"connector":"hermes"`) && strings.Contains(event.Details, `"agent_version":"0.18.0"`) {
			return
		}
	}
	t.Fatal("no unprotected Hermes install audit row")
}

func TestManagedHermesSessionHomeLimitAudit(t *testing.T) {
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
	valid := `{"connector":"hermes","reason":"session_only_hermes_home_unobservable","uid":0}`
	if got := send(1001, valid); got != http.StatusForbidden {
		t.Fatalf("ordinary user wrote a Hermes coverage alert: HTTP %d", got)
	}
	for _, invalid := range []string{
		`{"connector":"codex","reason":"session_only_hermes_home_unobservable","uid":0}`,
		`{"connector":"hermes","reason":"session_only_hermes_home_unobservable","uid":0,"pid":42}`,
		`{"connector":"hermes","reason":"session_only_hermes_home_unobservable","uid":0,"install_path":"/tmp/other"}`,
	} {
		if got := send(0, invalid); got != http.StatusBadRequest {
			t.Fatalf("invalid Hermes coverage alert %q accepted: HTTP %d", invalid, got)
		}
	}
	if got := send(0, valid); got != http.StatusNoContent {
		t.Fatalf("root Hermes coverage audit: HTTP %d", got)
	}
	events, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Structured["defenseclaw.schema.error_code"] == "managed_hermes_session_home_not_covered" {
			if event.Structured["defenseclaw.health.subsystem"] != "managed-install-coverage" ||
				!strings.Contains(event.Details, `"coverage_reason":"session_only_hermes_home_unobservable"`) ||
				!strings.Contains(event.Details, `"coverage_state":"incomplete"`) {
				t.Fatalf("Hermes coverage audit lost the limit: %+v", event)
			}
			return
		}
	}
	t.Fatal("no Hermes session-home coverage alert")
}
