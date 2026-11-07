//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type g693AuditTransport func(*http.Request) (*http.Response, error)

func (f g693AuditTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestGAP0693GuardianRemovedReportUsesTrustedSocket(t *testing.T) {
	previousTransport, previousFactory := enterpriseHookStandaloneHookTransport, guardianAuditClientFactory
	t.Cleanup(func() {
		enterpriseHookStandaloneHookTransport, guardianAuditClientFactory = previousTransport, previousFactory
	})
	const socket = "/run/defenseclaw-hook/hook.sock"
	enterpriseHookStandaloneHookTransport = func() (string, int, error) { return socket, 995, nil }
	calls := 0
	guardianAuditClientFactory = func(_ time.Duration, gotSocket string, uid int) (*http.Client, error) {
		if gotSocket != socket || uid != 995 {
			t.Fatalf("audit transport = %q, %d", gotSocket, uid)
		}
		return &http.Client{Transport: g693AuditTransport(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.Method != http.MethodPost || request.URL.Path != enterpriseHookGuardianRemovedAuditPath ||
				request.Header.Get("X-DefenseClaw-Client") != "hook-guardian" {
				t.Fatalf("audit request = %s %s, headers=%v", request.Method, request.URL, request.Header)
			}
			var report enterpriseHookGuardianRemovedAuditReport
			if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
				t.Fatal(err)
			}
			if report.User != "removed" || report.Connector != "hermes" || report.UID == nil || *report.UID != 508 {
				t.Fatalf("audit report = %+v", report)
			}
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
		})}, nil
	}
	removed := enterpriseHookReconcileRow{User: "removed", UID: 508, Connector: "hermes", Removed: true}
	reportEnterpriseHookGuardianRemoved(context.Background(), socket, []enterpriseHookReconcileRow{removed})
	if calls != 1 {
		t.Fatalf("audit sends = %d, want one", calls)
	}
	reportEnterpriseHookGuardianRemoved(context.Background(), "/another/socket", []enterpriseHookReconcileRow{removed})
	if calls != 1 {
		t.Fatalf("untrusted socket received an audit report")
	}
}
