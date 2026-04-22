// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleEgressEvent_RejectsUnauth is a regression guard for the
// silent-success bug: authenticateRequest only emits an audit event
// on failure; the handler is responsible for writing the 401. Before
// the fix, an unauthenticated caller got a default-200 response and
// silently dropped telemetry.
func TestHandleEgressEvent_RejectsUnauth(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	proxy.gatewayToken = "test-token"

	body := []byte(`{"target_host":"api.openai.com","branch":"known","decision":"allow"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/events/egress", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.handleEgressEvent(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without X-DC-Auth, got %d; body=%q", rec.Code, rec.Body.String())
	}
}

// TestHandleEgressEvent_RejectsInvalidEnums locks in the
// server-side branch/decision enum guard. A malformed TS client
// must not be able to inject arbitrary strings into the downstream
// event contract.
func TestHandleEgressEvent_RejectsInvalidEnums(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	proxy.gatewayToken = "test-token"

	body := []byte(`{"target_host":"api.openai.com","branch":"forbidden","decision":"allow"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/events/egress", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Auth", "Bearer test-token")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleEgressEvent(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid branch, got %d; body=%q", rec.Code, rec.Body.String())
	}
}

// TestHandleEgressEvent_RejectsOversizeBody enforces the 8 KiB read
// cap. A rogue TS client sending a giant payload must not be able
// to exhaust memory on the (loopback-only) egress endpoint.
func TestHandleEgressEvent_RejectsOversizeBody(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	proxy.gatewayToken = "test-token"

	// Construct a body that's ~16 KiB — well over the handler's
	// 8 KiB LimitReader cap. The result is truncated JSON, so the
	// unmarshal must fail with 400.
	big := bytes.Repeat([]byte(`"a"`), 16*1024/3)
	body := []byte(`{"target_host":"api.openai.com","branch":"known","decision":"allow","reason":` + string(big) + `}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/events/egress", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Auth", "Bearer test-token")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleEgressEvent(rec, req)

	// Accept either 400 (truncated JSON) or 413-like behaviour.
	// Key assertion: we did NOT silently accept (204) and we did
	// NOT OOM the handler.
	if rec.Code == http.StatusNoContent {
		t.Fatalf("oversize body silently accepted: body=%q", rec.Body.String())
	}
	if rec.Code >= 500 {
		t.Fatalf("oversize body crashed handler: %d %s", rec.Code, rec.Body.String())
	}
}

// TestHandleEgressEvent_RejectsNonPOST locks in the method allow-list.
func TestHandleEgressEvent_RejectsNonPOST(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/v1/events/egress", nil)
		rec := httptest.NewRecorder()
		proxy.handleEgressEvent(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d (body=%s)",
				method, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
}
