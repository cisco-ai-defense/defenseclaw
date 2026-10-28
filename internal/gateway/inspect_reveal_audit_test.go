// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestInspectRevealPersistsWhenComplianceCollectionIsOff(t *testing.T) {
	for _, tc := range []struct {
		name, route, body string
		handle            func(*APIServer, http.ResponseWriter, *http.Request)
	}{
		{"tool", "/api/v1/inspect/tool", piiPayload, (*APIServer).handleInspectTool},
		{"request", "/api/v1/inspect/request", `{"content":"leaked secret ` + piiLiteral + `"}`, (*APIServer).handleInspectRequest},
		{"response", "/api/v1/inspect/response", `{"content":"leaked secret ` + piiLiteral + `"}`, (*APIServer).handleInspectResponse},
		{"tool-response", "/api/v1/inspect/tool-response", `{"tool":"bash","output":"leaked secret ` + piiLiteral + `"}`, (*APIServer).handleInspectToolResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSidecarRuntimeFixtureCollectingNo(t, nil, observability.BucketComplianceActivity)
			logger := audit.NewLogger(fixture.store)
			logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime})
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
			req := httptest.NewRequest(http.MethodPost, tc.route, bytes.NewBufferString(tc.body))
			req.Header.Set(revealHeader, "1")
			w := httptest.NewRecorder()
			tc.handle(api, w, req)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), piiLiteral) {
				t.Fatalf("reveal status=%d body=%s", w.Code, w.Body.String())
			}
			events, err := fixture.store.ListEvents(100)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events {
				if event.Action == string(audit.ActionInspectReveal) {
					return
				}
			}
			t.Fatal("raw inspect response has no persisted reveal row")
		})
	}
}

// Every inspect route that can return matched evidence must leave an
// attributable, content-free reveal record before returning that evidence.
func TestEveryInspectEvidenceRevealIsAudited(t *testing.T) {
	for _, tc := range []struct {
		name, route, body string
		handle            func(*APIServer, http.ResponseWriter, *http.Request)
	}{
		{"tool", "/api/v1/inspect/tool", piiPayload, (*APIServer).handleInspectTool},
		{"request", "/api/v1/inspect/request", `{"content":"leaked secret ` + piiLiteral + `"}`, (*APIServer).handleInspectRequest},
		{"response", "/api/v1/inspect/response", `{"content":"leaked secret ` + piiLiteral + `"}`, (*APIServer).handleInspectResponse},
		{"tool-response", "/api/v1/inspect/tool-response", `{"tool":"bash","output":"leaked secret ` + piiLiteral + `"}`, (*APIServer).handleInspectToolResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := testAPIServerWithConfig(t, "action")
			for _, header := range []string{"", "true", "1"} {
				req := httptest.NewRequest(http.MethodPost, tc.route, bytes.NewBufferString(tc.body))
				req.RemoteAddr = "127.0.0.1:41234"
				if header != "" {
					req.Header.Set(revealHeader, header)
				}
				w := httptest.NewRecorder()
				tc.handle(api, w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("header %q: status %d: %s", header, w.Code, w.Body.String())
				}
				if got := strings.Contains(w.Body.String(), piiLiteral); got != (header == "1") {
					t.Errorf("header %q: raw evidence present = %v", header, got)
				}
			}
			events, err := api.store.ListEvents(100)
			if err != nil {
				t.Fatal(err)
			}
			var reveals []audit.Event
			for _, event := range events {
				if event.Action == string(audit.ActionInspectReveal) {
					reveals = append(reveals, event)
				}
			}
			if len(reveals) != 1 {
				t.Fatalf("reveal events = %d, want 1 for the exact header", len(reveals))
			}
			if got := reveals[0].Structured["route"]; got != tc.route {
				t.Errorf("reveal route = %v, want %s", got, tc.route)
			}
			if strings.Contains(reveals[0].Details, piiLiteral) || !strings.Contains(reveals[0].Details, "127.0.0.1:41234") {
				t.Errorf("reveal details contain evidence or omit caller address: %q", reveals[0].Details)
			}
			if err := api.store.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, tc.route, bytes.NewBufferString(tc.body))
			req.Header.Set(revealHeader, "1")
			w := httptest.NewRecorder()
			tc.handle(api, w, req)
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), piiLiteral) {
				t.Errorf("audit unavailable: status=%d body=%q, want no raw reveal", w.Code, w.Body.String())
			}
		})
	}
}
