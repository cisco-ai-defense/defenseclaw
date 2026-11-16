// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCSRFRefusalsAreJSON is GAP-0569: the CSRF gates in front of the JSON
// API refuse with a JSON body, so the refusal is served as application/json
// (not http.Error's text/plain). Status codes and bodies are unchanged.
func TestCSRFRefusalsAreJSON(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	gates := map[string]http.Handler{
		"api":   (&APIServer{}).apiCSRFProtect(next),
		"plain": csrfProtect(next),
	}
	for name, gate := range gates {
		for _, row := range []struct {
			name    string
			headers map[string]string
			status  int
			body    string
		}{
			{"no Content-Type", map[string]string{"X-DefenseClaw-Client": "cli"}, http.StatusUnsupportedMediaType,
				"Content-Type must be application/json"},
			{"no client header", map[string]string{"Content-Type": "application/json"}, http.StatusForbidden,
				"missing X-DefenseClaw-Client header"},
			{"cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden,
				"cross-site request rejected"},
		} {
			t.Run(name+"/"+row.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/token/rotate", strings.NewReader("{}"))
				for k, v := range row.headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()
				gate.ServeHTTP(rec, req)
				if rec.Code != row.status {
					t.Fatalf("status = %d, want %d", rec.Code, row.status)
				}
				if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
					t.Fatalf("Content-Type = %q, want application/json", ct)
				}
				if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
					t.Fatal("missing X-Content-Type-Options: nosniff")
				}
				var body struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error != row.body {
					t.Fatalf("body %q: error=%q err=%v", rec.Body.String(), body.Error, err)
				}
			})
		}
	}
}
