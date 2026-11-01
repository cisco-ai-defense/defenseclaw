// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1966: the gateway's authentication and rate-limit refusals carry a
// JSON body, so they are served as application/json (with nosniff), as
// reference/edge-connector/api.mdx says, not as text/plain. Status codes
// and bodies stay as they are.
func TestAuthAndRateLimitRefusalsAreJSON(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.Token = "gap1966-gateway-token"
	api := &APIServer{scannerCfg: cfg}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	limited := perIPRateLimiter(1, 1)(next)
	for _, row := range []struct {
		name    string
		handler http.Handler
		remote  string
		bearer  string
		repeat  int
		status  int
		body    string
	}{
		{"no token", api.tokenAuth(next), "127.0.0.1:41000", "", 1, http.StatusUnauthorized, "unauthorized"},
		{"wrong token", api.tokenAuth(next), "127.0.0.1:41000", "wrong", 1, http.StatusUnauthorized, "unauthorized"},
		{"rate limited", limited, "192.0.2.66:41000", "", 3, http.StatusTooManyRequests, "rate limit exceeded"},
	} {
		t.Run(row.name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			for i := 0; i < row.repeat; i++ {
				req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/token/rotate", strings.NewReader("{}"))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-DefenseClaw-Client", "cli")
				if row.bearer != "" {
					req.Header.Set("Authorization", "Bearer "+row.bearer)
				}
				req.RemoteAddr = row.remote
				rec = httptest.NewRecorder()
				row.handler.ServeHTTP(rec, req)
			}
			if rec.Code != row.status {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, row.status, rec.Body.String())
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
