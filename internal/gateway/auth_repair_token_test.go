// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// newAuthRepairedClient returns a client that booted on boot-token and then
// adopted rotated-token from openclaw.json through auth repair.
func newAuthRepairedClient(t *testing.T) *Client {
	t.Helper()
	home := t.TempDir()
	dataDir := testenv.PrivateTempDir(t)
	if err := os.MkdirAll(filepath.Join(home, ".openclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".openclaw", "openclaw.json"),
		[]byte(`{"gateway":{"auth":{"token":"rotated-token"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(&config.GatewayConfig{
		Token:         "boot-token",
		ClawHome:      home,
		DeviceKeyFile: filepath.Join(dataDir, "device.key"),
	}, dataDir)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.tryAuthRepair(errors.New("AUTH_TOKEN_MISMATCH"))
	if got := client.RefreshedToken(); got != "rotated-token" {
		t.Fatalf("RefreshedToken = %q, want rotated-token", got)
	}
	return client
}

// GAP-2259: when OpenClaw rotates gateway.auth.token, auth repair adopts the
// new token and writes it to .env, so the CLI presents it to the running
// API server (graceful shutdown during 'setup openclaw'). The API server
// must accept it next to its boot token instead of logging invalid_token.
func TestTokenAuth_AcceptsTokenAdoptedByAuthRepair(t *testing.T) {
	client := newAuthRepairedClient(t)

	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Gateway.Token = "boot-token"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), client, store, logger, cfg)
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for tok, want := range map[string]int{
		"boot-token":    http.StatusOK,
		"rotated-token": http.StatusOK,
		"other-token":   http.StatusUnauthorized,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/shutdown", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Errorf("token %s: status = %d, want %d", tok, rr.Code, want)
		}
	}
}

// GAP-2346: the guardrail proxy (LLM calls and /v1/events/egress from the
// OpenClaw plugin) must accept the rotated token next to the boot token too,
// otherwise OpenClaw turns fail with api-auth-failure until a restart.
func TestGuardrailProxyAuth_AcceptsTokenAdoptedByAuthRepair(t *testing.T) {
	client := newAuthRepairedClient(t)
	conn := connector.NewOpenClawConnector()
	conn.SetCredentials("boot-token", "")
	proxy := &GuardrailProxy{connector: conn}
	proxy.SetRefreshedGatewayTokenSource(client.RefreshedToken)

	for tok, want := range map[string]bool{
		"boot-token":    true,
		"rotated-token": true,
		"other-token":   false,
		"":              false,
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/events/egress", nil)
		req.RemoteAddr = "127.0.0.1:40000"
		if tok != "" {
			req.Header.Set("X-DC-Auth", "Bearer "+tok)
		}
		if _, got := proxy.authenticateRequest(req); got != want {
			t.Errorf("token %q: authenticated = %v, want %v", tok, got, want)
		}
	}
}
