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

// newAuthRepairedClient returns a client whose DefenseClaw gateway token is
// master-token, that booted with the OpenClaw credential boot-oc-token, and
// then adopted rotated-oc-token from openclaw.json through auth repair. It
// returns the data directory too.
func newAuthRepairedClient(t *testing.T) (*Client, string) {
	t.Helper()
	home := t.TempDir()
	dataDir := testenv.PrivateTempDir(t)
	if err := os.MkdirAll(filepath.Join(home, ".openclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".openclaw", "openclaw.json"),
		[]byte(`{"gateway":{"auth":{"token":"rotated-oc-token"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "hooks", ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"master-token\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, ".env"),
		[]byte("DEFENSECLAW_GATEWAY_TOKEN=master-token\nOPENCLAW_GATEWAY_TOKEN=boot-oc-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(&config.GatewayConfig{
		Token:         "master-token",
		OpenClawToken: "boot-oc-token",
		ClawHome:      home,
		DeviceKeyFile: filepath.Join(dataDir, "device.key"),
	}, dataDir)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got := client.wsToken(); got != "boot-oc-token" {
		t.Fatalf("wsToken before repair = %q, want boot-oc-token", got)
	}
	client.handleConnectRejection(errors.New("AUTH_TOKEN_MISMATCH"))
	if got := client.wsToken(); got != "rotated-oc-token" {
		t.Fatalf("wsToken after repair = %q, want rotated-oc-token", got)
	}
	return client, dataDir
}

// R-TOK: auth repair changes only the OpenClaw WebSocket credential. The
// DefenseClaw gateway token stays as it was in memory, in .env and in
// hooks/.token; the adopted token is saved only as OPENCLAW_GATEWAY_TOKEN.
func TestAuthRepair_ChangesOnlyTheOpenClawCredential(t *testing.T) {
	client, dataDir := newAuthRepairedClient(t)
	if client.cfg.Token != "master-token" {
		t.Fatalf("cfg.Token = %q, want master-token (auth repair must not touch the master)", client.cfg.Token)
	}
	env, err := loadDotEnv(filepath.Join(dataDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if env["DEFENSECLAW_GATEWAY_TOKEN"] != "master-token" {
		t.Errorf(".env DEFENSECLAW_GATEWAY_TOKEN = %q, want master-token", env["DEFENSECLAW_GATEWAY_TOKEN"])
	}
	if env["OPENCLAW_GATEWAY_TOKEN"] != "rotated-oc-token" {
		t.Errorf(".env OPENCLAW_GATEWAY_TOKEN = %q, want rotated-oc-token", env["OPENCLAW_GATEWAY_TOKEN"])
	}
	hook, err := os.ReadFile(filepath.Join(dataDir, "hooks", ".token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(hook) != "DEFENSECLAW_GATEWAY_TOKEN=\"master-token\"\n" {
		t.Errorf("hooks/.token = %q, want the master token unchanged", hook)
	}
}

// R-TOK negative cell: an OpenClaw gateway token (the one saved at boot and
// the one auth repair adopted) presented as Bearer is refused by
// /enforce/allow and shutdown. Only the DefenseClaw gateway token passes.
func TestTokenAuth_RefusesOpenClawGatewayTokens(t *testing.T) {
	client, _ := newAuthRepairedClient(t)

	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Gateway.Token = "master-token"
	cfg.Gateway.OpenClawToken = "boot-oc-token"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), client, store, logger, cfg)
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, path := range []string{"/enforce/allow", "/api/v1/admin/shutdown"} {
		for tok, want := range map[string]int{
			"master-token":     http.StatusOK,
			"boot-oc-token":    http.StatusUnauthorized,
			"rotated-oc-token": http.StatusUnauthorized,
			"other-token":      http.StatusUnauthorized,
		} {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != want {
				t.Errorf("%s token %s: status = %d, want %d", path, tok, rr.Code, want)
			}
		}
	}
}

// R-TOK negative cell: the guardrail proxy refuses an OpenClaw gateway token
// in X-DC-Auth (before 1.0.10 it accepted the adopted one, GAP-2346).
func TestGuardrailProxyAuth_RefusesOpenClawGatewayTokens(t *testing.T) {
	newAuthRepairedClient(t)
	conn := connector.NewOpenClawConnector()
	conn.SetCredentials("master-token", "")
	proxy := &GuardrailProxy{connector: conn, gatewayToken: "master-token"}

	for tok, want := range map[string]bool{
		"master-token":     true,
		"boot-oc-token":    false,
		"rotated-oc-token": false,
		"other-token":      false,
		"":                 false,
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
