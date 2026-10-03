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
)

// GAP-2259: when OpenClaw rotates gateway.auth.token, auth repair adopts the
// new token and writes it to .env, so the CLI presents it to the running
// API server (graceful shutdown during 'setup openclaw'). The API server
// must accept it next to its boot token instead of logging invalid_token.
func TestTokenAuth_AcceptsTokenAdoptedByAuthRepair(t *testing.T) {
	home := t.TempDir()
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
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
