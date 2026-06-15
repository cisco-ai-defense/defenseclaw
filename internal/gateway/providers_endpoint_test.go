// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// TestHandleListProviders_ReturnsMergedRegistry verifies the
// bootstrap endpoint the TS interceptor calls at startup includes
// both built-ins and the operator overlay.
func TestHandleListProviders_ReturnsMergedRegistry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-providers.json")
	body := `{"providers": [{"name": "EdgeLLM", "domains": ["edge.llm.test"]}]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", path)
	if err := ReloadProviderRegistry(); err != nil {
		t.Fatalf("ReloadProviderRegistry: %v", err)
	}
	t.Cleanup(func() {
		t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", "")
		_ = ReloadProviderRegistry()
	})

	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	req := httptest.NewRequest(http.MethodGet, "/v1/config/providers", nil)
	rec := httptest.NewRecorder()
	proxy.handleListProviders(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp providersListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	found := false
	for _, p := range resp.Providers {
		if strings.EqualFold(p.Name, "EdgeLLM") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("overlay provider missing from response: %+v", resp.Providers)
	}
	if resp.OverlayPath != path {
		t.Errorf("OverlayPath = %q, want %q", resp.OverlayPath, path)
	}
	if !resp.OverlayApplied {
		t.Errorf("OverlayApplied = false; overlay file exists at %s", path)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %q", rec.Header().Get("Cache-Control"))
	}
}

// TestHandleListProviders_RejectsNonGET locks in the method allow-list.
func TestHandleListProviders_RejectsNonGET(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	req := httptest.NewRequest(http.MethodPost, "/v1/config/providers", nil)
	rec := httptest.NewRecorder()
	proxy.handleListProviders(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

// TestHandleReloadProviders_RequiresAuth confirms that a caller
// without X-DC-Auth cannot roll the provider registry out from
// under active requests — that would be a DoS + silent-bypass
// surface if left unauthenticated.
func TestHandleReloadProviders_RequiresAuth(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	proxy.gatewayToken = "test-token"
	// Specifically exercising the auth path — flip off the test bypass.
	proxy.skipAuthForTest = false

	req := httptest.NewRequest(http.MethodPost, "/v1/config/providers/reload", nil)
	rec := httptest.NewRecorder()
	proxy.handleReloadProviders(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without X-DC-Auth, got %d", rec.Code)
	}
}

// TestHandleReloadProviders_MergesNewOverlay simulates the operator
// editing ~/.defenseclaw/custom-providers.json and calling the
// reload endpoint — the live registry must pick up the new entry
// without a process restart.
func TestHandleReloadProviders_MergesNewOverlay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-providers.json")
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", path)
	// Start with an empty (absent) overlay.
	if err := ReloadProviderRegistry(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", "")
		_ = ReloadProviderRegistry()
	})

	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	proxy.gatewayToken = "test-token"

	// Sanity: our custom provider is NOT known yet.
	if isKnownProviderDomain("https://llm.custom.test/chat/completions") {
		t.Fatalf("pre-reload: custom domain should not match")
	}

	// Write overlay, call reload.
	body := `{"providers": [{"name": "CustomLLM", "domains": ["llm.custom.test"]}]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/config/providers/reload", nil)
	req.Header.Set("X-DC-Auth", "Bearer test-token")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	proxy.handleReloadProviders(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload status = %d; body=%s", rec.Code, rec.Body.String())
	}

	// Post-reload: the domain MUST now match.
	if !isKnownProviderDomain("https://llm.custom.test/chat/completions") {
		t.Fatalf("post-reload: custom domain should match")
	}
}

// TestCustomProvidersPath_EnvOverride verifies the env var wins
// over ~/.defenseclaw so tests and container installs can both
// relocate the overlay without patching code.
func TestCustomProvidersPath_EnvOverride(t *testing.T) {
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", "/tmp/my-overlay.json")
	if got := configs.CustomProvidersPath(); got != "/tmp/my-overlay.json" {
		t.Errorf("CustomProvidersPath = %q, want /tmp/my-overlay.json", got)
	}
}
