// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	proxy.gatewayToken = "test-token"
	proxy.skipAuthForTest = false

	req := httptest.NewRequest(http.MethodGet, "/v1/config/providers", nil)
	req.Header.Set("X-DC-Auth", "Bearer test-token")
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

func sidecarProviderTestHandler(token string) http.Handler {
	cfg := &config.Config{Gateway: config.GatewayConfig{Token: token}}
	api := NewAPIServer("127.0.0.1:29871", nil, nil, nil, nil, cfg)
	mux := http.NewServeMux()
	api.registerProviderRoutes(mux)
	return api.tokenAuth(api.apiCSRFProtect(mux))
}

func TestSidecarProviderRoutes_RequireAuthWithoutProxyListener(t *testing.T) {
	handler := sidecarProviderTestHandler("sidecar-token")
	for _, tc := range []struct {
		name   string
		header string
		want   int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "invalid", header: "Bearer wrong", want: http.StatusUnauthorized},
		{name: "valid x-dc-auth", header: "Bearer sidecar-token", want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/config/providers", nil)
			if tc.header != "" {
				req.Header.Set("X-DC-Auth", tc.header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestSidecarProviderReload_UpdatesRegistryWithoutProxyListener(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-providers.json")
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", path)
	if err := ReloadProviderRegistry(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", "")
		_ = ReloadProviderRegistry()
	})

	if err := os.WriteFile(path, []byte(`{"providers":[{"name":"SidecarOnly","domains":["sidecar-only.test"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	handler := sidecarProviderTestHandler("sidecar-token")
	req := httptest.NewRequest(http.MethodPost, "/v1/config/providers/reload", nil)
	req.Header.Set("Authorization", "Bearer sidecar-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if !isKnownProviderDomain("https://sidecar-only.test/v1/chat/completions") {
		t.Fatal("sidecar provider reload did not update the in-memory registry")
	}
}

func TestProviderManagementHookOnlyIntegration(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "custom-providers.json")
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", overlayPath)
	if err := ReloadProviderRegistry(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", "")
		_ = ReloadProviderRegistry()
	})

	reservePort := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		return port
	}
	apiPort := reservePort()
	proxyPort := reservePort()
	addr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	cfg := &config.Config{Gateway: config.GatewayConfig{Token: "integration-token"}}
	api := NewAPIServer(addr, NewSidecarHealth(), nil, nil, nil, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- api.Run(ctx) }()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := "http://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(baseURL + "/health")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sidecar API did not start on non-default port %d: %v", apiPort, err)
		}
		time.Sleep(25 * time.Millisecond)
	}

	reload := func(providerName, domain string) {
		t.Helper()
		body := fmt.Sprintf(`{"providers":[{"name":%q,"domains":[%q]}]}`, providerName, domain)
		if err := os.WriteFile(overlayPath, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/config/providers/reload", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-DC-Auth", "Bearer integration-token")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "integration-test")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("reload status = %d", resp.StatusCode)
		}
	}

	reload("IntegrationProvider", "first.integration.test")
	reload("IntegrationProvider", "second.integration.test")
	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/config/providers", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer integration-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	var registry providersListResponse
	if err := json.NewDecoder(resp.Body).Decode(&registry); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, provider := range registry.Providers {
		if provider.Name == "IntegrationProvider" && len(provider.Domains) == 1 && provider.Domains[0] == "second.integration.test" {
			found = true
		}
	}
	if !found {
		t.Fatalf("re-added provider missing from live registry: %+v", registry.Providers)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("guardrail proxy port %d unexpectedly opened", proxyPort)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("sidecar API did not stop")
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
