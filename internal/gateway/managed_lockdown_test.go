// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func managedStandaloneTestConfig(dataDir string) *config.Config {
	cfg := &config.Config{DataDir: dataDir, DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	return cfg
}

func useBundleAnchorsPath(t *testing.T, path string, err error) {
	t.Helper()
	previous := bundleAnchorsPath
	bundleAnchorsPath = func() (string, error) { return path, err }
	t.Cleanup(func() { bundleAnchorsPath = previous })
}

func TestManagedStandaloneGatewayRefusesShutdownOverTheAPI(t *testing.T) {
	dataDir := t.TempDir()
	requested := 0
	api := &APIServer{scannerCfg: managedStandaloneTestConfig(dataDir), shutdownRequester: func() { requested++ }}
	body := []byte(fmt.Sprintf(`{"pid":%d,"data_dir":%q}`, os.Getpid(), dataDir))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/admin/shutdown", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:42100"
	w := httptest.NewRecorder()
	api.handleShutdown(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "system service") || requested != 0 {
		t.Fatalf("managed shutdown = %d %s, requests %d; want 403 and no shutdown", w.Code, w.Body.String(), requested)
	}

	// A per-user gateway still stops over the API.
	api = &APIServer{scannerCfg: &config.Config{DataDir: dataDir}, shutdownRequester: func() { requested++ }}
	req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/admin/shutdown", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:42100"
	w = httptest.NewRecorder()
	api.handleShutdown(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("per-user shutdown = %d %s; want 202", w.Code, w.Body.String())
	}
}

func TestSignedBundleComputerRefusesPolicyReloadOverTheAPI(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	logger := audit.NewLogger(capture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: runtime})
	api := &APIServer{health: NewSidecarHealth(), store: capture.store, logger: logger, scannerCfg: managedStandaloneTestConfig(t.TempDir())}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	called := 0
	api.SetPolicyReloader(func() error { called++; return nil })
	reload := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		api.handlePolicyReload(w, httptest.NewRequest(http.MethodPost, "/policy/reload", nil))
		return w
	}

	anchors := filepath.Join(t.TempDir(), "trust", "bundle-anchors.json")
	useBundleAnchorsPath(t, anchors, nil)
	if w := reload(); w.Code != http.StatusOK || called != 1 {
		t.Fatalf("reload without anchors = %d %s, calls %d; want the reload", w.Code, w.Body.String(), called)
	}

	if err := os.MkdirAll(filepath.Dir(anchors), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchors, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if w := reload(); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "signed policy bundles") || called != 1 {
		t.Fatalf("reload with anchors = %d %s, calls %d; want 403 and no reload", w.Code, w.Body.String(), called)
	}

	// An anchors location the gateway cannot resolve counts as bundle mode.
	useBundleAnchorsPath(t, "", errors.New("no layout"))
	if w := reload(); w.Code != http.StatusForbidden || called != 1 {
		t.Fatalf("reload with unknown anchors = %d %s, calls %d; want 403", w.Code, w.Body.String(), called)
	}
}
