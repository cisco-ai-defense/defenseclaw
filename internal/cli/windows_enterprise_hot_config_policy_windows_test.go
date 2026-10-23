// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsHotConfigHealthProofUsesOnlyTheServiceListener(t *testing.T) {
	requests := 0
	redirectURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/health" || r.Header.Get("X-DefenseClaw-Token") != "fixture-token" {
			t.Errorf("health request path %q or token was wrong", r.URL.Path)
		}
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"policy":{"effective_digest":"sha256:prior"}}`))
	}))
	defer server.Close()
	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	layout := managed.StandaloneLayout{ConfigPath: filepath.Join(root, "config.yaml"), DataDir: root, APIAddr: managed.StandaloneAPIAddr}
	if err := os.WriteFile(layout.ConfigPath, []byte(fmt.Sprintf("gateway:\n  api_port: %d\n", port)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=fixture-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	priorHost, priorLayout := managedHostWindowsStandalone, managedScanWindowsLayout
	priorListeners, priorServicePID := windowsEnterpriseAPIListeners, windowsEnterpriseServicePID
	t.Cleanup(func() {
		managedHostWindowsStandalone, managedScanWindowsLayout = priorHost, priorLayout
		windowsEnterpriseAPIListeners, windowsEnterpriseServicePID = priorListeners, priorServicePID
	})
	managedHostWindowsStandalone = func() (string, bool) { return "managed", true }
	managedScanWindowsLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	windowsEnterpriseServicePID = func(string) int { return 42 }
	windowsEnterpriseAPIListeners = func(host string, gotPort int) ([]daemon.Listener, error) {
		if host != "127.0.0.1" || gotPort != port {
			t.Fatalf("listener query %s:%d", host, gotPort)
		}
		return []daemon.Listener{{Address: fmt.Sprintf("127.0.0.1:%d", port), PID: 42}}, nil
	}
	policy, err := windowsEnterpriseHotConfigGatewayPolicy(context.Background(), layout)
	if err != nil || policy.EffectiveDigest != "sha256:prior" || requests != 1 {
		t.Fatalf("owned listener policy = %+v, %v; requests=%d", policy, err, requests)
	}
	windowsEnterpriseAPIListeners = func(string, int) ([]daemon.Listener, error) {
		return []daemon.Listener{{PID: 42}, {PID: 77}}, nil
	}
	if _, err := windowsEnterpriseHotConfigGatewayPolicy(context.Background(), layout); err == nil || requests != 1 {
		t.Fatalf("foreign listener got a request; err=%v requests=%d", err, requests)
	}
	tokenForwarded := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		tokenForwarded = r.Header.Get("X-DefenseClaw-Token") != ""
	}))
	defer redirectTarget.Close()
	redirectURL = redirectTarget.URL
	windowsEnterpriseAPIListeners = func(string, int) ([]daemon.Listener, error) {
		return []daemon.Listener{{PID: 42}}, nil
	}
	if _, err := windowsEnterpriseHotConfigGatewayPolicy(context.Background(), layout); err == nil || tokenForwarded || requests != 2 {
		t.Fatalf("redirect was accepted or forwarded the token: err=%v forwarded=%t requests=%d", err, tokenForwarded, requests)
	}
}
