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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsHotConfigHealthFixture serves /health on a loopback port and points
// a managed standalone layout (config api_port and gateway token) at it.
func windowsHotConfigHealthFixture(t *testing.T, handler http.HandlerFunc) (managed.StandaloneLayout, string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	layout := managed.StandaloneLayout{ConfigPath: filepath.Join(root, "config.yaml"), DataDir: root, APIAddr: managed.StandaloneAPIAddr}
	if err := os.WriteFile(layout.ConfigPath, []byte(fmt.Sprintf("gateway:\n  api_port: %s\n", port)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=fixture-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	priorHost, priorLayout := managedHostWindowsStandalone, managedScanWindowsLayout
	t.Cleanup(func() { managedHostWindowsStandalone, managedScanWindowsLayout = priorHost, priorLayout })
	managedHostWindowsStandalone = func() (string, bool) { return "managed", true }
	managedScanWindowsLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	return layout, "127.0.0.1:" + port
}

func TestWindowsHotConfigHealthProofUsesOnlyTheServiceSocket(t *testing.T) {
	requests := 0
	layout, apiAddr := windowsHotConfigHealthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/health" || r.Header.Get("X-DefenseClaw-Token") != "fixture-token" {
			t.Errorf("health request path %q or token was wrong", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"policy":{"effective_digest":"sha256:prior"}}`))
	})
	// The connected-socket check has its own tests (hookexec); here the
	// probe must ask it for the gateway service at the configured port.
	priorFactory := managedGatewayClientFactory
	t.Cleanup(func() { managedGatewayClientFactory = priorFactory })
	var dialed string
	managedGatewayClientFactory = func(timeout time.Duration, addr string, service string) (*http.Client, error) {
		dialed = addr
		if service != managed.StandaloneWindowsGatewaySvc {
			t.Fatalf("health checked the socket against %q", service)
		}
		return &http.Client{Timeout: timeout}, nil
	}
	policy, err := windowsEnterpriseHotConfigGatewayPolicy(context.Background(), layout)
	if err != nil || policy.EffectiveDigest != "sha256:prior" || requests != 1 || dialed != apiAddr {
		t.Fatalf("service socket policy = %+v, %v; requests=%d dialed=%q", policy, err, requests, dialed)
	}
}

// The service can release its port after a listener-table check and another
// account can bind it before the probe connects. The listener table below
// still names the service; the socket the probe reaches is not the
// service's. It must receive no token, and its policy answer must not count.
func TestWindowsHotConfigHealthSendsNoTokenToAPortTakenAfterTheListenerCheck(t *testing.T) {
	var received []string
	layout, _ := windowsHotConfigHealthFixture(t, func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.URL.Path+" "+r.Header.Get("X-DefenseClaw-Token"))
		_, _ = w.Write([]byte(`{"policy":{"effective_digest":"sha256:prior","bundle_id":"forged"}}`))
	})
	priorListeners, priorServicePID := windowsEnterpriseAPIListeners, windowsEnterpriseServicePID
	t.Cleanup(func() { windowsEnterpriseAPIListeners, windowsEnterpriseServicePID = priorListeners, priorServicePID })
	windowsEnterpriseServicePID = func(string) int { return 42 }
	windowsEnterpriseAPIListeners = func(string, int) ([]daemon.Listener, error) {
		return []daemon.Listener{{PID: 42}}, nil
	}
	if policy, err := windowsEnterpriseHotConfigGatewayPolicy(context.Background(), layout); err == nil {
		t.Fatalf("a listener that is not the gateway service supplied policy health %+v", policy)
	}
	prior := policyDigestReport{GatewayReportedBundleID: "forged"}
	prior.Digest = "sha256:prior"
	if windowsEnterpriseHotConfigPriorPolicyLive(context.Background(), layout, prior) {
		t.Fatal("a forged policy answer from another listener proved the prior policy live")
	}
	if len(received) != 0 {
		t.Fatalf("an unverified listener received %v", received)
	}
}
