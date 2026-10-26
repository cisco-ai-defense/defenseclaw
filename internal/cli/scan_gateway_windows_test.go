// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestManagedScanGatewayEndpointUsesInstalledAPIPort(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configPath, []byte("gateway:\n  api_port: 18971\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousHost, previousLayout := managedHostWindowsStandalone, managedScanWindowsLayout
	t.Cleanup(func() {
		managedHostWindowsStandalone, managedScanWindowsLayout = previousHost, previousLayout
	})
	managedHostWindowsStandalone = func() (string, bool) { return "managed", true }
	managedScanWindowsLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: configPath, DataDir: root, APIAddr: managed.StandaloneAPIAddr}, nil
	}
	endpoint, token, managedHost, err := managedScanGatewayEndpoint()
	if err != nil || !managedHost || endpoint != "http://127.0.0.1:18971" || token != "test-token" {
		t.Fatalf("endpoint = %q, token = %q, managed = %v, err = %v", endpoint, token, managedHost, err)
	}
}

// GAP-1391: a standard account's scan on a managed computer failed with
// "read installed managed gateway config: open C:/ProgramData/...: Access is
// denied". It now says an administrator runs it, without the private path.
func TestManagedScanGatewayEndpointRefusesAStandardAccountPlainly(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	previousHost, previousLayout, previousRead := managedHostWindowsStandalone, managedScanWindowsLayout, managedScanReadFile
	t.Cleanup(func() {
		managedHostWindowsStandalone, managedScanWindowsLayout, managedScanReadFile = previousHost, previousLayout, previousRead
	})
	managedHostWindowsStandalone = func() (string, bool) { return "managed", true }
	managedScanWindowsLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: configPath, DataDir: root, APIAddr: managed.StandaloneAPIAddr}, nil
	}
	managedScanReadFile = func(path string, _ int64) ([]byte, error) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: windows.ERROR_ACCESS_DENIED}
	}
	_, _, managedHost, err := managedScanGatewayEndpoint()
	if !managedHost || err == nil || strings.Contains(err.Error(), configPath) || strings.Contains(err.Error(), "Access is denied") ||
		!strings.Contains(err.Error(), "elevated Administrator prompt") {
		t.Fatalf("standard account scan: managed = %v, err = %v", managedHost, err)
	}
}

// status and verify read /health on the gateway.api_port of the installed
// config, as they read /status there (GAP-1351).
func TestWindowsStandaloneGatewayHealthUsesInstalledAPIPort(t *testing.T) {
	previousFactory := managedGatewayClientFactory
	managedGatewayClientFactory = func(time.Duration, string, string) (*http.Client, error) { return &http.Client{}, nil }
	t.Cleanup(func() { managedGatewayClientFactory = previousFactory })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte("configured-port"))
		}
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("gateway:\n  api_port: %s\n", port)), 0o600); err != nil {
		t.Fatal(err)
	}
	previousLayout, previousFactory := managedScanWindowsLayout, managedGatewayClientFactory
	t.Cleanup(func() { managedScanWindowsLayout, managedGatewayClientFactory = previousLayout, previousFactory })
	managedScanWindowsLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: configPath, DataDir: root, APIAddr: managed.StandaloneAPIAddr}, nil
	}
	// This test is about the port; the listener check has its own test.
	var dialed string
	managedGatewayClientFactory = func(timeout time.Duration, apiAddr string, service string) (*http.Client, error) {
		dialed = apiAddr
		if service != managed.StandaloneWindowsGatewaySvc {
			t.Fatalf("health checked the listener against %q", service)
		}
		return &http.Client{Timeout: timeout}, nil
	}
	body, err := windowsStandaloneGatewayHealth()
	if err != nil || string(body) != "configured-port" || dialed != "127.0.0.1:"+port {
		t.Fatalf("health = %q, %v (dialed %q)", body, err, dialed)
	}
}

// GAP-0962: status reads /status with the administrator's gateway token. A
// process that holds the installed API port while the gateway service is
// stopped (another account's) receives neither the token nor the request;
// /health tells it nothing either.
func TestWindowsStandaloneGatewayStatusSendsNoTokenToAnUnverifiedListener(t *testing.T) {
	var received []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.URL.Path+" "+r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("gateway:\n  api_port: %s\n", port)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=managed-admin-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousHost, previousLayout := managedHostWindowsStandalone, managedScanWindowsLayout
	t.Cleanup(func() { managedHostWindowsStandalone, managedScanWindowsLayout = previousHost, previousLayout })
	managedHostWindowsStandalone = func() (string, bool) { return "managed", true }
	managedScanWindowsLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: configPath, DataDir: root, APIAddr: managed.StandaloneAPIAddr}, nil
	}
	if body := windowsStandaloneGatewayStatus(); body != nil {
		t.Fatalf("status read %q from a listener that is not the gateway service", body)
	}
	if body, err := windowsStandaloneGatewayHealth(); err == nil {
		t.Fatalf("health read %q from a listener that is not the gateway service", body)
	}
	if len(received) != 0 {
		t.Fatalf("an unverified listener received %v", received)
	}
}

func TestWindowsStandaloneViewsDoNotSendToAnUnverifiedListener(t *testing.T) {
	seen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		seen++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("gateway:\n  api_port: %s\n", port)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=private-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousLayout, previousHost, previousFactory := managedScanWindowsLayout, managedHostWindowsStandalone, managedGatewayClientFactory
	t.Cleanup(func() {
		managedScanWindowsLayout, managedHostWindowsStandalone, managedGatewayClientFactory = previousLayout, previousHost, previousFactory
	})
	managedScanWindowsLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: configPath, DataDir: root, APIAddr: managed.StandaloneAPIAddr}, nil
	}
	managedHostWindowsStandalone = func() (string, bool) { return "managed", true }
	managedGatewayClientFactory = func(time.Duration, string, string) (*http.Client, error) {
		return nil, fmt.Errorf("connected gateway listener is not the protected service")
	}
	if _, err := windowsStandaloneGatewayHealth(); err == nil {
		t.Fatal("health accepted an unverified listener")
	}
	if body := windowsStandaloneGatewayStatus(); body != nil || seen != 0 {
		t.Fatalf("managed views sent data to an unverified listener: status=%q requests=%d", body, seen)
	}
}
