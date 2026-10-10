// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"

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
