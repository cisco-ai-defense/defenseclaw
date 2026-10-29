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

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func withManagedWindowsProvenanceHost(t *testing.T, port string, readFile func(string, int64) ([]byte, error)) {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("gateway:\n  api_port: %s\n", port)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=admin-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousHost, previousLayout, previousFactory, previousRead := managedHostWindowsStandalone, managedScanWindowsLayout, managedGatewayClientFactory, managedScanReadFile
	t.Cleanup(func() {
		managedHostWindowsStandalone, managedScanWindowsLayout, managedGatewayClientFactory, managedScanReadFile = previousHost, previousLayout, previousFactory, previousRead
	})
	managedHostWindowsStandalone = func() (string, bool) { return "managed", true }
	managedScanWindowsLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: configPath, DataDir: root, APIAddr: managed.StandaloneAPIAddr}, nil
	}
	managedGatewayClientFactory = func(time.Duration, string, string) (*http.Client, error) { return &http.Client{}, nil }
	if readFile != nil {
		managedScanReadFile = readFile
	}
}

// GAP-0391: on managed Windows, provenance show printed this short-lived
// CLI's own snapshot (generation 0) while the running gateway had applied
// config changes. It reads the gateway's administrator /status now, as
// enterprise windows status does.
func TestManagedWindowsProvenanceShowsTheRunningGatewaySnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" || r.Header.Get("Authorization") != "Bearer admin-token" {
			http.Error(w, "unexpected", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, `{"provenance":{"schema_version":7,"content_hash":%q,"generation":3,"binary_version":"1.0.5-live"}}`, strings.Repeat("b", 64))
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	withManagedWindowsProvenanceHost(t, port, nil)
	var out strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runProvenanceShow(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "generation: 3\n") || !strings.Contains(out.String(), "content_hash: "+strings.Repeat("b", 64)+"\n") ||
		!strings.Contains(out.String(), "binary_version: 1.0.5-live\n") {
		t.Fatalf("provenance show used this CLI's own snapshot, not the running gateway's: %s", out.String())
	}
}

// A standard account cannot read the gateway token: it is told an
// administrator runs the command, not shown a scan message or a local
// generation 0.
func TestManagedWindowsProvenanceNamesTheAdministratorStepForAStandardAccount(t *testing.T) {
	withManagedWindowsProvenanceHost(t, "18970", func(path string, _ int64) ([]byte, error) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: windows.ERROR_ACCESS_DENIED}
	})
	var out strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runProvenanceShow(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "elevated Administrator prompt") || strings.Contains(err.Error(), "scan") || strings.Contains(out.String(), "generation: 0") {
		t.Fatalf("standard account: err = %v, out = %q", err, out.String())
	}
}

// An incomplete answer is refused rather than printed.
func TestManagedWindowsProvenanceRefusesAnIncompleteAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"provenance":{"generation":3}}`))
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	withManagedWindowsProvenanceHost(t, port, nil)
	cmd := &cobra.Command{}
	cmd.SetOut(&strings.Builder{})
	if err := runProvenanceShow(cmd, nil); err == nil || !strings.Contains(err.Error(), "complete administrator provenance") {
		t.Fatalf("incomplete provenance = %v", err)
	}
}
