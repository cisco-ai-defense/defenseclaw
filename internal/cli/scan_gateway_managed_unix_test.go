// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-1234: the managed Linux and macOS packages ship no skill, MCP or
// plugin scanner, so `defenseclaw-gateway scan skill|mcp|plugin` cannot run
// there. Root got "no per-user gateway to check" and, past that, "skill-
// scanner not found ... repair the managed DefenseClaw installation". Every
// caller now gets one answer that names the limit and the scan that runs
// here, and nothing reaches the gateway.
func TestManagedUnixGatewayScanNamesTheScannerLimit(t *testing.T) {
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	restorePath, restoreTrust, restoreEndpoint := managedHostDescriptorPath, managedHostRecordTrusted, scanGatewayEndpoint
	t.Cleanup(func() {
		managedHostDescriptorPath, managedHostRecordTrusted, scanGatewayEndpoint = restorePath, restoreTrust, restoreEndpoint
	})
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostRecordTrusted = func(string) error { return nil }
	scanGatewayEndpoint = func() (string, string, error) {
		t.Fatal("a managed Linux or macOS scan reached the gateway")
		return "", "", nil
	}
	gateway := managedHostGatewayCommand()
	for _, kind := range []string{"skill", "mcp", "plugin"} {
		for _, uid := range []int{0, 991, 1000} {
			t.Run(fmt.Sprintf("%s as uid %d", kind, uid), func(t *testing.T) {
				withManagedHostCallerUID(t, uid)
				err := runGatewayScan(&cobra.Command{}, kind, t.TempDir())
				if err == nil {
					t.Fatalf("scan %s ran on a managed Linux or macOS computer", kind)
				}
				var coded interface{ ExitCode() int }
				if !errors.As(err, &coded) || coded.ExitCode() != 3 {
					t.Fatalf("scan %s exit code: %v", kind, err)
				}
				message := err.Error()
				for _, want := range []string{descriptor, "include no", "scanner", "Nothing was scanned"} {
					if !strings.Contains(message, want) {
						t.Fatalf("scan %s answer lacks %q: %s", kind, want, message)
					}
				}
				for _, stale := range []string{"no per-user gateway", "repair"} {
					if strings.Contains(message, stale) {
						t.Fatalf("scan %s answer still says %q: %s", kind, stale, message)
					}
				}
				route := "`sudo " + gateway + " scan code <path>`"
				if kind == "mcp" {
					route = "agent's own MCP configuration"
				}
				if !strings.Contains(message, route) {
					t.Fatalf("scan %s answer lacks the route %q: %s", kind, route, message)
				}
			})
		}
	}
}

// A host without a trusted managed deployment record keeps the gateway scan.
func TestGatewayScanWithoutManagedRecordStillAsksTheGateway(t *testing.T) {
	restorePath, restoreEndpoint := managedHostDescriptorPath, scanGatewayEndpoint
	t.Cleanup(func() { managedHostDescriptorPath, scanGatewayEndpoint = restorePath, restoreEndpoint })
	managedHostDescriptorPath = func() string { return filepath.Join(t.TempDir(), "absent.json") }
	asked := errors.New("asked the gateway")
	scanGatewayEndpoint = func() (string, string, error) { return "", "", asked }
	for _, kind := range []string{"skill", "mcp", "plugin"} {
		if err := runGatewayScan(&cobra.Command{}, kind, t.TempDir()); !errors.Is(err, asked) {
			t.Fatalf("scan %s on an unmanaged host: %v", kind, err)
		}
	}
}

// The administrator's `scan code` on a managed Linux or macOS computer, the
// route the limit names, no longer ends with a per-user command its launcher
// refuses (`defenseclaw doctor`, `defenseclaw alerts`); elsewhere it does.
func TestManagedCodeScanPrintsNoPerUserHint(t *testing.T) {
	t.Setenv("FORCE_COLOR", "1")
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	restorePath, restoreTrust := managedHostDescriptorPath, managedHostRecordTrusted
	t.Cleanup(func() { managedHostDescriptorPath, managedHostRecordTrusted = restorePath, restoreTrust })
	managedHostRecordTrusted = func(string) error { return nil }
	clean := &scanner.ScanResult{Target: "/srv/skill"}
	finding := &scanner.ScanResult{Target: "/srv/skill", Findings: []scanner.Finding{{ID: "CG-1", Severity: "HIGH", Title: "t"}}}
	for _, tc := range []struct {
		name    string
		managed bool
	}{{"managed", true}, {"per-user", false}} {
		managedHostDescriptorPath = func() string { return filepath.Join(t.TempDir(), "absent.json") }
		if tc.managed {
			managedHostDescriptorPath = func() string { return descriptor }
		}
		for _, result := range []*scanner.ScanResult{clean, finding} {
			out := captureStdout(t, func() { printCodeScanResults(result) })
			hinted := strings.Contains(out, "defenseclaw doctor") || strings.Contains(out, "defenseclaw alerts")
			if hinted == tc.managed {
				t.Fatalf("%s code scan with %d findings: per-user hint shown = %v:\n%s", tc.name, len(result.Findings), hinted, out)
			}
		}
	}
}
