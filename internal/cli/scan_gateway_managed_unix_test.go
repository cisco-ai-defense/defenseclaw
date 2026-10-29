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

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-1234 / GAP-1527: the managed Linux and macOS packages install the
// scanner runtime, so on a host with it `defenseclaw-gateway scan
// skill|mcp|plugin` reaches the managed gateway (root got "no per-user
// gateway to check" before). A deployment without the runtime (the payload
// archive) answers exit 3 naming the package, and nothing reaches the
// gateway.
func TestManagedUnixGatewayScanRunsThroughTheManagedGateway(t *testing.T) {
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	restorePath, restoreTrust, restoreEndpoint, restoreRuntime := managedHostDescriptorPath, managedHostRecordTrusted, scanGatewayEndpoint, managedScanUnixRuntime
	t.Cleanup(func() {
		managedHostDescriptorPath, managedHostRecordTrusted, scanGatewayEndpoint, managedScanUnixRuntime = restorePath, restoreTrust, restoreEndpoint, restoreRuntime
	})
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostRecordTrusted = func(string) error { return nil }
	asked := errors.New("asked the managed gateway")
	for _, installed := range []bool{true, false} {
		managedScanUnixRuntime = func() error { return nil }
		if !installed {
			managedScanUnixRuntime = func() error { return managed.ErrNoScannerRuntime }
		}
		for _, kind := range []string{"skill", "mcp", "plugin"} {
			for _, uid := range []int{0, 991, 1000} {
				t.Run(fmt.Sprintf("%s as uid %d runtime %v", kind, uid, installed), func(t *testing.T) {
					withManagedHostCallerUID(t, uid)
					reached := false
					scanGatewayEndpoint = func() (string, string, error) { reached = true; return "", "", asked }
					target := "/opt/defenseclaw-scan/review"
					if kind == "mcp" {
						target = "https://mcp.example.test/mcp"
					}
					err := runGatewayScan(&cobra.Command{}, kind, target)
					if installed {
						if !reached || !errors.Is(err, asked) {
							t.Fatalf("scan %s with the runtime installed did not reach the managed gateway: %v", kind, err)
						}
						return
					}
					if reached {
						t.Fatalf("scan %s without a runtime reached the gateway", kind)
					}
					var coded interface{ ExitCode() int }
					if !errors.As(err, &coded) || coded.ExitCode() != 3 {
						t.Fatalf("scan %s exit code: %v", kind, err)
					}
					for _, want := range []string{"installs the scanner runtime", "payload archive", "Nothing was scanned"} {
						if !strings.Contains(err.Error(), want) {
							t.Fatalf("scan %s answer lacks %q: %s", kind, want, err)
						}
					}
				})
			}
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

// An administrator's `scan code` of a skill directory it can stat but not
// list (a root-squashed NFS home) must fail as incomplete, never print clean.
func TestManagedCodeScanOfAnUnlistableSkillIsIncomplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists mode-000 directories; the restriction cannot be built here")
	}
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	restorePath, restoreTrust := managedHostDescriptorPath, managedHostRecordTrusted
	t.Cleanup(func() { managedHostDescriptorPath, managedHostRecordTrusted = restorePath, restoreTrust })
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostRecordTrusted = func(string) error { return nil }
	skill := filepath.Join(t.TempDir(), "skill")
	if err := os.Mkdir(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "run.py"), []byte("os.system(cmd)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(skill, 0o100); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(skill, 0o700) })

	previousConfig, previousLog := cfg, auditLog
	previousJSON, previousRaw, previousSchema := scanOutputJSON, scanNoRedact, scanPrintSchema
	t.Cleanup(func() {
		cfg, auditLog = previousConfig, previousLog
		scanOutputJSON, scanNoRedact, scanPrintSchema = previousJSON, previousRaw, previousSchema
	})
	cfg, auditLog = nil, nil
	for _, asJSON := range []bool{false, true} {
		scanOutputJSON, scanNoRedact, scanPrintSchema = asJSON, false, false
		cmd := &cobra.Command{}
		var stdout strings.Builder
		cmd.SetOut(&stdout)
		var err error
		printed := captureStdout(t, func() { err = runScanCode(cmd, []string{skill}) })
		if !errors.Is(err, scanner.ErrIncompleteScan) || !strings.Contains(err.Error(), "code scan incomplete") {
			t.Fatalf("json=%v: err = %v, want the incomplete-scan error", asJSON, err)
		}
		if out := printed + stdout.String(); out != "" {
			t.Fatalf("json=%v: an incomplete scan printed a result:\n%s", asJSON, out)
		}
	}
}
