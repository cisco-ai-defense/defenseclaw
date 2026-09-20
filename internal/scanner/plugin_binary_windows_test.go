//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewPluginScannerResolvesPackagedInstalledLayout(t *testing.T) {
	installBin := filepath.Join(t.TempDir(), "DefenseClaw", "bin")
	if err := os.MkdirAll(installBin, 0o700); err != nil {
		t.Fatal(err)
	}
	gatewayPath := filepath.Join(installBin, "defenseclaw-gateway.exe")
	launcherPath := filepath.Join(installBin, "defenseclaw.exe")
	if err := os.WriteFile(launcherPath, []byte("launcher"), 0o600); err != nil {
		t.Fatal(err)
	}

	originalExecutable := pluginScannerExecutable
	pluginScannerExecutable = func() (string, error) { return gatewayPath, nil }
	t.Cleanup(func() { pluginScannerExecutable = originalExecutable })

	scanner := NewPluginScanner("")
	if scanner.BinaryPath != launcherPath {
		t.Fatalf("BinaryPath = %q, want packaged launcher %q", scanner.BinaryPath, launcherPath)
	}
	binary, args := scanner.pluginScanCommand(filepath.Join(t.TempDir(), "plugin"))
	if binary != launcherPath {
		t.Fatalf("command binary = %q, want %q", binary, launcherPath)
	}
	if len(args) < 3 || args[0] != "plugin" || args[1] != "scan" || args[2] != "--json" {
		t.Fatalf("command args = %v, want plugin scan --json", args)
	}
}

func TestNewPluginScannerPackagedResolutionIsProvenanceBound(t *testing.T) {
	root := t.TempDir()
	launcherPath := filepath.Join(root, "defenseclaw.exe")
	if err := os.WriteFile(launcherPath, []byte("launcher"), 0o600); err != nil {
		t.Fatal(err)
	}

	originalExecutable := pluginScannerExecutable
	t.Cleanup(func() { pluginScannerExecutable = originalExecutable })

	t.Run("non-gateway process keeps PATH lookup", func(t *testing.T) {
		pluginScannerExecutable = func() (string, error) {
			return filepath.Join(root, "some-tool.exe"), nil
		}
		if got := NewPluginScanner("defenseclaw").BinaryPath; got != "defenseclaw" {
			t.Fatalf("BinaryPath = %q, want bare default", got)
		}
	})

	t.Run("missing sibling keeps truthful default", func(t *testing.T) {
		pluginScannerExecutable = func() (string, error) {
			return filepath.Join(root, "missing", "defenseclaw-gateway.exe"), nil
		}
		if got := NewPluginScanner("defenseclaw").BinaryPath; got != "defenseclaw" {
			t.Fatalf("BinaryPath = %q, want bare default", got)
		}
	})

	t.Run("explicit scanner path is never replaced", func(t *testing.T) {
		pluginScannerExecutable = func() (string, error) {
			return filepath.Join(root, "defenseclaw-gateway.exe"), nil
		}
		explicit := filepath.Join(root, "custom", "scanner.exe")
		if got := NewPluginScanner(explicit).BinaryPath; got != explicit {
			t.Fatalf("BinaryPath = %q, want explicit %q", got, explicit)
		}
	})
}
