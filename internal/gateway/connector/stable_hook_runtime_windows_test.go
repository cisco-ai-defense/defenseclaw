// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const stableHookUninstallTransactionID = "0123456789abcdef0123456789abcdef"

func stageRelocatedNativeInstallForTest(t *testing.T, suffix string) (string, string, string) {
	t.Helper()
	parent := t.TempDir()
	declaredRoot := filepath.Join(parent, "DefenseClaw")
	physicalRoot := declaredRoot + suffix
	commandDir := filepath.Join(physicalRoot, "bin")
	installerDir := filepath.Join(physicalRoot, "installer")
	if err := os.MkdirAll(commandDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(commandDir, windowsGatewayBinaryName)
	hook := filepath.Join(commandDir, windowsHookBinaryName)
	for _, path := range []string{gateway, hook} {
		if err := os.WriteFile(path, []byte("MZ-test-native-binary"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := nativeWindowsInstallState{
		SchemaVersion: 1,
		InstallKind:   "native-windows-exe",
		InstallScope:  "user",
		InstallRoot:   declaredRoot,
		CommandDir:    filepath.Join(declaredRoot, "bin"),
		Runtime:       filepath.Join(declaredRoot, "runtime", "python"),
	}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installerDir, "install-state.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return declaredRoot, gateway, hook
}

func TestPackagedWindowsHookBinaryRecognizesOnlyOwnedUninstallTree(t *testing.T) {
	declaredRoot, gateway, hook := stageRelocatedNativeInstallForTest(
		t,
		".uninstall."+stableHookUninstallTransactionID,
	)
	if got := packagedWindowsHookBinaryAtUninstallRoot(gateway, declaredRoot); !sameWindowsInstallPath(got, hook) {
		t.Fatalf("owned uninstall hook = %q, want %q", got, hook)
	}

	for _, suffix := range []string{
		".uninstall.short",
		".uninstall.0123456789ABCDEF0123456789ABCDEF",
		".uninstall.0123456789abcdef0123456789abcdeg",
		".backup." + stableHookUninstallTransactionID,
	} {
		t.Run(suffix, func(t *testing.T) {
			root, candidate, _ := stageRelocatedNativeInstallForTest(t, suffix)
			if got := packagedWindowsHookBinaryAtUninstallRoot(candidate, root); got != "" {
				t.Fatalf("unsafe transaction suffix accepted: %q", got)
			}
		})
	}
}

func TestPackagedWindowsHookBinaryRejectsRelocatedTreeWithForeignState(t *testing.T) {
	declaredRoot, gateway, _ := stageRelocatedNativeInstallForTest(
		t,
		".uninstall."+stableHookUninstallTransactionID,
	)
	statePath := filepath.Join(filepath.Dir(filepath.Dir(gateway)), "installer", "install-state.json")
	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state nativeWindowsInstallState
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	state.InstallRoot = filepath.Join(t.TempDir(), "foreign")
	body, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := packagedWindowsHookBinaryAtUninstallRoot(gateway, declaredRoot); got != "" {
		t.Fatalf("foreign install state accepted: %q", got)
	}
}
