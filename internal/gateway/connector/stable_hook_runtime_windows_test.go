// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// packagedWindowsHookBinaryAtUninstallRoot is a test-only strict resolver for
// exercising uninstall-trash layout validation without adding an otherwise
// unused production wrapper around the two production primitives.
func packagedWindowsHookBinaryAtUninstallRoot(executable, expectedRoot string) string {
	physicalRoot := packagedWindowsUninstallPhysicalRoot(executable, expectedRoot)
	if physicalRoot == "" {
		return ""
	}
	return packagedWindowsHookBinaryAtLayout(executable, physicalRoot, expectedRoot, false)
}

func TestCanonicalNativeWindowsInstallRootIgnoresConnectorEnvironmentOverrides(t *testing.T) {
	want := canonicalNativeWindowsInstallRoot()
	if strings.TrimSpace(want) == "" {
		t.Fatal("token-bound native install root is empty before environment overrides")
	}
	foreignProfile := t.TempDir()
	for name, value := range map[string]string{
		"USERPROFILE":  foreignProfile,
		"HOME":         foreignProfile,
		"LOCALAPPDATA": filepath.Join(foreignProfile, "AppData", "Local"),
		"APPDATA":      filepath.Join(foreignProfile, "AppData", "Roaming"),
	} {
		t.Setenv(name, value)
	}
	got := canonicalNativeWindowsInstallRoot()
	if !sameWindowsInstallPath(got, want) {
		t.Fatalf("token-bound native install root changed with connector environment: got %q, want %q", got, want)
	}
}

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
	logicalHook := filepath.Join(declaredRoot, "bin", windowsHookBinaryName)
	if got := packagedWindowsHookBinaryForRoot(gateway, declaredRoot); !sameWindowsInstallPath(got, logicalHook) {
		t.Fatalf("owned uninstall command = %q, want original installed sibling %q", got, logicalHook)
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

func TestPackagedWindowsRunningGatewayUsesExactInstalledSiblingWhileImageIsLocked(t *testing.T) {
	root, gateway, hook := stageRelocatedNativeInstallForTest(t, "")
	gatewayPointer, err := windows.UTF16PtrFromString(gateway)
	if err != nil {
		t.Fatal(err)
	}
	gatewayHandle, err := windows.CreateFile(
		gatewayPointer,
		windows.GENERIC_READ,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("lock packaged gateway image: %v", err)
	}
	defer windows.CloseHandle(gatewayHandle)

	hookPointer, err := windows.UTF16PtrFromString(hook)
	if err != nil {
		t.Fatal(err)
	}
	hookHandle, err := windows.CreateFile(
		hookPointer,
		windows.GENERIC_READ,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("lock packaged hook image: %v", err)
	}
	if got := packagedWindowsHookBinaryAtRoot(gateway, root); got != "" {
		t.Fatalf("non-running strict resolver accepted a sharing-locked gateway: %q", got)
	}

	released := make(chan error, 1)
	go func() {
		time.Sleep(250 * time.Millisecond)
		released <- windows.CloseHandle(hookHandle)
	}()
	if got := packagedWindowsHookBinaryForRoot(gateway, root); !sameWindowsInstallPath(got, hook) {
		t.Fatalf("running packaged resolver = %q, want exact installed sibling %q", got, hook)
	}
	if err := <-released; err != nil {
		t.Fatalf("release packaged hook image: %v", err)
	}
}
