// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func TestStandaloneEnterpriseHookExecutableMatchesOnlyTheStandaloneBinary(t *testing.T) {
	roots, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileStandalone)
	if err != nil {
		t.Skipf("trusted enterprise roots unavailable: %v", err)
	}
	secureClient, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil {
		t.Skipf("trusted Secure Client roots unavailable: %v", err)
	}
	for path, want := range map[string]bool{
		filepath.Join(roots.InstallRoot, "bin", "defenseclaw-hook.exe"):                            true,
		filepath.Join(roots.CertificationInstallBase, "0123456789", "bin", "defenseclaw-hook.exe"): true,
		filepath.Join(roots.InstallRoot, "bin", "defenseclaw-gateway.exe"):                         false,
		filepath.Join(roots.InstallRoot, "defenseclaw-hook.exe"):                                   false,
		filepath.Join(roots.CertificationInstallBase, "not-a-run", "bin", "defenseclaw-hook.exe"):  false,
		filepath.Join(secureClient.InstallRoot, "bin", "defenseclaw-hook.exe"):                     false,
		`C:\Users\someone\.local\bin\defenseclaw-hook.exe`:                                         false,
		`bin\defenseclaw-hook.exe`: false,
		"":                         false,
	} {
		if got := standaloneEnterpriseHookExecutable(path); got != want {
			t.Fatalf("standaloneEnterpriseHookExecutable(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestHookConnectorFromArgsAcceptsStandalonePerUserHookConnectors(t *testing.T) {
	// OpenCode's managed plugin runs the hook binary for every event.
	for _, name := range []string{"copilot", "antigravity", "devin", "hermes", "opencode", "codex", "claudecode", "cursor"} {
		got, err := hookConnectorFromArgs([]string{"hook", "--connector", name})
		if err != nil || got != name {
			t.Fatalf("%s: got %q err=%v", name, got, err)
		}
	}
	// A plugin-only connector never executes the hook binary.
	for _, name := range []string{"amp", "openhands"} {
		if _, err := hookConnectorFromArgs([]string{"hook", "--connector", name}); err == nil {
			t.Fatalf("%s accepted as an enterprise-managed hook connector", name)
		}
	}
}

func TestManagedHermesHookIgnoresTargetWritableTombstone(t *testing.T) {
	original := standaloneEnterpriseHookCheck
	standaloneEnterpriseHookCheck = func(string) bool { return true }
	t.Cleanup(func() { standaloneEnterpriseHookCheck = original })
	if !implicitEnterpriseManagedHook() {
		t.Fatal("standalone administrator binary did not select the managed runtime")
	}
	if NativeConnectorHookNoop([]string{"hook", "--connector", "hermes"}) {
		t.Fatal("a managed Hermes hook honored the per-user disable tombstone")
	}
}
