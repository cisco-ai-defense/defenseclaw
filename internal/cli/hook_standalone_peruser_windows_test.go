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

// A plugin-only connector never executes the hook binary, so a managed hook
// call naming one resolves no runtime and is closed.
func TestManagedHookOfAPluginOnlyConnectorIsClosed(t *testing.T) {
	for _, name := range []string{"amp"} {
		nativeEnterpriseHookRuntimeSnapshot.Lock()
		nativeEnterpriseHookRuntimeSnapshot.prepared = false
		nativeEnterpriseHookRuntimeSnapshot.Unlock()
		if prepareEnterpriseManagedHookRuntime(name) {
			t.Fatalf("%s: managed hook ended as a no-op", name)
		}
		if !enterpriseManagedHookRuntimeForceClosed() {
			t.Fatalf("%s accepted as an enterprise-managed hook connector", name)
		}
	}
	nativeEnterpriseHookRuntimeSnapshot.Lock()
	nativeEnterpriseHookRuntimeSnapshot.prepared = false
	nativeEnterpriseHookRuntimeSnapshot.err = nil
	nativeEnterpriseHookRuntimeSnapshot.Unlock()
}
