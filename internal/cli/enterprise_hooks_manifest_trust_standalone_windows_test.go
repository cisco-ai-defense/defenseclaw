// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// GAP-0561: on the standalone profile the guardian manifest gate refuses a
// targets.yaml whose untrusted writer the repair did not remove, and accepts
// it once a repair has made it trusted. The Secure Client twin is
// TestEnterpriseHooksReconcileManagedUntrustedWriterOnManifest.
func TestEnterpriseHookManifestTrustCheckStandaloneDrift(t *testing.T) {
	skipIfLocalSystem(t, "LocalSystem owns its t.TempDir() tree, so the fixture cannot stand in for a file a standard account owns")
	check := enterpriseHookManifestFileTrustCheck
	originalRepair, originalGOOS := enterpriseHookManifestACLRepair, enterpriseHooksRuntimeGOOS
	t.Cleanup(func() {
		enterpriseHookManifestACLRepair, enterpriseHooksRuntimeGOOS = originalRepair, originalGOOS
	})
	enterpriseHooksRuntimeGOOS = func() string { return "windows" }
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)

	write := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "targets.yaml")
		if err := os.WriteFile(path, []byte("version: 1\ntargets: []\n"), 0o600); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
		grantUntrustedWriterForTest(t, path)
		return path
	}

	t.Run("unrepaired drift is refused", func(t *testing.T) {
		manifest := write(t)
		calls := 0
		enterpriseHookManifestACLRepair = func(string) error { calls++; return nil }
		err := check(manifest)
		if err == nil {
			t.Fatal("standalone accepted a guardian manifest with an Everyone writer")
		}
		if calls != 1 {
			t.Fatalf("repair calls = %d, want 1", calls)
		}
		if !strings.Contains(err.Error(), "hook guardian manifest") {
			t.Fatalf("manifest trust error = %v, want the strict hook guardian manifest verdict", err)
		}
	})

	t.Run("repaired drift is accepted", func(t *testing.T) {
		manifest := write(t)
		enterpriseHookManifestACLRepair = func(path string) error {
			ownerOnlyDACLForTest(t, path)
			return nil
		}
		if err := check(manifest); err != nil {
			t.Fatalf("standalone refused a guardian manifest the repair made trusted: %v", err)
		}
	})
}

// ownerOnlyDACLForTest stamps a protected DACL that grants only the process
// user, SYSTEM and Administrators, the shape the manifest repair leaves.
func ownerOnlyDACLForTest(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)")
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("repair DACL on %s: %v", path, err)
	}
}
