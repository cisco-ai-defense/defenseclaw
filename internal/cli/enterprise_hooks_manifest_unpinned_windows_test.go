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

// GAP-1048: Setup's own process carries no standalone trust scope (no profile
// pin, and it runs from wherever the administrator put it), so the manifest
// gate took its Secure Client branch there and re-stamped a targets.yaml an
// untrusted account could write, in place, on every ensure. The bytes that
// account wrote then reached the guardian under a trusted descriptor.

func manifestDescriptorForTest(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read the descriptor of %s: %v", path, err)
	}
	return descriptor.String()
}

func untrustedManifestForTest(t *testing.T) string {
	t.Helper()
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets: []\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	ownerOnlyDACLForTest(t, manifest)
	grantUntrustedWriterForTest(t, manifest)
	return manifest
}

func TestStandaloneClaudeMachineHookContractNeverRestampsAnUntrustedManifest(t *testing.T) {
	requireAdministratorTestToken(t, "the product trusts only administrator-owned state folders; a standard user's test folder is untrusted by design")
	skipIfLocalSystem(t, "LocalSystem owns its t.TempDir() tree, so the fixture cannot stand in for a file a standard account owns")
	originalRepair, originalGOOS := enterpriseHookManifestACLRepair, enterpriseHooksRuntimeGOOS
	t.Cleanup(func() {
		enterpriseHookManifestACLRepair, enterpriseHooksRuntimeGOOS = originalRepair, originalGOOS
	})
	enterpriseHooksRuntimeGOOS = func() string { return "windows" }
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	// Setup's own process: no profile pin.
	t.Setenv(managed.EnterpriseProfileEnv, "")
	repairs := 0
	enterpriseHookManifestACLRepair = func(path string) error {
		repairs++
		ownerOnlyDACLForTest(t, path)
		return nil
	}

	manifest := untrustedManifestForTest(t)
	before := manifestDescriptorForTest(t, manifest)
	if contract := standaloneClaudeMachineHookContract(managed.StandaloneLayout{ManifestPath: manifest}); contract != "" {
		t.Fatalf("contract = %q, want none from a manifest an untrusted account can write", contract)
	}
	if repairs != 0 {
		t.Fatalf("manifest re-stamped in place %d time(s) by a read", repairs)
	}
	if after := manifestDescriptorForTest(t, manifest); after != before {
		t.Fatalf("the read changed the manifest descriptor:\n before %s\n after  %s", before, after)
	}
	if got := os.Getenv(managed.EnterpriseProfileEnv); got != "" {
		t.Fatalf("the read left %s=%q in Setup's environment", managed.EnterpriseProfileEnv, got)
	}
}

func TestRepairEnterpriseHookManifestACLRefusesAnUntrustedManifestOnAStandaloneHost(t *testing.T) {
	requireAdministratorTestToken(t, "the product trusts only administrator-owned state folders; a standard user's test folder is untrusted by design")
	skipIfLocalSystem(t, "LocalSystem owns its t.TempDir() tree, so the fixture cannot stand in for a file a standard account owns")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	previous := managedHostWindowsStandalone
	t.Cleanup(func() { managedHostWindowsStandalone = previous })
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\` + WindowsEnterpriseMarkerKey, true }

	manifest := untrustedManifestForTest(t)
	before := manifestDescriptorForTest(t, manifest)
	err := repairEnterpriseHookManifestACL(manifest)
	if err == nil || !strings.Contains(err.Error(), "not repaired in place") {
		t.Fatalf("repair of an untrusted manifest on a standalone host = %v, want a refusal", err)
	}
	if after := manifestDescriptorForTest(t, manifest); after != before {
		t.Fatalf("the refused repair changed the manifest descriptor:\n before %s\n after  %s", before, after)
	}
}
