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
// drifted targets.yaml with the strict verdict and never repairs it in place,
// so a handle kept from the drift cannot leave an edited roster under a
// trusted descriptor; only a trusted rewrite recovers it. The Secure Client
// twin is TestEnterpriseHooksReconcileManagedUntrustedWriterOnManifest.
func TestEnterpriseHookManifestTrustCheckStandaloneDrift(t *testing.T) {
	requireAdministratorTestToken(t, "the product trusts only administrator-owned state folders; a standard user's test folder is untrusted by design")
	skipIfLocalSystem(t, "LocalSystem owns its t.TempDir() tree, so the fixture cannot stand in for a file a standard account owns")
	check := enterpriseHookManifestFileTrustCheck
	originalRepair, originalGOOS := enterpriseHookManifestACLRepair, enterpriseHooksRuntimeGOOS
	t.Cleanup(func() {
		enterpriseHookManifestACLRepair, enterpriseHooksRuntimeGOOS = originalRepair, originalGOOS
	})
	enterpriseHooksRuntimeGOOS = func() string { return "windows" }
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	calls := 0
	enterpriseHookManifestACLRepair = func(path string) error {
		calls++
		ownerOnlyDACLForTest(t, path)
		return nil
	}

	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets: []\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	ownerOnlyDACLForTest(t, manifest)
	if err := check(manifest); err != nil {
		t.Fatalf("trusted manifest refused: %v", err)
	}
	grantUntrustedWriterForTest(t, manifest)
	writer := openManifestHandleForTest(t, manifest, windows.GENERIC_READ|windows.GENERIC_WRITE)

	err := check(manifest)
	if err == nil || !strings.Contains(err.Error(), "untrusted Windows principal") ||
		!strings.Contains(err.Error(), `.\DefenseClawSetup-Enterprise-Standalone-x64.exe' /ensure`) {
		t.Fatalf("drifted manifest = %v, want the strict verdict and the Setup step", err)
	}
	if calls != 0 {
		t.Fatalf("repair calls = %d, want none on standalone", calls)
	}
	var written uint32
	if err := windows.WriteFile(writer, []byte("# edited\n"), &written, nil); err != nil {
		t.Fatalf("write through the retained handle: %v", err)
	}
	if err := check(manifest); err == nil {
		t.Fatal("standalone accepted a roster written through a retained handle")
	}

	// Setup writes a fresh manifest and replaces the old name; the old
	// handle points at the replaced object.
	fresh := manifest + ".setup"
	if err := os.WriteFile(fresh, []byte("version: 1\ntargets: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ownerOnlyDACLForTest(t, fresh)
	// [IO.File]::Replace renames the open old file aside, then moves the
	// fresh one onto the name.
	for _, move := range [][2]string{{manifest, manifest + ".backup"}, {fresh, manifest}} {
		from, _ := windows.UTF16PtrFromString(move[0])
		to, _ := windows.UTF16PtrFromString(move[1])
		if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
			t.Fatalf("move %s to %s: %v", move[0], move[1], err)
		}
	}
	if err := check(manifest); err != nil {
		t.Fatalf("standalone refused a manifest Setup rewrote: %v", err)
	}
	if err := windows.WriteFile(writer, []byte("# late edit\n"), &written, nil); err != nil {
		t.Fatalf("write through the old handle: %v", err)
	}
	if got, err := os.ReadFile(manifest); err != nil || string(got) != "version: 1\ntargets: []\n" {
		t.Fatalf("manifest = %q, %v after an old-handle write; want the rewritten roster", got, err)
	}
	if calls != 0 {
		t.Fatalf("repair calls = %d, want none on standalone", calls)
	}
}

func openManifestHandleForTest(t *testing.T, path string, access uint32) windows.Handle {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("open retained handle: %v", err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	return handle
}

// ownerOnlyDACLForTest stamps a protected DACL that grants only SYSTEM and
// Administrators, the shape Setup and the manifest repair leave; the owner
// keeps its implicit WRITE_DAC. An OWNER RIGHTS entry would be an untrusted
// writer.
func ownerOnlyDACLForTest(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
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
		t.Fatalf("set DACL on %s: %v", path, err)
	}
}
