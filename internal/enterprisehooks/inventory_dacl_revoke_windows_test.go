// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-1765: the inventory grant on a folder that is also on a managed hook
// path (~\.config) broke the uninstall's removal trust check; revoking it
// restores the exact protected DACL.
func TestRevokeGatewayInventoryReadRestoresTheProtectedDACL(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := t.TempDir()
	config := filepath.Join(home, ".config")
	if err := os.Mkdir(config, 0o700); err != nil {
		t.Fatal(err)
	}
	// An elevated test run creates folders owned by Administrators; a
	// profile folder is owned by its account.
	if err := windows.SetNamedSecurityInfo(config, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, target, nil, nil, nil); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	if err := setWindowsUserPathProtection(config, target, true); err != nil {
		t.Fatalf("set canonical DACL: %v", err)
	}
	gateway, err := windows.StringToSid(windowsServiceSIDString(productionGatewayServiceName))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := ensureInventoryReadACE(config, gateway); err != nil || result != inventoryDACLGranted {
		t.Fatalf("grant = %v, %v", result, err)
	}
	if err := validateWindowsUserPathElement(config, target, true, true, true); err == nil {
		t.Fatal("the protected DACL with the inventory grant passed the trust check")
	}
	manifest := Manifest{Targets: []ManifestTarget{{UserHome: home, Connector: "amp"}, {UserHome: home, Connector: "opencode"}}}
	if err := RevokeGatewayInventoryReadForManifest(manifest); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := validateWindowsUserPathElement(config, target, true, true, true); err != nil {
		t.Fatalf("trust check after revoke: %v", err)
	}
	// A second pass and a missing folder are no-ops.
	if err := RevokeGatewayInventoryReadForManifest(manifest); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
}
