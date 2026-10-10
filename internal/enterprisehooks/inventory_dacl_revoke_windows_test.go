// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// GAP-1324: a user who made a parent of a component folder
// (AppData\Local\hermes) a junction to another account's folder, or a
// profile file a hard link to another account's file, does not take the
// gateway's read ACE off that account's folder or file when revoked.
func TestRevokeGatewayInventoryReadSkipsAJunctionBelowTheProfile(t *testing.T) {
	gateway, err := windows.StringToSid(windowsServiceSIDString(productionGatewayServiceName))
	if err != nil {
		t.Fatal(err)
	}
	userA, userB := t.TempDir(), t.TempDir()
	const hermes = `appdata\local\hermes`
	var rel, linked string
	for _, dir := range inventoryDACLComponentDirs(userA) {
		if strings.HasPrefix(strings.ToLower(dir), hermes+`\`) {
			rel, linked = dir, dir[:len(hermes)]
			break
		}
	}
	if rel == "" {
		t.Fatal("no Hermes component folder below " + hermes)
	}
	other := filepath.Join(userB, rel)
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if result, err := ensureInventoryReadACE(other, gateway); err != nil || result != inventoryDACLGranted {
		t.Fatalf("grant = %v, %v", result, err)
	}
	if err := os.MkdirAll(filepath.Join(userA, filepath.Dir(linked)), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(userA, linked), filepath.Join(userB, linked)).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	// A hard link to the other account's .claude.json shares its DACL.
	otherFile := filepath.Join(userB, ".claude.json")
	if err := os.WriteFile(otherFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := ensureInventorySelfACE(otherFile, gateway); err != nil || result != inventoryDACLGranted {
		t.Fatalf("file grant = %v, %v", result, err)
	}
	if err := os.Link(otherFile, filepath.Join(userA, ".claude.json")); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Targets: []ManifestTarget{{UserHome: userA, Connector: "hermes"}}}
	if err := RevokeGatewayInventoryReadForManifest(manifest); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(other, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if acl, _, err := sd.DACL(); err != nil || acl == nil || !daclHasACEFor(acl, []*windows.SID{gateway}) {
		t.Fatalf("the other account's %s lost the gateway ACE through the junction (err %v)", rel, err)
	}
	sd, err = windows.GetNamedSecurityInfo(otherFile, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if acl, _, err := sd.DACL(); err != nil || acl == nil || !daclHasACEFor(acl, []*windows.SID{gateway}) {
		t.Fatalf("the other account's .claude.json lost the gateway ACE through a hard link (err %v)", err)
	}
}
