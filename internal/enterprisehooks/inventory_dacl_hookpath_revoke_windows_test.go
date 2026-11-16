//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// GAP-2380: once OpenCode is disabled the enumerator grants the gateway its
// inventory read on ~\.config, and the per-user cleanup's walk to the
// OpenCode plugin refused that folder ("has 9 ACEs, expected 7") on every
// guardian pass. The cleanup now takes the grant off the dotdirs on that
// connector's hook path first; a connector whose hook path does not run
// through ~\.config leaves it alone.
func TestRevokeGatewayInventoryReadOnHookPathDotdirsUnblocksTheRemovalWalk(t *testing.T) {
	target := currentWindowsTestSID(t)
	home := t.TempDir()
	config := filepath.Join(home, ".config")
	plugins := filepath.Join(config, "opencode", "plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(plugins, "defenseclaw.js")
	if err := os.WriteFile(plugin, []byte("// plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config, filepath.Join(config, "opencode"), plugins, plugin} {
		// An elevated test run creates objects owned by Administrators; a
		// profile's are owned by its account.
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, target, nil, nil, nil); err != nil {
			t.Fatalf("set owner of %s: %v", path, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := setWindowsUserPathProtection(path, target, info.IsDir()); err != nil {
			t.Fatalf("set canonical DACL on %s: %v", path, err)
		}
	}
	gateway, err := windows.StringToSid(managed.WindowsServiceSIDString(productionGatewayServiceName))
	if err != nil {
		t.Fatal(err)
	}
	grant := func() {
		t.Helper()
		if result, err := ensureInventoryReadACE(config, gateway); err != nil || (result != inventoryDACLGranted && result != inventoryDACLAlreadyPresent) {
			t.Fatalf("grant = %v, %v", result, err)
		}
	}
	grant()
	if err := validateWindowsUserPathElement(config, target, true, true, true); err == nil {
		t.Fatal("~\\.config with the inventory grant passed the exact check the removal walk runs")
	}
	if err := RevokeGatewayInventoryReadOnHookPathDotdirs(home, "codex"); err != nil {
		t.Fatalf("revoke for codex: %v", err)
	}
	if err := validateWindowsUserPathElement(config, target, true, true, true); err == nil {
		t.Fatal("a connector whose hook path does not run through ~\\.config took the grant off it")
	}
	if err := RevokeGatewayInventoryReadOnHookPathDotdirs(home, "OpenCode"); err != nil {
		t.Fatalf("revoke for opencode: %v", err)
	}
	if err := validateWindowsUserPathElement(config, target, true, true, true); err != nil {
		t.Fatalf("~\\.config after the revoke is not at the exact protected DACL: %v", err)
	}
	if err := prepareWindowsGenericPath(home, plugin, target, false, false, false, "removal file"); err != nil {
		t.Fatalf("the removal walk still refuses after the revoke: %v", err)
	}
	if err := RevokeGatewayInventoryReadOnHookPathDotdirs(filepath.Join(home, "missing"), "amp"); err != nil {
		t.Fatalf("revoke on a missing profile: %v", err)
	}
}
