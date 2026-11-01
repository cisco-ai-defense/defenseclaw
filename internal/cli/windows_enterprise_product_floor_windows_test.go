// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"
)

// private #8: a Setup install, upgrade, repair or ensure below the confirmed
// bundle's release floor is refused before anything changes; read-only
// actions, the installed CLI (no payload), Secure Client and the recovery of
// a pending transaction are not checked.
func TestWindowsEnterpriseSetupBelowProductFloorIsRefusedBeforeAnyChange(t *testing.T) {
	e := newBundleCLIEnv(t)
	store := bundleDevice(t, e)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	confirmFloorBundleCLI(t, e, store, 2, "1.0.7")
	originalPending := windowsEnterpriseStandaloneRecoveryPending
	t.Cleanup(func() { windowsEnterpriseStandaloneRecoveryPending = originalPending })
	pending := false
	windowsEnterpriseStandaloneRecoveryPending = func(*windowsEnterpriseLifecycleOptions) bool { return pending }
	setup := func(version string) *windowsEnterpriseLifecycleOptions {
		return &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", jsonOutput: true,
			productVersion: version, gatewayBinary: `C:\payload\defenseclaw-gateway.exe`, acpBinary: `C:\payload\defenseclaw-acp.exe`,
			hookBinary: `C:\payload\defenseclaw-hook.exe`, sensorHelperBinary: `C:\payload\defenseclaw-sensor-helper.exe`}
	}
	for _, action := range []string{"install", "upgrade", "repair", "ensure"} {
		err := refuseWindowsEnterpriseBelowProductFloor(action, setup("1.0.6"))
		if err == nil || !strings.HasPrefix(err.Error(), windowsProductFloorRefused+": ") ||
			windowsEnterpriseMessageCode(err.Error(), "") != windowsProductFloorRefused {
			t.Fatalf("%s of 1.0.6 under floor 1.0.7: %v", action, err)
		}
		if err := refuseWindowsEnterpriseBelowProductFloor(action, setup("1.0.7")); err != nil {
			t.Fatalf("%s at the floor refused: %v", action, err)
		}
	}
	for _, action := range []string{"status", "verify", "uninstall", "reconcile"} {
		if err := refuseWindowsEnterpriseBelowProductFloor(action, setup("1.0.6")); err != nil {
			t.Fatalf("read-only or removing %s refused: %v", action, err)
		}
	}
	for name, opts := range map[string]*windowsEnterpriseLifecycleOptions{
		"installed CLI (no payload)": {profile: "standalone", resolvedProfile: "standalone", productVersion: "1.0.6"},
		"Secure Client":              {profile: "secure_client", resolvedProfile: "secure_client", productVersion: "1.0.6"},
	} {
		if err := refuseWindowsEnterpriseBelowProductFloor("ensure", opts); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	pending = true
	if err := refuseWindowsEnterpriseBelowProductFloor("repair", setup("1.0.6")); err != nil {
		t.Fatalf("recovery of a pending transaction refused: %v", err)
	}
}
