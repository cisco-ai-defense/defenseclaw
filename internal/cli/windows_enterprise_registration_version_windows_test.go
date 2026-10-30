// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-2636: an /upgrade that Setup's TIMEOUTSECONDS stopped and its replay
// finished ends 1603 with the new version installed. The marker and the
// Add/Remove Programs entry must name that version, not the old one.
func TestFailedRunRefreshesTheRegisteredInstalledVersion(t *testing.T) {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	base := `Software\DefenseClawTest-gap2636-` + hex.EncodeToString(suffix)
	markerPath, arpPath := base+`\Enterprise`, base+`\Uninstall`
	t.Cleanup(func() {
		_ = registry.DeleteKey(registry.CURRENT_USER, markerPath)
		_ = registry.DeleteKey(registry.CURRENT_USER, arpPath)
		_ = registry.DeleteKey(registry.CURRENT_USER, base)
	})
	for _, path := range []string{markerPath, arpPath} {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
		if err != nil {
			t.Fatal(err)
		}
		name := "ProductVersion"
		if path == arpPath {
			name = "DisplayVersion"
		}
		if err := key.SetStringValue(name, "1.0.3"); err != nil {
			t.Fatal(err)
		}
		if err := key.SetStringValue("Publisher", "kept"); err != nil {
			t.Fatal(err)
		}
		key.Close()
	}

	result := &enterprisestatus.Result{Action: "upgrade", Installed: true, InstalledVersion: "1.0.6"}
	version, ok := windowsEnterpriseFailedRunInstalledVersion(result)
	if !ok || version != "1.0.6" {
		t.Fatalf("failed upgrade with the new version installed: got %q, %t", version, ok)
	}
	if err := refreshWindowsEnterpriseRegistrationVersion(registry.CURRENT_USER, markerPath, arpPath, version); err != nil {
		t.Fatal(err)
	}
	for path, name := range map[string]string{markerPath: "ProductVersion", arpPath: "DisplayVersion"} {
		key, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := key.GetStringValue(name)
		kept, _, keptErr := key.GetStringValue("Publisher")
		key.Close()
		if err != nil || got != "1.0.6" {
			t.Fatalf("%s %s = %q (%v), want 1.0.6", path, name, got, err)
		}
		if keptErr != nil || kept != "kept" {
			t.Fatalf("%s: other values must stay; Publisher = %q (%v)", path, kept, keptErr)
		}
	}

	// No registration to correct: a failed run never creates one.
	absent := base + `\Absent`
	if err := refreshWindowsEnterpriseRegistrationVersion(registry.CURRENT_USER, absent, absent+`ARP`, "1.0.6"); err != nil {
		t.Fatal(err)
	}
	if key, err := registry.OpenKey(registry.CURRENT_USER, absent, registry.QUERY_VALUE); err == nil {
		key.Close()
		t.Fatal("a failed run created a registration")
	}

	for name, run := range map[string]*enterprisestatus.Result{
		"pending transaction":  {Action: "upgrade", Installed: true, InstalledVersion: "1.0.6", TransactionPending: true},
		"no installed version": {Action: "upgrade", Installed: true},
		"not installed":        {Action: "install", InstalledVersion: "1.0.6"},
		"read-only action":     {Action: "verify", Installed: true, InstalledVersion: "1.0.6"},
		"successful run":       {Action: "upgrade", OK: true, Installed: true, InstalledVersion: "1.0.6"},
	} {
		if version, ok := windowsEnterpriseFailedRunInstalledVersion(run); ok {
			t.Errorf("%s: refreshed the registration to %q", name, version)
		}
	}
}
