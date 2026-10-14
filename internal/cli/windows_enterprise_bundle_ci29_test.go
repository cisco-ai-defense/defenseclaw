// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestWindowsBundleReceiptEventRepairsDirectoryACL(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	bundles := filepath.Join(t.TempDir(), "bundles")
	if err := createWindowsBundleDirectory(bundles, windowsBundlePrivateSDDL()); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(bundles, enterprisestatus.PublicReceiptEventsDirName)
	if err := os.MkdirAll(events, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(events, "r-01JA0000000000000000000033.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publishWindowsBundleReceipt(path); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ path, sddl string }{
		{events, windowsBundlePrivateSDDL()},
		{path, windowsBundleAdminFileSDDL()},
	} {
		actual, err := windows.GetNamedSecurityInfo(check.path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := windows.SecurityDescriptorFromString(check.sddl)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := actual.Control()
		if err != nil {
			t.Fatal(err)
		}
		matches, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
		if err != nil || !matches || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("receipt event ACL differs from module contract: %s: %s (%v)", check.path, actual.String(), err)
		}
	}
}

func TestWindowsBundleReceiptEventsRepairPriorFiles(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	bundles := filepath.Join(t.TempDir(), "bundles")
	if err := createWindowsBundleDirectory(bundles, windowsBundlePrivateSDDL()); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(bundles, enterprisestatus.PublicReceiptEventsDirName)
	if err := os.MkdirAll(events, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(events, "prior.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsBundleReceiptEvents(bundles); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ path, sddl string }{
		{events, windowsBundlePrivateSDDL()},
		{file, windowsBundleAdminFileSDDL()},
	} {
		actual, err := windows.GetNamedSecurityInfo(check.path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := windows.SecurityDescriptorFromString(check.sddl)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := actual.Control()
		if err != nil {
			t.Fatal(err)
		}
		matches, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
		if err != nil || !matches || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("prior receipt event ACL differs from module contract: %s: %s (%v)", check.path, actual.String(), err)
		}
	}
}
