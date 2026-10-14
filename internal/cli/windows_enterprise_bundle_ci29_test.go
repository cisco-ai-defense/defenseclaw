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

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Exercises the same pre-apply creator and terminal receipt publisher as
// Setup. DC_WINDOWS_BUNDLE_TEST_ROOT lets an isolated Windows ACL probe inspect
// the tree after the test; ordinary test runs use a disposable temp directory.
func TestWindowsBundleReceiptEventsSetupAndPublisherContract(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	root := os.Getenv("DC_WINDOWS_BUNDLE_TEST_ROOT")
	if root == "" {
		root = windowsBundleScratchDir(t)
	}
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"fresh", "admin-only"} {
		t.Run(scenario, func(t *testing.T) {
			layout := managed.StandaloneLayout{ConfigDir: filepath.Join(root, scenario, "etc")}
			if err := os.MkdirAll(layout.ConfigDir, 0o700); err != nil {
				t.Fatal(err)
			}
			bundles := filepath.Join(layout.ConfigDir, enterprisebundle.BundlesDirName)
			if err := createWindowsBundleDirectory(bundles, windowsBundleDirectorySDDL(service.String())); err != nil {
				t.Fatal(err)
			}
			events := filepath.Join(bundles, enterprisestatus.PublicReceiptEventsDirName)
			if scenario == "admin-only" {
				if err := createWindowsBundleDirectory(events, windowsBundlePrivateSDDL()); err != nil {
					t.Fatal(err)
				}
			}
			if err := ensureWindowsBundleDirectory(layout); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(events, "r-01JA0000000000000000000033.json")
			if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := publishWindowsBundleReceipt(file); err != nil {
				t.Fatal(err)
			}
			for _, check := range []struct{ path, sddl string }{
				{events, windowsBundleDirectorySDDL(service.String())},
				{file, windowsBundleReceiptSDDL(service.String())},
			} {
				actual, err := windows.GetNamedSecurityInfo(check.path, windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s ACL: %s", check.path, actual.String())
				expected, err := windows.SecurityDescriptorFromString(check.sddl)
				if err != nil {
					t.Fatal(err)
				}
				matches, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
				if err != nil || !matches {
					t.Fatalf("receipt event ACL differs from the module contract: %s (%v)", check.path, err)
				}
			}
		})
	}
}

func TestWindowsBundleReceiptEventRepairsDirectoryACL(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	bundles := filepath.Join(t.TempDir(), "bundles")
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		t.Fatal(err)
	}
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
		{events, windowsBundleDirectorySDDL(service.String())},
		{path, windowsBundleReceiptSDDL(service.String())},
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
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		t.Fatal(err)
	}
	if err := createWindowsBundleDirectory(bundles, windowsBundlePrivateSDDL()); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(bundles, enterprisestatus.PublicReceiptEventsDirName)
	if err := os.MkdirAll(events, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(events, "r-01JA0000000000000000000033.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(events, "prior.json")
	if err := os.WriteFile(unknown, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsBundleReceiptEvents(bundles, service.String()); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ path, sddl string }{
		{events, windowsBundleDirectorySDDL(service.String())},
		{file, windowsBundleReceiptSDDL(service.String())},
		{unknown, windowsBundleAdminFileSDDL()},
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
