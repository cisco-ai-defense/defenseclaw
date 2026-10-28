// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Review loop round 4: an executable an elevated process or a service runs
// from a runtime folder under C:\ProgramData\Cisco is refused when a
// standard user can replace it, the folder or a folder between them, or a
// folder above them, ProgramData\Cisco included: every right that replaces
// a child (delete child, delete, change permissions, take ownership, full
// or generic all) and an untrusted owner, on any of them, and a file
// added to the runtime folder. The stock ProgramData grants (create files
// and folders, write attributes) stay accepted above the runtime folder.
// The advisory walk only warned for the Cisco folder, which is what the
// precondition shows.
func TestValidateTrustedRuntimeImageRefusesReplaceRightsOnEveryFolder(t *testing.T) {
	const (
		runtimeDir  = "DefenseClaw-ScannerRuntime"
		trustedDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	)
	user := ""
	for _, tc := range []struct {
		name    string
		element string // base, cisco, root or nested
		sddl    string
		refused bool
	}{
		{name: "stock tree", element: "cisco", sddl: testenv.AdminOnlySDDL},
		{name: "stock ProgramData create grants on Cisco", element: "cisco", sddl: "O:BA" + trustedDACL + "(A;;0x1201bf;;;BU)"},
		{name: "Users can delete the children of Cisco", element: "cisco", sddl: "O:BA" + trustedDACL + "(A;;0x1200e9;;;BU)", refused: true},
		{name: "Users can delete Cisco", element: "cisco", sddl: "O:BA" + trustedDACL + "(A;;0x1300a9;;;BU)", refused: true},
		{name: "Users can change the permissions of Cisco", element: "cisco", sddl: "O:BA" + trustedDACL + "(A;;0x1600a9;;;BU)", refused: true},
		{name: "Users can take ownership of Cisco", element: "cisco", sddl: "O:BA" + trustedDACL + "(A;;0x1a00a9;;;BU)", refused: true},
		{name: "Users have full control of Cisco", element: "cisco", sddl: "O:BA" + trustedDACL + "(A;;FA;;;BU)", refused: true},
		{name: "Authenticated Users have generic all on Cisco", element: "cisco", sddl: "O:BA" + trustedDACL + "(A;;GA;;;AU)", refused: true},
		{name: "a standard account owns Cisco", element: "cisco", sddl: "user", refused: true},
		{name: "Users can delete the children of the folder above Cisco", element: "base", sddl: "O:BA" + trustedDACL + "(A;;0x1200e9;;;BU)", refused: true},
		{name: "Users can add a file to the runtime folder", element: "root", sddl: "O:BA" + trustedDACL + "(A;;0x1200ab;;;BU)", refused: true},
		{name: "Users can delete the children of a folder between", element: "nested", sddl: "O:BA" + trustedDACL + "(A;;0x1200e9;;;BU)", refused: true},
		{name: "Users can add Python startup code", element: "nested", sddl: "O:BA" + trustedDACL + "(A;;0x1200ab;;;BU)", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cisco, root := testenv.CiscoRuntimeTree(t, runtimeDir)
			image := filepath.Join(root, "defenseclaw-scanners.exe")
			nestedImage := filepath.Join(root, "python", "python.exe")
			testenv.WriteAdminOnlyFile(t, image, []byte("runtime"))
			testenv.WriteAdminOnlyFile(t, nestedImage, []byte("python"))
			if !PlatformInstallerOwnedPath(cisco) || PlatformInstallerOwnedPath(filepath.Dir(cisco)) {
				t.Fatalf("precondition: %s must be installer-owned and its parent not", cisco)
			}
			sddl := tc.sddl
			if sddl == "user" {
				if user == "" {
					user = testenv.CurrentUserSID(t)
				}
				if user == "S-1-5-18" {
					t.Skip("the test runs as LocalSystem, a trusted owner")
				}
				sddl = "O:" + user + trustedDACL
			}
			target := map[string]string{"base": filepath.Dir(cisco), "cisco": cisco, "root": root, "nested": filepath.Dir(nestedImage)}[tc.element]
			testenv.SetSecurity(t, target, sddl)
			images := []string{nestedImage}
			if tc.element != "nested" {
				images = append(images, image)
			}
			for _, path := range images {
				err := ValidateTrustedRuntimeImage(root, path, "scanner runtime")
				if !tc.refused {
					if err != nil {
						t.Fatalf("%s refused: %v", path, err)
					}
					continue
				}
				if err == nil || !strings.Contains(err.Error(), target) {
					t.Fatalf("%s = %v, want a refusal naming %s", path, err, target)
				}
				if tc.element == "cisco" {
					// The advisory walk only warned here.
					if advisoryErr := ValidateTrustedFilePath(path, "scanner runtime"); advisoryErr != nil {
						t.Fatalf("precondition: the advisory walk refused %s: %v", path, advisoryErr)
					}
				}
			}
		})
	}

	// An image outside the folder it is checked with is refused.
	_, root := testenv.CiscoRuntimeTree(t, runtimeDir)
	outside := filepath.Join(filepath.Dir(root), "other.exe")
	testenv.WriteAdminOnlyFile(t, outside, []byte("other"))
	if err := ValidateTrustedRuntimeImage(root, outside, "scanner runtime"); err == nil || !strings.Contains(err.Error(), "not inside") {
		t.Fatalf("an image outside the runtime folder = %v, want refused", err)
	}
}

// The embedded interpreter imports sitecustomize and .pth files from
// site-packages. A protected python.exe is insufficient if any directory or
// existing import file beneath it admits an untrusted writer (GAP-0439).
func TestValidateTrustedRuntimeCodeTreeChecksWholeImportTree(t *testing.T) {
	const userCreate = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1200ab;;;BU)"
	for _, element := range []string{"python", "Lib", "site-packages", "module"} {
		t.Run(element, func(t *testing.T) {
			_, root := testenv.CiscoRuntimeTree(t, "DefenseClaw-ScannerRuntime")
			python := filepath.Join(root, "python")
			site := filepath.Join(python, "Lib", "site-packages")
			module := filepath.Join(site, "sitecustomize.py")
			testenv.WriteAdminOnlyFile(t, filepath.Join(python, "python.exe"), []byte("python"))
			testenv.WriteAdminOnlyFile(t, module, []byte("pass"))
			if err := ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime"); err != nil {
				t.Fatalf("trusted Python tree refused: %v", err)
			}
			target := map[string]string{"python": python, "Lib": filepath.Join(python, "Lib"),
				"site-packages": site, "module": module}[element]
			testenv.SetSecurity(t, target, userCreate)
			if err := ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime"); err == nil || !strings.Contains(err.Error(), target) {
				t.Fatalf("untrusted %s = %v, want refusal naming the path", target, err)
			}
		})
	}
}

func TestValidateTrustedRuntimeCodeTreeIgnoresRetiredUnpack(t *testing.T) {
	_, root := testenv.CiscoRuntimeTree(t, "DefenseClaw-ScannerRuntime")
	testenv.WriteAdminOnlyFile(t, filepath.Join(root, "runtime-digest", "python", "python.exe"), []byte("python"))
	stale := filepath.Join(root, ".stale-0123456789abcdef")
	if err := os.Mkdir(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	testenv.SetSecurity(t, stale, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1200ab;;;BU)")
	if err := ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime"); err != nil {
		t.Fatalf("a retired unpack prevented repair of the active runtime: %v", err)
	}
}

func TestValidateTrustedInstallMarkerDirRefusesReplaceableAncestor(t *testing.T) {
	cisco, root := testenv.CiscoRuntimeTree(t, "DefenseClaw")
	marker := filepath.Join(root, "secure-client.install")
	if err := os.Mkdir(marker, 0o755); err != nil {
		t.Fatal(err)
	}
	testenv.SetSecurity(t, marker, testenv.AdminOnlySDDL)
	if err := ValidateTrustedInstallMarkerDir(marker, "Secure Client install marker"); err == nil || !strings.Contains(err.Error(), marker) {
		t.Fatalf("Administrators-owned marker = %v, want SYSTEM owner refusal", err)
	}
	testenv.SetSecurity(t, cisco, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1200e9;;;BU)")
	if err := ValidateTrustedInstallMarkerDir(marker, "Secure Client install marker"); err == nil || !strings.Contains(err.Error(), cisco) {
		t.Fatalf("replaceable marker ancestor = %v, want refusal naming %s", err, cisco)
	}
}

func TestValidateTrustedInstallMarkerDirAcceptsSystemOwnedLeaf(t *testing.T) {
	_, root := testenv.CiscoRuntimeTree(t, "DefenseClaw")
	marker := filepath.Join(root, "secure-client.install")
	if err := os.Mkdir(marker, 0o755); err != nil {
		t.Fatal(err)
	}
	if testenv.CurrentUserSID(t) != "S-1-5-18" {
		t.Skip("setting a SYSTEM owner requires the native LocalSystem installer test cell")
	}
	testenv.SetSecurity(t, marker, "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
	if err := ValidateTrustedInstallMarkerDir(marker, "Secure Client install marker"); err != nil {
		t.Fatalf("SYSTEM-owned marker refused: %v", err)
	}
}
