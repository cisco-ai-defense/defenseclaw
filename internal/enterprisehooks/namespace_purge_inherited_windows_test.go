// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const windowsNamespacePurgeInstallDirectorySDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

func setNamespacePurgeTestSecurity(t *testing.T, path, sddl string, info windows.SECURITY_INFORMATION) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("%s: %v", sddl, err)
	}
	owner, _, _ := sd.Owner()
	group, _, _ := sd.Group()
	dacl, _, _ := sd.DACL()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if info&windows.OWNER_SECURITY_INFORMATION == 0 {
		owner = nil
	}
	if info&windows.GROUP_SECURITY_INFORMATION == 0 {
		group = nil
	}
	if info&windows.DACL_SECURITY_INFORMATION == 0 {
		dacl = nil
	}
	set := func() error {
		return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil)
	}
	err = set()
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		// SYSTEM as the owner needs SeRestorePrivilege, which an elevated
		// GitHub runner token holds disabled: enable it on a locked thread,
		// as the native OTLP fixtures do (rel-1-0-6:GAP-0385).
		var held bool
		if err, held = runWithFixtureRestorePrivilege(set); !held {
			t.Fatalf("set %s on %s: this token does not hold SeRestorePrivilege, which a SYSTEM-owned fixture needs (run the package as an elevated administrator): %v", sddl, path, err)
		}
	}
	if err != nil {
		t.Fatalf("set %s on %s: %v", sddl, path, err)
	}
}

const (
	nsTestOwnerGroupDACL = windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION
)

// newInheritedNamespacePurgeTree makes an InstallDirectory-shaped root (as
// the standalone install creates it) holding what a killed first install
// leaves: bin and libexec folders and a file, all with only the inherited
// ACEs. bin is owned by LocalSystem (a Setup run as SYSTEM); libexec and
// bin\defenseclaw.exe are left as the elevated test process created them
// (owner Administrators, group the token's primary group).
func newInheritedNamespacePurgeTree(t *testing.T) (string, []string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "DefenseClaw")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	setNamespacePurgeTestSecurity(t, root, windowsNamespacePurgeInstallDirectorySDDL,
		nsTestOwnerGroupDACL|windows.PROTECTED_DACL_SECURITY_INFORMATION)
	bin := filepath.Join(root, "bin")
	libexec := filepath.Join(root, "libexec")
	for _, dir := range []string{bin, libexec} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(bin, "defenseclaw.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	setNamespacePurgeTestSecurity(t, bin, "O:SYG:SY", windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION)
	return root, []string{bin, libexec, exe}
}

func namespacePurgeHandle(t *testing.T, path string) windows.Handle {
	t.Helper()
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(ptr, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	return handle
}

// p0-round:GAP-1365, GAP-1587: an object a killed first install created
// under the standalone install root, before it was given its own protected
// DACL, carries only the ACEs it inherited from that root, owned by SYSTEM
// or by Administrators (an elevated Setup), with any primary group. Nothing
// looser matches, and the Secure Client set has no inherited shape.
func TestWindowsNamespacePurgeInheritedShapeOwnerAndDACLOnly(t *testing.T) {
	standalone, err := windowsNamespacePurgeCanonicalDescriptors(windowsNamespacePurgeTestGatewaySID)
	if err != nil {
		t.Fatal(err)
	}
	if len(standalone.inheritedDirectories) != 0 || len(standalone.inheritedFiles) != 0 {
		t.Fatal("the canonical (Secure Client) set carries inherited shapes")
	}
	if err := addWindowsNamespacePurgeInheritedDescriptors(standalone, windowsNamespacePurgeTestGatewaySID); err != nil {
		t.Fatal(err)
	}
	_, objects := newInheritedNamespacePurgeTree(t)
	bin, libexec, exe := objects[0], objects[1], objects[2]
	match := func(path string, directory bool) bool {
		t.Helper()
		allowed := standalone.inheritedFiles
		if directory {
			allowed = standalone.inheritedDirectories
		}
		matched, err := windowsNamespacePurgeInheritedMatches(namespacePurgeHandle(t, path), allowed)
		if err != nil {
			t.Fatal(err)
		}
		return matched
	}
	for _, tc := range []struct {
		path      string
		directory bool
	}{{bin, true}, {libexec, true}, {exe, false}} {
		if !match(tc.path, tc.directory) {
			t.Fatalf("inherited %s refused: %s", tc.path, ownerRewrittenTestSDDL(t, tc.path))
		}
	}
	if sddl := ownerRewrittenTestSDDL(t, exe); !strings.Contains(sddl, ";ID;") {
		t.Fatalf("fixture is not inherited-only: %s", sddl)
	}
	// Another owner, an explicit extra ACE, or a protected DACL with any
	// other ACE stays foreign.
	setNamespacePurgeTestSecurity(t, exe, "O:BU", windows.OWNER_SECURITY_INFORMATION)
	if match(exe, false) {
		t.Fatal("inherited file owned by Users accepted")
	}
	setNamespacePurgeTestSecurity(t, exe, "O:SYG:SYD:(A;;0x1301bf;;;BU)", nsTestOwnerGroupDACL|windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if match(exe, false) {
		t.Fatal("inherited file with an explicit Users write ACE accepted")
	}
	setNamespacePurgeTestSecurity(t, libexec, "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1301bf;;;BU)", nsTestOwnerGroupDACL|windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if match(libexec, true) {
		t.Fatal("protected folder with a Users write ACE accepted")
	}
}

func newInheritedNamespacePurgeRequest(t *testing.T, root, profile string) WindowsNamespacePurgeRequest {
	t.Helper()
	if err := requireWindowsEnterpriseAdministrator(); err != nil {
		t.Skipf("native namespace purge test requires elevation: %v", err)
	}
	oldAncestorTrust := windowsNamespacePurgeAncestorTrust
	oldRootScope := windowsNamespacePurgeRootScope
	windowsNamespacePurgeAncestorTrust = func(string) error { return nil }
	windowsNamespacePurgeRootScope = func(string, string) error { return nil }
	t.Cleanup(func() {
		windowsNamespacePurgeAncestorTrust = oldAncestorTrust
		windowsNamespacePurgeRootScope = oldRootScope
	})
	handle, err := openWindowsTargetsManifestObject(root, true, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	identity, identityErr := windowsManagedRuntimeHandleIdentity(handle, true)
	_ = windows.CloseHandle(handle)
	if identityErr != nil {
		t.Fatal(identityErr)
	}
	return WindowsNamespacePurgeRequest{
		SchemaVersion:     WindowsNamespacePurgeSchemaVersion,
		Root:              root,
		ExpectedIdentity:  identity,
		GatewayServiceSID: windowsNamespacePurgeTestGatewaySID,
		Profile:           profile,
	}
}

// The full exact-scope purge (the state-absent removal of a forced
// uninstall) removes a standalone install tree a killed first install left,
// SYSTEM-owned and admin-created inherited children included; the Secure
// Client purge of the same tree still refuses it, as on base.
func TestPurgeWindowsNamespaceRootRemovesInheritedChildrenOfAKilledInstall(t *testing.T) {
	root, _ := newInheritedNamespacePurgeTree(t)
	secureClient := newInheritedNamespacePurgeRequest(t, root, "")
	report, err := PurgeWindowsNamespaceRoot(secureClient)
	if err == nil || report.Removed || !strings.Contains(strings.ToLower(err.Error()), "foreign descriptor") {
		t.Fatalf("Secure Client purge of the inherited tree: report=%#v err=%v, want the foreign-descriptor refusal", report, err)
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatalf("the Secure Client refusal changed the root: %v", err)
	}
	standalone := newInheritedNamespacePurgeRequest(t, root, winpath.EnterpriseProfileStandalone)
	report, err = PurgeWindowsNamespaceRoot(standalone)
	if err != nil || !report.OK || !report.Removed || report.EntriesRemoved < 3 {
		t.Fatalf("standalone purge of the inherited tree: report=%#v err=%v", report, err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("root survived the purge: %v", err)
	}
}
