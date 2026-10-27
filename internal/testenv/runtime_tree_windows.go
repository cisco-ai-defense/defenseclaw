// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package testenv

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AdminOnlySDDL is a protected folder or file that SYSTEM and Administrators
// own and control and that standard users can only read.
const AdminOnlySDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

// CiscoRuntimeTree builds <ProgramData>\dc-trust-*\Cisco\<name> for a test,
// every folder owned by Administrators with AdminOnlySDDL, and points
// %ProgramData% at the outer folder for the test, so its Cisco folder is an
// installer-owned folder as C:\ProgramData\Cisco is. It sits under the real
// ProgramData so the folders above it have stock trusted owners, which a
// user temporary folder does not. It returns the Cisco folder and the
// runtime folder, and skips the test unless the process is elevated.
func CiscoRuntimeTree(t *testing.T, name string) (cisco, root string) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the runtime tree is administrator-only; run elevated")
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(programData, "dc-trust-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	SetSecurity(t, base, AdminOnlySDDL)
	t.Setenv("ProgramData", base)
	cisco = filepath.Join(base, "Cisco")
	root = filepath.Join(cisco, name)
	for _, dir := range []string{cisco, root} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		SetSecurity(t, dir, AdminOnlySDDL)
	}
	return cisco, root
}

// WriteAdminOnlyFile writes body at path, creating the folders it needs, and
// gives the file and each folder it created AdminOnlySDDL, Administrators
// owning them whoever the test runs as.
func WriteAdminOnlyFile(t *testing.T, path string, body []byte) {
	t.Helper()
	var created []string
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil || dir == filepath.Dir(dir) {
			break
		}
		created = append(created, dir)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := len(created) - 1; i >= 0; i-- {
		SetSecurity(t, created[i], AdminOnlySDDL)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	SetSecurity(t, path, AdminOnlySDDL)
}

// SetSecurity sets the owner and the protected DACL of path from sddl.
func SetSecurity(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("security descriptor %q: %v", sddl, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		t.Fatalf("set the security of %s to %s: %v", path, sddl, err)
	}
}

// CurrentUserSID is the SID of the account the test runs as.
func CurrentUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

// AsAdministratorsOwner runs fn with BUILTIN\Administrators as the owner of
// the files the process creates, as for an installer elevated through UAC.
// The built-in Administrator account (a GitHub runner, an EC2 instance's
// Administrator) owns them itself otherwise, which the runtime trust checks
// refuse for an administrator-owned tree.
func AsAdministratorsOwner(t *testing.T, fn func()) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if size == 0 {
		t.Fatal("token owner is unavailable")
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		t.Fatal(err)
	}
	type tokenOwner struct{ Owner *windows.SID }
	previous, err := (*tokenOwner)(unsafe.Pointer(&buffer[0])).Owner.Copy()
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	set := func(owner *windows.SID) error {
		value := tokenOwner{Owner: owner}
		return windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&value)), uint32(unsafe.Sizeof(value)))
	}
	if err := set(admins); err != nil {
		t.Fatalf("make Administrators the owner of new files: %v", err)
	}
	defer func() {
		if err := set(previous); err != nil {
			t.Errorf("restore the token owner: %v", err)
		}
	}()
	fn()
}
