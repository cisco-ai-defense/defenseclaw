//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func withoutPublishedSessionACL(*testing.T) {}

func publishedSessionTestIdentity(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToUpper(user.User.Sid.String())
}

func publishedSessionOtherIdentity(string) string { return "S-1-5-21-1111-2222-3333-4242" }

// The per-account folder's protected DACL: SYSTEM and Administrators full,
// the gateway (this process) modify, the account read, nobody else.
func TestPublishedSessionDirSDDLGrantsOnlyTheAccountRead(t *testing.T) {
	service, _ := windows.StringToSid("S-1-5-80-1-2-3-4-5")
	account, _ := windows.StringToSid("S-1-5-21-1111-2222-3333-1001")
	sddl := publishedSessionDirSDDL(service, account)
	if !strings.HasPrefix(sddl, "O:S-1-5-80-1-2-3-4-5D:P(") || strings.Contains(sddl, ";BU)") || strings.Contains(sddl, ";WD)") ||
		!strings.Contains(sddl, "(A;OICI;0x1200a9;;;S-1-5-21-1111-2222-3333-1001)") ||
		!strings.Contains(sddl, "(A;OICI;0x1301bf;;;S-1-5-80-1-2-3-4-5)") {
		t.Fatalf("unexpected DACL %s", sddl)
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatal(err)
	}
}

// Kill switch, on a real Windows file: the key file's protected DACL gives
// standard users its attributes and security descriptor only (no access a
// sharing mode applies to, so none can hold it open and keep it from being
// removed, and no DELETE, so none can rename it), the gateway service
// DELETE besides, and SYSTEM and Administrators full control.
func TestPublishedSessionKeyFileGivesOnlyTheGatewayItsRemoval(t *testing.T) {
	root := filepath.Join(t.TempDir(), "DefenseClaw-HookSessions")
	withPublishedSessionKeysOfTheTestAccount(t)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path, err := createAccountTestKey(root, publishedSessionTestIdentity(t), publishedSessionTestTrust)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := managed.WindowsServiceAccountSID(publishedSessionTestTrust.ServiceAccount)
	if err != nil || gateway == nil {
		t.Fatalf("gateway SID: %v", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := descriptor.String()
	if !strings.Contains(sddl, "D:P") || !strings.Contains(sddl, "(A;;0x120080;;;BU)") || strings.Contains(sddl, ";WD)") || strings.Contains(sddl, ";AU)") ||
		!strings.Contains(sddl, "(A;;0x130080;;;"+gateway.String()+")") {
		t.Fatalf("the key file's DACL must give standard users no access a sharing mode applies to: %s", sddl)
	}
	if _, err := createAccountTestKey(filepath.Join(t.TempDir(), "x"), publishedSessionTestIdentity(t), PublishedSessionTrust{}); err == nil {
		t.Fatal("a key file in a folder that does not exist must not be made")
	}
	if err := RevokePublishedSessionKey(root, publishedSessionTestIdentity(t)); err != nil {
		t.Fatal(err)
	}
}

// Kill switch: the key file is next to the record folder in
// %ProgramData%\Cisco, where no standard user may rename or delete a file
// another account made, and not in the record folder, which an account
// that kept a handle on it could change.
func TestPublishedSessionKeyIsInTheCiscoFolder(t *testing.T) {
	layout, err := managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	dir, ok := PublishedSessionKeyDir(layout.HookSessionDir)
	if !ok || !strings.EqualFold(dir, `C:\ProgramData\Cisco`) {
		t.Fatalf("the key folder must be %s: %q", `C:\ProgramData\Cisco`, dir)
	}
}
