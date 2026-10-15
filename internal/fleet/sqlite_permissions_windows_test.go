// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package fleet

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// Windows os.Chmod changes only the read-only attribute. Add a real Users
// read ACE so opening or reopening the store must repair an actual leak.
func widenSQLiteFileAccess(path string) error { return widenWindowsSQLiteAccess(path, false) }

func widenSQLiteParentAccess(path string) error { return widenWindowsSQLiteAccess(path, true) }

func widenWindowsSQLiteAccess(path string, inherit bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return err
	}
	var inheritance uint32
	if inherit {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		},
		{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(users),
			},
		},
	}, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return err
	}
	var validate func(string) error = safefile.ValidatePrivateFile
	if inherit {
		validate = safefile.ValidatePrivateDirectory
	}
	if err := validate(path); err == nil {
		return fmt.Errorf("Users-readable SQLite path was accepted as private: %s", path)
	}
	return nil
}

func assertSQLiteFilePrivate(path string) error {
	return safefile.ValidatePrivateFile(path)
}

func assertSQLiteParentPrivate(path string) error {
	return safefile.ValidatePrivateDirectory(path)
}
