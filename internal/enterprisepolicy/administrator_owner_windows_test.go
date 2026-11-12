//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"testing"

	"golang.org/x/sys/windows"
)

// writeAdministratorFile writes a file the way an elevated administrator's
// process leaves it on a default Windows host: owned by the group
// BUILTIN\Administrators, which is what the trust rules call an
// administrator's file. A GitHub runner, and any host that sets "Default owner
// for objects created by members of the Administrators group" to "Object
// creator", leaves the file owned by the user instead, which the rules treat
// as a standard user's file; so a test that needs an administrator's file sets
// the owner itself.
func writeAdministratorFile(t *testing.T, path, content string) {
	t.Helper()
	writeFile(t, path, content)
	setAdministratorsOwner(t, path)
}

func setAdministratorsOwner(t *testing.T, path string) {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("Administrators SID: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
		t.Fatalf("set owner of %s to Administrators: %v", path, err)
	}
}
