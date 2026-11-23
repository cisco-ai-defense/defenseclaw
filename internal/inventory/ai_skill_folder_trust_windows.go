// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"

	"golang.org/x/sys/windows"
)

// skillHomeOwnerTrust approves a folder a resolved skill path goes through
// when the owner of home (the scanning account when home is "") or SYSTEM,
// Administrators or TrustedInstaller owns it.
func skillHomeOwnerTrust(home string) func(*os.File, string) bool {
	var owner *windows.SID
	if home != "" {
		owner = skillPathOwner(home)
	} else if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		owner = user.User.Sid
	}
	if owner == nil {
		return func(*os.File, string) bool { return false }
	}
	return func(_ *os.File, path string) bool {
		folder := skillPathOwner(path)
		return folder != nil && (folder.Equals(owner) || skillAdminSID(folder))
	}
}
