// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// nativeOTLPTakeBackMarkerOwnerTrusted refuses a take-back-pending marker
// that another account owns (GAP-2021): its owner must be the owner of the
// account's managed data directory (the take-back writes it as that
// account), LocalSystem, Administrators, or this process's user.
func nativeOTLPTakeBackMarkerOwnerTrusted(path string, _ os.FileInfo) error {
	owner, err := nativeOTLPTakeBackPathOwner(path)
	if err != nil {
		return err
	}
	dirOwner, err := nativeOTLPTakeBackPathOwner(filepath.Dir(path))
	if err != nil {
		return err
	}
	if owner.Equals(dirOwner) || owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	if user, userErr := windows.GetCurrentProcessToken().GetTokenUser(); userErr == nil && owner.Equals(user.User.Sid) {
		return nil
	}
	return fmt.Errorf("take-back marker %s: owner %s is not the data directory's owner", path, owner.String())
}

func nativeOTLPTakeBackPathOwner(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("take-back marker owner %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil, fmt.Errorf("take-back marker owner %s: no owner", path)
	}
	return owner.Copy()
}
