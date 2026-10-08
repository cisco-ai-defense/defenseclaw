//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// ErrEnrolledUserSignedOut is RemoveEnrolledUserAsset finding no token to act
// as the user: no session, and no S4U logon either, which a Microsoft Entra
// ID account does not have ("No credentials are available in the security
// package"). RemoveEnrolledUserAssetInSession succeeds once the user signs
// in (GAP-0414).
var ErrEnrolledUserSignedOut = errors.New("the user is signed out and the account has no S4U logon")

// RemoveEnrolledUserAsset deletes a quarantined skill or plugin folder in an
// enrolled user's profile for the hook guardian (GAP-0202). It runs as that
// user (the session token, else an S4U logon), only when the user, an
// administrator or SYSTEM owns the folder (purgeWindowsEnrolledAsset), and
// by handle without following junctions, so LocalSystem never
// deletes a user-controlled path with its own identity and the user can not
// point the deletion anywhere they could not delete themselves.
func RemoveEnrolledUserAsset(sid, home, path string) error {
	target, err := windows.StringToSid(sid)
	if err != nil {
		return fmt.Errorf("enterprise hooks: invalid enrolled user SID %q: %w", sid, err)
	}
	ran := false
	remove := func() error {
		ran = true
		return purgeWindowsEnrolledAsset(path, target)
	}
	err = withWindowsEnterpriseTargetImpersonation(target, home, remove)
	if err != nil && !ran {
		// No session token for a signed-out user: use an S4U logon.
		err = withWindowsEnterpriseS4UTargetImpersonation(target, home, remove)
		if err != nil && !ran {
			return fmt.Errorf("%w (%v)", ErrEnrolledUserSignedOut, err)
		}
	}
	return err
}

// RemoveEnrolledUserAssetInSession is RemoveEnrolledUserAsset with the session
// token only, for a removal deferred until the user signs in: it returns
// ErrEnrolledUserSignedOut while the user has no session, without an S4U
// logon attempt on every retry.
func RemoveEnrolledUserAssetInSession(sid, home, path string) error {
	target, err := windows.StringToSid(sid)
	if err != nil {
		return fmt.Errorf("enterprise hooks: invalid enrolled user SID %q: %w", sid, err)
	}
	ran := false
	err = withWindowsEnterpriseTargetImpersonation(target, home, func() error {
		ran = true
		return purgeWindowsEnrolledAsset(path, target)
	})
	if err != nil && !ran {
		return fmt.Errorf("%w (%v)", ErrEnrolledUserSignedOut, err)
	}
	return err
}

// purgeWindowsEnrolledAsset deletes a quarantined skill or plugin folder as
// the exact target token, like purgeWindowsTargetOwnedQuarantine, when the
// folder is owned by the user or by an administrator or SYSTEM: a folder an
// administrator or a SYSTEM job copied into the profile is owned by them, and
// the guardian refused it, so a CRITICAL skill stayed loadable (GAP-0574).
// The deletion still runs as the user and by handle without following
// junctions, so it removes only what the user may remove.
func purgeWindowsEnrolledAsset(path string, target *windows.SID) error {
	if target == nil {
		return fmt.Errorf("enterprise hooks: quarantine target SID is unavailable")
	}
	if err := windowsQuarantineTargetTokenCheck(target); err != nil {
		return fmt.Errorf("enterprise hooks: quarantine deletion requires exact target-token impersonation: %w", err)
	}
	handle, err := openWindowsQuarantineRoot(path)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	owner, ownerErr := windowsHandleOwner(handle)
	if ownerErr != nil {
		windows.CloseHandle(handle)
		return ownerErr
	}
	if !enrolledAssetOwnerAllowed(owner, target) {
		windows.CloseHandle(handle)
		return fmt.Errorf("the folder is owned by %s, not by the user, an administrator or SYSTEM", owner)
	}
	budget := &windowsQuarantineBudget{}
	purgeErr := purgeWindowsQuarantineHandle(handle, 0, budget, openWindowsQuarantineChild)
	closeErr := windows.CloseHandle(handle)
	if purgeErr != nil {
		return purgeErr
	}
	if closeErr != nil {
		return fmt.Errorf("enterprise hooks: close deleted quarantine root: %w", closeErr)
	}
	return nil
}

// enrolledAssetOwnerAllowed accepts the target user, the Administrators
// group, LocalSystem and the built-in Administrator account of this computer
// as the owner of an enrolled asset folder.
func enrolledAssetOwnerAllowed(owner, target *windows.SID) bool {
	if owner == nil || target == nil {
		return false
	}
	if owner.Equals(target) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	name, err := windows.ComputerName()
	if err != nil {
		return false
	}
	machine, _, kind, err := windows.LookupSID("", name)
	return err == nil && kind == windows.SidTypeDomain && strings.EqualFold(owner.String(), machine.String()+"-500")
}
