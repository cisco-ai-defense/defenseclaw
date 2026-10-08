//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"

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
// user (the session token, else an S4U logon), only when the user owns the
// folder, and by handle without following junctions, so LocalSystem never
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
		return purgeWindowsTargetOwnedQuarantine(path, target)
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
		return purgeWindowsTargetOwnedQuarantine(path, target)
	})
	if err != nil && !ran {
		return fmt.Errorf("%w (%v)", ErrEnrolledUserSignedOut, err)
	}
	return err
}
