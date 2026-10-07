//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"

	"golang.org/x/sys/windows"
)

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
	}
	return err
}
