// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import "errors"

// WindowsProtectedTargetFromOtherRelease is the native Windows check; no
// other platform's guardian defers a protected target to a sign-in.
func WindowsProtectedTargetFromOtherRelease(InstallOptions) (string, bool, error) {
	return "", false, nil
}

// WindowsProtectedTargetHookFailModeChange is the native Windows check.
func WindowsProtectedTargetHookFailModeChange(InstallOptions) (string, string, error) {
	return "", "", nil
}

// WindowsSecureClientProfileProcess is the native Windows check.
func WindowsSecureClientProfileProcess() bool {
	return false
}

// IsWindowsEnterpriseNotLocalSystem is the native Windows check.
func IsWindowsEnterpriseNotLocalSystem(error) bool {
	return false
}

// WindowsTargetHasNoSession is the native Windows check; no other platform
// has a Windows session list, so it never proves a sign-out.
func WindowsTargetHasNoSession(string) (bool, error) {
	return false, errors.New("enterprise hooks: the Windows session list exists only on Windows")
}
