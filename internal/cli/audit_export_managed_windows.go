// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// platformAuditExportCallerIsAdministrator accepts an elevated token or
// LocalSystem, the identities the managed audit database grants read access.
func platformAuditExportCallerIsAdministrator() bool {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return true
	}
	user, err := token.GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

func platformAuditExportManagedLayout() (managed.StandaloneLayout, error) {
	return managed.StandaloneWindowsLayout()
}
