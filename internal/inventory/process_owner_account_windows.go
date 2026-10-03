// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import "golang.org/x/sys/windows"

// currentWindowsAccount names this process's account the way Windows process
// rows do (DOMAIN\account, see nativeWindowsSnapshotReader.Details), or "".
func currentWindowsAccount() string {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}
