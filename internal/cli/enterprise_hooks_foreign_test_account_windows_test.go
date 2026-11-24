// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "golang.org/x/sys/windows"

// foreignHookTestAccountSID is the SID of the account the test runs as, a
// target whose registry hive is loaded (rel-1-0-10:GAP-1729). "" when the
// token cannot be read: the ledger identity is then empty and the test fails
// on it.
func foreignHookTestAccountSID() string {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return user.User.Sid.String()
}
