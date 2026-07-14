//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func enterpriseHooksNativePlatformPreflight() error {
	if enterpriseHooksRuntimeGOOS() != "windows" {
		return nil
	}
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return fmt.Errorf("enterprise hooks require an elevated administrator or LocalSystem token on native Windows")
}
