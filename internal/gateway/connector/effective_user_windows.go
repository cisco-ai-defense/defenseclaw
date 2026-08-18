// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// windowsEffectiveUserSID is the one identity every per-user artifact in this
// package is created under and validated against.
var windowsEffectiveUserSID = defaultWindowsEffectiveUserSID

// defaultWindowsEffectiveUserSID returns the impersonated thread user when one
// is installed, and the process user otherwise. Windows takes a new object's
// owner from the same token, so this is who owns what the caller creates.
func defaultWindowsEffectiveUserSID() (*windows.SID, error) {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err == nil {
		defer token.Close()
		user, userErr := token.GetTokenUser()
		if userErr != nil {
			return nil, userErr
		}
		if user == nil || user.User.Sid == nil {
			return nil, fmt.Errorf("effective Windows thread token has no user SID")
		}
		return user.User.Sid.Copy()
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user == nil || user.User.Sid == nil {
		return nil, fmt.Errorf("Windows process token has no user SID")
	}
	return user.User.Sid.Copy()
}
