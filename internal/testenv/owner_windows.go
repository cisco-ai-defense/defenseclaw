// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package testenv

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OwnNewObjectsAsTokenUser makes the test process's own account the default
// owner of every file, folder and other object it creates from now on, and
// returns the default owner the token had. A package's TestMain calls it
// before any fixture exists.
//
// An elevated administrator's token (the built-in Administrator, an SSH or
// S4U session, an elevated prompt) names BUILTIN\Administrators as the
// default owner. A fixture tree it created was then owned by Administrators
// while the tests target the test account, and the product's exact-owner
// checks refused it: safefile ("refusing foreign-owned directory", GAP-0079),
// the inventory store (GAP-0823) and the enterprise hooks ("refusing to
// canonicalize wrong-owner path", GAP-0684). In production a per-user
// process makes the same change at start
// (managed.UseCurrentUserAsWindowsDefaultOwner) and the managed gateway
// adopts its service SID (managed.AdoptWindowsGatewayServiceFileOwner), so
// fixtures get the owner production custody gives them; the CI harness does
// it too (scripts/windows-native-ci.ps1 Set-CurrentUserAsDefaultOwner). The
// token user is always a valid owner in its own token. A standard user's and
// LocalSystem's tokens already name it, and no DACL or privilege changes.
func OwnNewObjectsAsTokenUser() (*windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token,
	); err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user == nil || user.User.Sid == nil {
		return nil, errors.New("the token user is unavailable")
	}
	// TOKEN_OWNER: the SID that becomes the owner of new objects.
	type tokenOwner struct{ Owner *windows.SID }
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if size < uint32(unsafe.Sizeof(tokenOwner{})) {
		return nil, errors.New("the token owner is unavailable")
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		return nil, err
	}
	previous, err := (*tokenOwner)(unsafe.Pointer(&buffer[0])).Owner.Copy()
	if err != nil {
		return nil, err
	}
	owner := tokenOwner{Owner: user.User.Sid}
	if err := windows.SetTokenInformation(
		token, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner)),
	); err != nil {
		return nil, err
	}
	return previous, nil
}
