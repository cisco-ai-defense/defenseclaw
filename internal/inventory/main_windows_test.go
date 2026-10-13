// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"fmt"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestMain makes the token user the owner of every file and folder the tests
// create. An elevated run (an SSH Administrator, a CI runner) otherwise
// creates them owned by BUILTIN\Administrators, which the private AI discovery
// state store refuses as foreign-owned, so every test that persists the
// inventory read back an empty store (GAP-0823). A per-user gateway runs as a
// standard user, whose objects it owns.
func TestMain(m *testing.M) {
	if err := ownNewObjectsAsTokenUser(); err != nil {
		fmt.Fprintln(os.Stderr, "inventory tests: set the default owner:", err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func ownNewObjectsAsTokenUser() error {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token,
	); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	// TOKEN_OWNER: the SID that becomes the owner of new objects.
	owner := struct{ Owner *windows.SID }{Owner: user.User.Sid}
	return windows.SetTokenInformation(
		token, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner)),
	)
}
