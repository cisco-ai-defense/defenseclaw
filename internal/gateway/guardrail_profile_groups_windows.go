// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"errors"
	osuser "os/user"

	"golang.org/x/sys/windows"
)

// profileGroupExists asks the LSA whether a group named in an assignment
// (DOMAIN\name or a bare name) exists. An error means the answer is unknown,
// not that the group is absent.
var profileGroupExists = func(_ context.Context, name string) (bool, error) {
	// Go's os/user.LookupGroup does not reliably resolve DOMAIN\name for
	// the LocalSystem service. Ask the LSA directly, as profile explain does
	// for accounts. Only ERROR_NONE_MAPPED proves the group is absent.
	sid, _, _, err := windows.LookupSID("", name)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, _, kind, err := sid.LookupAccount("")
	if err != nil {
		return false, err
	}
	return kind == windows.SidTypeGroup || kind == windows.SidTypeAlias ||
		kind == windows.SidTypeWellKnownGroup, nil
}

// profileGroupQualifiedName has nothing to offer on Windows, where an
// assignment names a group as DOMAIN\\name or by its SID.
var profileGroupQualifiedName = func(context.Context, string) string { return "" }

// accountGroupIDs lists an OS account's group SIDs.
var accountGroupIDs = func(account *osuser.User) ([]string, error) { return account.GroupIds() }
