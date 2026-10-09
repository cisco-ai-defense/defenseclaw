// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"errors"
	osuser "os/user"
	"strings"

	"golang.org/x/sys/windows"
)

// profileGroupExists asks the LSA whether a group named in an assignment
// (DOMAIN\name or a bare name) exists. An error means the answer is unknown,
// not that the group is absent.
var profileGroupExists = func(_ context.Context, name string) (bool, error) {
	// Go's os/user.LookupGroup does not reliably resolve DOMAIN\name for
	// the LocalSystem service. Ask the LSA directly, as profile explain does
	// for accounts. Only ERROR_NONE_MAPPED proves the group is absent.
	var sid *windows.SID
	var err error
	if strings.HasPrefix(strings.ToUpper(name), "S-1-") {
		sid, err = windows.StringToSid(name)
		if err != nil {
			// Parsing is local and definitive: a malformed SID cannot match.
			return false, nil
		}
	} else {
		sid, _, _, err = windows.LookupSID("", name)
	}
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, _, kind, err := sid.LookupAccount("")
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return kind == windows.SidTypeGroup || kind == windows.SidTypeAlias ||
		kind == windows.SidTypeWellKnownGroup, nil
}

func init() { profileGroupSIDLookup = lsaProfileGroupSID }

// lsaProfileGroupSID resolves an assignment group name (DOMAIN\name or a bare
// name) to the SID of that group (LookupAccountName). A name the LSA maps to
// no group, or to an account that is not a group, is errProfileGroupUnknown.
func lsaProfileGroupSID(name string) (string, error) {
	sid, _, kind, err := windows.LookupSID("", name)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return "", errProfileGroupUnknown
	}
	if err != nil {
		return "", err
	}
	if kind != windows.SidTypeGroup && kind != windows.SidTypeAlias && kind != windows.SidTypeWellKnownGroup {
		return "", errProfileGroupUnknown
	}
	return sid.String(), nil
}

// profileGroupQualifiedName has nothing to offer on Windows, where an
// assignment names a group as DOMAIN\\name or by its SID.
var profileGroupQualifiedName = func(context.Context, string) string { return "" }

// profileUserEntryUnmatched has nothing to report on Windows, where the LSA
// names every account DOMAIN\name and the entry is matched against that.
func profileUserEntryUnmatched() func(context.Context, string) string { return nil }

// accountGroupIDs lists an OS account's group SIDs.
var accountGroupIDs = func(account *osuser.User) ([]string, error) { return account.GroupIds() }
