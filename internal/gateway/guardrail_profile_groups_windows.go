// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"errors"
	osuser "os/user"
)

// profileGroupExists asks the LSA whether a group named in an assignment
// (DOMAIN\name or a bare name) exists. An error means the answer is unknown,
// not that the group is absent.
var profileGroupExists = func(_ context.Context, name string) (bool, error) {
	_, err := osuser.LookupGroup(name)
	var unknown osuser.UnknownGroupError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &unknown):
		return false, nil
	default:
		return false, err
	}
}

// profileGroupQualifiedName has nothing to offer on Windows, where an
// assignment names a group as DOMAIN\\name or by its SID.
var profileGroupQualifiedName = func(context.Context, string) string { return "" }

// accountGroupIDs lists an OS account's group SIDs.
var accountGroupIDs = func(account *osuser.User) ([]string, error) { return account.GroupIds() }
