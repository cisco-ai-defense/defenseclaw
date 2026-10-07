// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	osuser "os/user"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// profileGroupExists asks the platform's account database (NSS on Linux,
// Open Directory on macOS) whether a group named in an assignment exists.
// An error means the answer is unknown, not that the group is absent.
var profileGroupExists = func(ctx context.Context, name string) (bool, error) {
	_, err := unixidentity.Default(ctx).LookupGroup(name)
	switch {
	case err == nil:
		return true, nil
	case unixidentity.IsNotFound(err):
		return false, nil
	default:
		return false, err
	}
}

// accountGroupIDs lists an OS account's group ids: os/user's listing, which
// on macOS is read again with `id -G` when it failed or filled its 256-group
// buffer (an account in more groups, GAP-0201).
var accountGroupIDs = func(account *osuser.User) ([]string, error) {
	return unixidentity.AccountGroupIDs(context.Background(), account)
}
