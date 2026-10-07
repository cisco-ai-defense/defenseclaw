// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
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
	case unixidentity.IsNotFound(err) && !unixidentity.GroupNameLookupDefinitive():
		// Himmelblau finds an Entra group only by gid or object id, so its
		// "no such group" by name says nothing (GAP-0292).
		return false, errGroupNameNotSearchable
	case unixidentity.IsNotFound(err):
		return false, nil
	default:
		return false, err
	}
}

// errGroupNameNotSearchable is the unknown answer of a host whose group
// service cannot look groups up by name.
var errGroupNameNotSearchable = errors.New("the group service of this host cannot look groups up by name")

// profileGroupQualifiedName returns the name@domain under which a joined
// realm knows a group the host does not know by its short name (SSSD with
// use_fully_qualified_names = True), or "" (GAP-0332).
var profileGroupQualifiedName = func(ctx context.Context, name string) string {
	return unixidentity.QualifiedGroupName(ctx, unixidentity.Default(ctx), name)
}

// accountGroupIDs lists an OS account's group ids: os/user's listing, which
// on macOS is read again with `id -G` when it failed or filled its 256-group
// buffer (an account in more groups, GAP-0201).
var accountGroupIDs = func(account *osuser.User) ([]string, error) {
	return unixidentity.AccountGroupIDs(context.Background(), account)
}
