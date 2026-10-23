//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"os"
	"os/user"
	"strconv"
)

// platformAccountGroupIDs binds os/user's group candidates to the uid. Local
// accounts use local group records; directory accounts use the verified NSS
// owner of the uid. The original name-based candidate list is not reused.
func platformAccountGroupIDs(ctx context.Context, _ commandRunner, account *user.User, _ []string, _ error, _ []string) ([]string, error) {
	uid, err := parseID(account.Uid, "uid")
	if err != nil {
		return nil, err
	}
	primary, err := parseID(account.Gid, "gid")
	if err != nil {
		return nil, err
	}
	local, err := LocalAccounts(ctx)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var ids []int
	if held, ok := local[account.Username]; ok && held == uid {
		owned := Account{Name: account.Username, UID: uid, GID: primary}
		if resolver, resolverErr := NewNSSResolver(ctx); resolverErr == nil {
			ids, _, _, err = resolver.localAccountGroupsWithDirectory(owned)
		} else {
			ids, _, err = localAccountGroups(owned)
		}
	} else {
		var resolver *NSSResolver
		resolver, err = NewNSSResolver(ctx)
		if err == nil {
			var owned Account
			owned, err = resolver.LookupUID(uid)
			if err == nil {
				ids, err = resolver.GroupIDs(owned)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, strconv.Itoa(id))
	}
	return out, nil
}
