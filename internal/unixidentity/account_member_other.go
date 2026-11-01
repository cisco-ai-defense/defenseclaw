//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os/user"
	"slices"
	"strconv"
)

// platformAccountInGroup reads the whole list: NSS answers it in one call.
func platformAccountInGroup(ctx context.Context, account *user.User, gid int) (bool, error) {
	ids, err := AccountGroupIDs(ctx, account)
	if err != nil {
		return false, err
	}
	return slices.Contains(ids, strconv.Itoa(gid)), nil
}
