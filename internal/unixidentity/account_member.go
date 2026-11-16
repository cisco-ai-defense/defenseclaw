//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os/user"
)

// AccountInGroup reports whether AccountGroupIDs lists gid for account. On
// macOS it confirms that one group with Open Directory instead of every group
// the account is in: the macOS admin-group check of a discovered agent path
// ran one dsmemberutil per group of the owner (about 175 on an Active
// Directory Mac) for each path, about 1.5 s of every hook guardian pass, and
// put the repair of a rewritten Hermes hooks block past its 3 s bound
// (GAP-1825, r103 GAP-0045).
func AccountInGroup(ctx context.Context, account *user.User, gid int) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return platformAccountInGroup(ctx, account, gid)
}
