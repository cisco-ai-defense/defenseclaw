//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os/user"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// profileAccountLocality verifies a fallback account against the local
// account node by uid. Mobile records remain directory accounts on macOS.
func profileAccountLocality(account *user.User) (local, known bool) {
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 0 {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accounts, err := unixidentity.LocalAccounts(ctx)
	if err != nil {
		return false, false
	}
	if held, ok := accounts[account.Username]; !ok || held != uid {
		return false, true
	}
	mobile, err := unixidentity.MobileAccounts(ctx)
	if err != nil {
		return false, false
	}
	return mobile[account.Username] == "", true
}
