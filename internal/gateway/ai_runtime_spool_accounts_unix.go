// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// aiRuntimeSpoolAccountsMax bounds the accounts one runtime poll reads.
const aiRuntimeSpoolAccountsMax = 4096

// aiRuntimeSpoolAccounts is the enrolled-account table of a standalone
// managed Linux or macOS gateway for the runtime owner lookup: one entry per
// trusted identity record of the hook guardian, which keeps one for each
// account the enumerator found eligible (eligible-accounts.json is root-only;
// the records are what the gateway's service account may read). The home is
// the one the account database names now; a record whose uid now belongs to
// another account name is left out, so a finding is never attributed to
// another account (p0-round GAP-1389). Empty on a per-user gateway (no
// spool). A variable for tests.
var aiRuntimeSpoolAccounts = func() []sensor.Account {
	dir := currentIdentitySpoolDir()
	if dir == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolver := unixidentity.Default(ctx)
	var accounts []sensor.Account
	enterprisehooks.WalkIdentitySpoolRecords(dir, validateManagedGuardianAuthorization, func(record enterprisehooks.IdentitySpoolRecord) bool {
		if ctx.Err() != nil {
			return false
		}
		if account, ok := spoolRecordAccount(resolver, record); ok {
			accounts = append(accounts, account)
		}
		return len(accounts) < aiRuntimeSpoolAccountsMax
	})
	return accounts
}

// spoolRecordAccount is the account of one identity record: its uid's
// account and home as the account database names them, only while that
// account still has the name the record names.
func spoolRecordAccount(resolver unixidentity.Resolver, record enterprisehooks.IdentitySpoolRecord) (sensor.Account, bool) {
	uid, err := strconv.Atoi(record.Key)
	if err != nil || uid <= 0 {
		return sensor.Account{}, false
	}
	account, err := resolver.LookupUID(uid)
	if err != nil {
		return sensor.Account{}, false
	}
	name, home := strings.TrimSpace(account.Name), filepath.Clean(strings.TrimSpace(account.Home))
	if name == "" || !filepath.IsAbs(home) || home == "/" {
		return sensor.Account{}, false
	}
	if user := strings.TrimSpace(record.User); user != "" && user != name {
		return sensor.Account{}, false
	}
	return sensor.Account{Name: name, Home: home}, true
}
