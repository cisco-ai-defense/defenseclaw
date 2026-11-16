// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// hookAccountHome reads uid's home through NSS (a root-owned getent), so
// local, SSSD, winbind and LDAP accounts all resolve. Never os/user: in a
// CGO_ENABLED=0 build it reads only /etc/passwd, and for the process's own
// uid that /etc/passwd does not list (a directory account) it answers from
// HOME and USER. With no trusted getent the account is unresolved and the
// hook writes no failure row.
func hookAccountHome(uid int) (string, error) {
	resolver, err := unixidentity.NewNSSResolver(context.Background())
	if err != nil {
		return "", err
	}
	account, err := resolver.LookupUID(uid)
	if err != nil {
		return "", err
	}
	return account.Home, nil
}
