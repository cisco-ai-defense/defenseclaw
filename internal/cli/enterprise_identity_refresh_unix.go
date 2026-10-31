// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func identityRefreshPlatformPrivileged() bool { return os.Geteuid() == 0 }

// identityRefreshPlatformResolveUser resolves --user through the account
// database as root (NSS, Open Directory).
func identityRefreshPlatformResolveUser(user string) (string, string, error) {
	id, name, err := gateway.LookupIdentityRefreshAccount(user)
	if err != nil {
		return "", "", fmt.Errorf("no account %q on this host (%v); --user takes the account name as id prints it, user@domain or the uid", user, err)
	}
	return id, name, nil
}

// identityRefreshCommandTimeout bounds one OS cache flush command.
const identityRefreshCommandTimeout = 30 * time.Second
