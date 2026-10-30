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
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func identityRefreshPlatformPrivileged() bool { return os.Geteuid() == 0 }

// identityRefreshPlatformResolveUser resolves --user through the account
// database as root (NSS, Open Directory).
func identityRefreshPlatformResolveUser(user string) (string, string, error) {
	return gateway.LookupIdentityRefreshAccount(user)
}

// identityRefreshCommandTimeout bounds one OS cache flush command.
const identityRefreshCommandTimeout = 30 * time.Second

// identityRefreshRun runs one OS cache command; replaceable in tests.
var identityRefreshRun = func(path string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), identityRefreshCommandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, path, args...).Run()
}
