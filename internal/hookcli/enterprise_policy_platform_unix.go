//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookcli

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// standaloneEnterprisePolicyLayout returns the standalone layout and, on
// Windows only, the trusted machine roots.
func StandaloneEnterprisePolicyLayout() (managed.StandaloneLayout, string, string, error) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	return layout, "", "", err
}

// hookForeignGuardAccountHome returns the calling account's home from the
// system account database, never from the agent's environment: the
// guardian installs DefenseClaw's per-user registrations there. Release
// builds have no cgo, so os/user sees only /etc/passwd; a directory
// (LDAP, SSSD) account resolves through the same trusted NSS lookup the
// enumerator uses. Empty when neither resolves. Replaceable in tests.
var HookForeignGuardAccountHome = func() string {
	uid := os.Getuid()
	if account, err := user.LookupId(strconv.Itoa(uid)); err == nil && filepath.IsAbs(account.HomeDir) {
		return filepath.Clean(account.HomeDir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if account, err := unixidentity.Default(ctx).LookupUID(uid); err == nil && filepath.IsAbs(account.Home) {
		return filepath.Clean(account.Home)
	}
	return ""
}

// hookForeignGuardEnvHomes lists the homes the agent's environment names
// ($HOME as inherited from the agent), which it may read hook config from.
// Replaceable in tests.
var HookForeignGuardEnvHomes = func() []string {
	return []string{os.Getenv("HOME")}
}
