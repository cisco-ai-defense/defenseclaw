// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisehooks

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On macOS the root enumerator reads the account's Open Directory record,
// the AD binding and the device Platform SSO configuration
// (useridentity.ParseMacOSDirectoryFacts). The per-user Platform SSO login
// UPN is not recorded: it stays claimed until a root-readable source for it
// is confirmed on a live host.

const macOSIdentityToolTimeout = 10 * time.Second

func collectIdentitySpoolRecord(ctx context.Context, account IdentitySpoolAccount, _ []RealmEntry, now time.Time) (IdentitySpoolRecord, error) {
	name := strings.TrimSpace(account.User)
	if name == "" || strings.ContainsAny(name, "/\x00\n") || strings.HasPrefix(name, "-") {
		return IdentitySpoolRecord{}, errors.New("account has no usable name")
	}
	in := useridentity.MacOSDirectoryInputs{
		DSCL:       runMacOSIdentityTool(ctx, "/usr/bin/dscl", "/Search", "-read", "/Users/"+name, "AuthenticationAuthority", "OriginalNodeName"),
		DSConfigAD: runMacOSIdentityTool(ctx, "/usr/sbin/dsconfigad", "-show"),
		AppSSO:     runMacOSIdentityTool(ctx, "/usr/bin/app-sso", "platform", "-s"),
	}
	if in.DSCL == "" {
		return IdentitySpoolRecord{}, errors.New("dscl returned no record")
	}
	return IdentitySpoolRecord{
		Key:       strconv.Itoa(account.UID),
		User:      name,
		UpdatedAt: now,
		Facts:     useridentity.ParseMacOSDirectoryFacts(in, now),
	}, nil
}

func runMacOSIdentityTool(ctx context.Context, tool string, args ...string) string {
	if trustedIdentityTool(tool) == "" {
		return ""
	}
	runCtx, cancel := context.WithTimeout(ctx, macOSIdentityToolTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, tool, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	return boundedOutput(out)
}

func readRealmList(context.Context) []RealmEntry { return nil }
