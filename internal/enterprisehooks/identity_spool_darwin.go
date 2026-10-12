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
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On macOS the root enumerator reads the account's Open Directory record
// (with the Platform SSO login UPN of AltSecurityIdentities), the AD binding
// and the device Platform SSO configuration
// (useridentity.ParseMacOSDirectoryFacts).

const macOSIdentityToolTimeout = 10 * time.Second

func collectIdentitySpoolRecord(ctx context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
	name := strings.TrimSpace(account.User)
	if name == "" || strings.ContainsAny(name, "/\x00\n") || strings.HasPrefix(name, "-") {
		return IdentitySpoolRecord{}, errors.New("account has no usable name")
	}
	in := useridentity.MacOSDirectoryInputs{
		DSCL:       runMacOSIdentityTool(ctx, "/usr/bin/dscl", "/Search", "-read", "/Users/"+name, "AuthenticationAuthority", "OriginalNodeName", "AltSecurityIdentities"),
		DSConfigAD: runMacOSIdentityTool(ctx, "/usr/sbin/dsconfigad", "-show"),
		AppSSO:     runMacOSIdentityTool(ctx, "/usr/bin/app-sso", "platform", "-s"),
	}
	if in.DSCL == "" {
		return IdentitySpoolRecord{}, errors.New("dscl returned no record")
	}
	facts := useridentity.ParseMacOSDirectoryFacts(in, now)
	return IdentitySpoolRecord{
		Key:           strconv.Itoa(account.UID),
		User:          name,
		UpdatedAt:     now,
		AccountDomain: facts.AccountDomain,
		Facts:         facts,
	}, nil
}

// FlushDirectoryCaches empties Open Directory's caches (dscacheutil
// -flushcache, dsmemberutil flushcache), which only root can do. The
// guardian calls it when its pass resolves accounts again after one that
// resolved none: once the domain controller answers again, Open Directory
// kept answering from the caches it filled during the outage, an account
// without its domain groups, for about 11 more minutes, and the accounts
// stayed on the default profile until an administrator flushed them by hand
// (GAP-0680, GAP-0517). The gateway's next lookup of an account then gets its
// groups from the directory.
func FlushDirectoryCaches(ctx context.Context) error {
	var errs []error
	for _, step := range [][]string{{"/usr/bin/dscacheutil", "-flushcache"}, {"/usr/bin/dsmemberutil", "flushcache"}} {
		if trustedIdentityTool(step[0]) == "" {
			errs = append(errs, fmt.Errorf("%s is not a root-owned tool", step[0]))
			continue
		}
		runCtx, cancel := context.WithTimeout(ctx, macOSIdentityToolTimeout)
		cmd := exec.CommandContext(runCtx, step[0], step[1:]...)
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
		if out, err := cmd.CombinedOutput(); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w: %s", step[0], step[1], err, strings.TrimSpace(boundedOutput(out))))
		}
		cancel()
	}
	return errors.Join(errs...)
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

// trustedIdentityTool returns the first root-owned, non-writable candidate.
func trustedIdentityTool(candidates ...string) string {
	for _, candidate := range candidates {
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() || !rootOwnedChain(candidate) {
			continue
		}
		return candidate
	}
	return ""
}

// boundedOutput trims command output to a sane size.
func boundedOutput(data []byte) string {
	const limit = 64 << 10
	if len(data) > limit {
		data = data[:limit]
	}
	return strings.ToValidUTF8(string(data), "")
}
