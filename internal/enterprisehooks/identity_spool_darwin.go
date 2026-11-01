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
	"os/exec"
	"strings"
	"time"
)

// The macOS identity facts are collected by collectMacOSIdentityRecord
// (identity_spool_macos.go) with the root-owned tools below.

// bindIdentitySpoolUPN binds nothing on macOS: the guardian keeps no
// InfoPipe UPN there (KeepVerifiedInfoPipeUPN needs an SSSD domain).
func bindIdentitySpoolUPN(context.Context, int, string, string, bool) UPNBinding {
	return UPNBindingUnknown
}

func collectIdentitySpoolRecord(ctx context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
	return collectMacOSIdentityRecord(ctx, runMacOSIdentityTool, account, now)
}

// DirectoryCachesHoldOutageAnswers: Open Directory keeps serving the answers
// it gave while the domain controller was away, so the guardian watches for
// them (DirectoryCachesStale).
const DirectoryCachesHoldOutageAnswers = true

// DirectoryAwayWithoutAnswer is false on a Mac: its own check cannot tell an
// outage from a firewall in front of the LDAP port, so a domain whose
// domain controllers never answered since the guardian started is not away.
const DirectoryAwayWithoutAnswer = false

// DirectoryAnswers reports whether a domain controller of the Active
// Directory domain answers (DomainControllerAnswers).
func DirectoryAnswers(ctx context.Context, domain string) bool {
	return DomainControllerAnswers(ctx, domain)
}

// directoryReachDomain is the domain the guardian checks for an account's
// record: its Active Directory domain.
func directoryReachDomain(record IdentitySpoolRecord) string {
	return activeDirectoryDomain(record)
}

// FlushDirectoryCaches empties Open Directory's caches (dscacheutil
// -flushcache, dsmemberutil flushcache), which only root can do. The
// guardian calls it when a domain controller answers again while Open
// Directory still lists an Active Directory account without its domain
// groups: it kept answering from the caches it filled during the outage for
// 11 to 19 more minutes, and the accounts stayed on the default profile until
// an administrator flushed them by hand (#1197, GAP-0680, GAP-0517). The
// gateway's next lookup of an account then gets its groups from the
// directory.
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

func runMacOSIdentityTool(ctx context.Context, timeout time.Duration, tool string, args ...string) string {
	if trustedIdentityTool(tool) == "" {
		return ""
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, tool, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	return boundedOutput(out)
}
