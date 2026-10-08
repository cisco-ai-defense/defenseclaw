//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GroupNameLookupDefinitive is always true on macOS: Open Directory looks
// groups up by name.
func GroupNameLookupDefinitive() bool { return true }

// QualifiedGroupName has nothing to offer on macOS, whose group names carry
// no domain.
func QualifiedGroupName(context.Context, Resolver, string) string { return "" }
func QualifiedUserName(context.Context, Resolver, string) string  { return "" }

const darwinDSCL = "/usr/bin/dscl"

// DefaultUIDRange is the interactive-account uid range. macOS local
// accounts start at 501; directory accounts often use large uids.
func DefaultUIDRange() (int, int) { return 501, 2147483646 }

// Default returns the platform resolver. macOS os/user already resolves
// through Open Directory, so it is authoritative for lookups.
func Default(ctx context.Context) Resolver {
	return NewCachingResolver(NewOSUserResolver(ctx))
}

// DirectoryFactsFunc is nil on macOS: Open Directory answers each spelling
// of an account with the account itself.
func DirectoryFactsFunc(context.Context) func(uid int) (useridentity.DirectoryFacts, bool) {
	return nil
}

// platformLocalAccounts lists the local directory node's accounts.
func platformLocalAccounts(ctx context.Context) (map[string]int, error) {
	if err := validateTrustedTool(darwinDSCL); err != nil {
		return nil, err
	}
	result, err := runTrustedCommand(ctx, darwinDSCL, []string{".", "-list", "/Users", "UniqueID"})
	if err != nil {
		return nil, err
	}
	if result.exitCode != 0 {
		return nil, fmt.Errorf("unixidentity: dscl exited %d", result.exitCode)
	}
	return parseDSCLLocalAccounts(string(result.stdout)), nil
}

// platformDirectoryConfigured reads the Open Directory search policy: a
// Mac whose search path lists only local nodes answers every lookup from
// its local directory, so "no such user" is definitive for every account,
// as it is on a Linux host whose nsswitch.conf lists only files. A Mac
// bound to a directory, or one whose policy cannot be read, may reach a
// directory.
func platformDirectoryConfigured() bool {
	if err := validateTrustedTool(darwinDSCL); err != nil {
		return true
	}
	result, err := runTrustedCommand(context.Background(), darwinDSCL,
		[]string{"-plist", "/Search", "-read", "/", "SearchPath", "CSPSearchPath", "NSPSearchPath"})
	if err != nil || result.exitCode != 0 {
		return true
	}
	return ParseDSCLSearchPolicyDirectoryConfigured(result.stdout)
}

// platformLocalUserLister lists local accounts with `dscl . -list /Users
// UniqueID`, then resolves each through os/user for home and group data.
func platformLocalUserLister(ctx context.Context, runner commandRunner) ([]Account, error) {
	if err := validateTrustedTool(darwinDSCL); err != nil {
		return nil, err
	}
	result, err := runner(ctx, darwinDSCL, []string{".", "-list", "/Users", "UniqueID"})
	if err != nil {
		return nil, err
	}
	if result.exitCode != 0 {
		return nil, fmt.Errorf("unixidentity: dscl exited %d", result.exitCode)
	}
	return parseDSCLUniqueIDs(string(result.stdout), NewOSUserResolver(ctx)), nil
}

// parseDSCLUniqueIDs parses "name uid" rows and resolves each account.
// Unresolvable or malformed rows are skipped rather than failing the list.
func parseDSCLUniqueIDs(output string, resolver *OSUserResolver) []Account {
	var accounts []Account
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if strings.HasPrefix(fields[0], "_") {
			// Underscore accounts are daemon identities, never people.
			continue
		}
		uid, err := parseID(fields[1], "uid")
		if err != nil {
			continue
		}
		account, err := resolver.LookupUID(uid)
		if err != nil || account.Name != fields[0] {
			continue
		}
		accounts = append(accounts, account)
	}
	return accounts
}
