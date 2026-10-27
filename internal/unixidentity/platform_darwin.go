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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GroupNameLookupDefinitive reports whether Open Directory's "no such group"
// for a name is definitive: it looks groups up by name, but while the node of
// a bound Active Directory domain is offline it does not know that domain's
// groups, and an assignment group was reported as renamed or deleted in the
// directory (GAP-0496).
func GroupNameLookupDefinitive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return !OpenDirectoryOffline(ctx)
}

// GroupDirectoryUsesWinbind is false on macOS: Open Directory answers for a
// bound Active Directory domain.
func GroupDirectoryUsesWinbind() bool { return false }

// QualifiedGroupName has nothing to offer on macOS, whose group names carry
// no domain.
func QualifiedGroupName(context.Context, Resolver, string) string { return "" }
func QualifiedUserName(context.Context, Resolver, string) string  { return "" }

// SameNameAccounts finds no twins on macOS: Open Directory resolves a short
// name to one account.
func SameNameAccounts(context.Context, Resolver, Account) ([]Account, error) { return nil, nil }

// ConfirmLocalAccount has nothing to order on macOS: Open Directory's
// local node holds the accounts os/user names.
func ConfirmLocalAccount(Resolver, int, string) error { return nil }

const (
	darwinDSCL   = "/usr/bin/dscl"
	darwinODUtil = "/usr/bin/odutil"
)

// platformOpenDirectoryNodeStates runs `odutil show nodenames`, which lists
// each Open Directory node with its state; any user may run it.
func platformOpenDirectoryNodeStates(ctx context.Context) (string, error) {
	if err := validateTrustedTool(darwinODUtil); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	result, err := runTrustedCommand(ctx, darwinODUtil, []string{"show", "nodenames"})
	if err != nil {
		return "", err
	}
	if result.exitCode != 0 {
		return "", fmt.Errorf("unixidentity: odutil exited %d", result.exitCode)
	}
	return string(result.stdout), nil
}

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

// platformLocalAccountRecords lists the local node's accounts with the
// attributes that change when an account is replaced or moved: uid,
// GeneratedUID, home and primary group. Any account may list them.
// platformLocalDatabaseAccounts has no other local account database here.
func platformLocalDatabaseAccounts(ctx context.Context) (map[string]int, error) {
	return platformLocalAccounts(ctx)
}

func platformLocalAccountRecords(ctx context.Context) (map[string]LocalAccountRecord, error) {
	if err := validateTrustedTool(darwinDSCL); err != nil {
		return nil, err
	}
	attributes := []string{"UniqueID", "GeneratedUID", "NFSHomeDirectory", "PrimaryGroupID"}
	listed := make([]map[string]string, len(attributes))
	for i, attribute := range attributes {
		result, err := runTrustedCommand(ctx, darwinDSCL, []string{".", "-list", "/Users", attribute})
		if err != nil {
			return nil, err
		}
		if result.exitCode != 0 {
			return nil, fmt.Errorf("unixidentity: dscl exited %d", result.exitCode)
		}
		listed[i] = parseDSCLAttribute(string(result.stdout))
	}
	return mergeDSCLAccountRecords(listed[0], listed[1], listed[2], listed[3]), nil
}

// parseDSCLRead parses `dscl . -read /Users/<name> <attributes>` output
// ("Attribute: value", or "Attribute:" with the value on the next,
// indented line) into attribute -> value.
func parseDSCLRead(output string) map[string]string {
	out := map[string]string{}
	pending := ""
	for _, line := range strings.Split(output, "\n") {
		if pending != "" && strings.HasPrefix(line, " ") {
			out[pending] = strings.TrimSpace(line)
			pending = ""
			continue
		}
		pending = ""
		key, value, ok := strings.Cut(line, ":")
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			continue
		}
		if value = strings.TrimSpace(value); value == "" {
			pending = key
			continue
		}
		out[key] = value
	}
	return out
}

// platformLocalAccountRecord reads one local account's record.
func platformLocalAccountRecord(ctx context.Context, name string) (LocalAccountRecord, bool, error) {
	if err := validateTrustedTool(darwinDSCL); err != nil {
		return LocalAccountRecord{}, false, err
	}
	result, err := runTrustedCommand(ctx, darwinDSCL, []string{".", "-read", "/Users/" + name,
		"UniqueID", "GeneratedUID", "NFSHomeDirectory", "PrimaryGroupID"})
	if err != nil {
		return LocalAccountRecord{}, false, err
	}
	if result.exitCode != 0 {
		// Also a record the node does not hold: the uid lookup tells that.
		return LocalAccountRecord{}, false, fmt.Errorf("unixidentity: dscl exited %d", result.exitCode)
	}
	read := parseDSCLRead(string(result.stdout))
	uid, err := parseSignedDSCLID(read["UniqueID"])
	if err != nil {
		return LocalAccountRecord{}, false, err
	}
	return LocalAccountRecord{UID: uid, RecordID: read["GeneratedUID"], Home: read["NFSHomeDirectory"], PrimaryGID: read["PrimaryGroupID"]}, true, nil
}

// platformMobileAccounts lists the local node's mobile accounts with the
// directory node each came from.
func platformMobileAccounts(ctx context.Context) (map[string]string, error) {
	if err := validateTrustedTool(darwinDSCL); err != nil {
		return nil, err
	}
	result, err := runTrustedCommand(ctx, darwinDSCL, []string{".", "-list", "/Users", "OriginalNodeName"})
	if err != nil {
		return nil, err
	}
	if result.exitCode != 0 {
		return nil, fmt.Errorf("unixidentity: dscl exited %d", result.exitCode)
	}
	return parseDSCLOriginalNodes(string(result.stdout)), nil
}

// platformSSOLinkedAccounts lists the local node's accounts registered with
// Platform SSO.
func platformSSOLinkedAccounts(ctx context.Context) (map[string]bool, error) {
	if err := validateTrustedTool(darwinDSCL); err != nil {
		return nil, err
	}
	result, err := runTrustedCommand(ctx, darwinDSCL, []string{".", "-list", "/Users", "AltSecurityIdentities"})
	if err != nil {
		return nil, err
	}
	if result.exitCode != 0 {
		return nil, fmt.Errorf("unixidentity: dscl exited %d", result.exitCode)
	}
	return parseDSCLPlatformSSOAccounts(string(result.stdout)), nil
}

// platformLocalGroups lists the local directory node's groups.
func platformLocalGroups(ctx context.Context) (map[string]int, error) {
	if err := validateTrustedTool(darwinDSCL); err != nil {
		return nil, err
	}
	result, err := runTrustedCommand(ctx, darwinDSCL, []string{".", "-list", "/Groups", "PrimaryGroupID"})
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
