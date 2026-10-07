//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// enterpriseACPHomeForUID names the home of the account with uid, through
// the account database and, on a standalone host, the directory; found is
// false for a uid no account has. Replaceable in tests.
var enterpriseACPHomeForUID = func(uid int) (home string, found bool, err error) {
	account, err := enterprisehooks.StandaloneResolver().LookupUID(uid)
	if unixidentity.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return account.Home, true, nil
}

// enterpriseACPDescribePrincipal names the account of a uid:N principal;
// replaceable in tests.
var enterpriseACPDescribePrincipal = func(principal string) (enterpriseACPAccount, error) {
	kind, value, _ := strings.Cut(principal, ":")
	uid, err := strconv.Atoi(value)
	if kind != "uid" || err != nil {
		return enterpriseACPAccount{}, fmt.Errorf("%s names no account", principal)
	}
	account, err := enterprisehooks.StandaloneResolver().LookupUID(uid)
	if unixidentity.IsNotFound(err) {
		return enterpriseACPAccount{uid: uid, gid: -1}, nil
	}
	if err != nil {
		return enterpriseACPAccount{}, err
	}
	return enterpriseACPAccount{exists: true, name: account.Name, home: account.Home, uid: account.UID, gid: account.GID}, nil
}

// revokeGoneEnterpriseACPEnrollments revokes the managed ACP enrollments of
// accounts that no longer exist, as the enumerator revokes their hook rows:
// a cycle counts definitive misses, and repair (immediate) revokes at once.
// The credential of a deleted account stayed valid for whoever got its uid
// next, and nothing listed it (GAP-0367). The user's copy is not touched:
// its account is gone.
func revokeGoneEnterpriseACPEnrollments(
	ctx context.Context, current *config.Config, resolver unixidentity.Resolver,
	directoryAnswered, immediate bool, state *enterprisehooks.UnixEnumeratorState, stderr io.Writer,
) (revoked, kept []string) {
	if current == nil || !managed.IsManagedEnterprise(current.DeploymentMode) || strings.TrimSpace(current.DataDir) == "" {
		return nil, nil
	}
	var enrollments []acp.EnterpriseEnrollment
	if err := withEnterpriseACPServiceOwner(current.DataDir, func() error {
		var listErr error
		enrollments, _, listErr = acp.ListEnterpriseEnrollments(current.DataDir)
		return listErr
	}); err != nil {
		fmt.Fprintf(stderr, "[acp-enrollments] warn: could not read the managed ACP enrollments: %v\n", err)
		return nil, nil
	}
	principals := make([]string, 0, len(enrollments))
	for _, enrollment := range enrollments {
		principals = append(principals, enrollment.Principal)
	}
	gone, kept := enterprisehooks.GoneUnixACPPrincipals(ctx, enterprisehooks.UnixGoneACPOptions{
		Principals: principals, Resolver: resolver,
		LocalAccounts:       func() (map[string]int, error) { return enterpriseHooksEnumerateLocalAccounts(ctx) },
		DirectoryConfigured: enterpriseHooksEnumerateDirectoryConfigured,
		DirectoryAnswered:   directoryAnswered, State: state, Immediate: immediate,
		Logger: func(subject, reason string) {
			fmt.Fprintf(stderr, "[acp-enrollments] %s: %s\n", subject, reason)
		},
	})
	goneSet := map[string]bool{}
	for _, principal := range gone {
		goneSet[principal] = true
	}
	failed := map[string]bool{}
	for _, enrollment := range enrollments {
		if !goneSet[enrollment.Principal] {
			continue
		}
		pair := fmt.Sprintf("%s %s/%s/%s", enrollment.Principal, enrollment.ClientID, enrollment.AgentID, enrollment.Profile)
		if err := withEnterpriseACPServiceOwner(current.DataDir, func() error {
			return acp.RemoveEnterpriseCredential(current.DataDir, enrollment.Principal, enrollment.ClientID, enrollment.AgentID, enrollment.Profile)
		}); err != nil {
			failed[enrollment.Principal] = true
			kept = append(kept, fmt.Sprintf("%s: the account no longer exists, but its ACP enrollment could not be revoked: %v", pair, err))
			continue
		}
		fmt.Fprintf(stderr, "[acp-enrollments] %s: the account no longer exists; revoked its ACP enrollment\n", pair)
		revoked = append(revoked, pair)
	}
	for _, principal := range gone {
		if !failed[principal] {
			enterprisehooks.ForgetUnixACPPrincipal(state, principal)
		}
	}
	return revoked, kept
}
