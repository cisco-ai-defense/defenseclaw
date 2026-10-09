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

// enterpriseACPUIDMayBeHidden reports a host with a directory: a lookup that
// finds no account with the uid is then not proof that it was deleted, since
// a directory that does not answer gives the same answer (GAP-0838).
func enterpriseACPUIDMayBeHidden() bool { return enterpriseHooksEnumerateDirectoryConfigured() }

// settleEnterpriseACPListedAccounts keeps "deleted" only where a lookup that
// found no account is definitive, as the enumerator decides before it
// revokes: no local account has the uid, and the directory, if this host has
// one, answered for another account of the listing. With the directory
// unreachable every directory account read "account deleted", the signal
// to revoke by hand (GAP-0838).
func settleEnterpriseACPListedAccounts(ctx context.Context, rows []enterpriseACPListedEnrollment) {
	missing := false
	for _, row := range rows {
		missing = missing || row.Account == "deleted"
	}
	if !missing {
		return
	}
	local, localErr := enterpriseHooksEnumerateLocalAccounts(ctx)
	localUIDs := map[int]bool{}
	for _, uid := range local {
		localUIDs[uid] = true
	}
	directoryAnswered := false
	for _, row := range rows {
		if uid, ok := enterpriseACPPrincipalUID(row.Principal); ok && row.Account == "present" && !localUIDs[uid] {
			directoryAnswered = true
		}
	}
	directory := enterpriseHooksEnumerateDirectoryConfigured()
	for i := range rows {
		uid, ok := enterpriseACPPrincipalUID(rows[i].Principal)
		if rows[i].Account != "deleted" || !ok {
			continue
		}
		note := ""
		switch {
		case localErr != nil || localUIDs[uid]:
			note = "the account does not resolve, but the local account database could not be read or still lists it; nothing was revoked"
		case directory && !directoryAnswered:
			note = "the account does not resolve and the directory could not be confirmed reachable, so DefenseClaw cannot tell " +
				"whether it was deleted; nothing is revoked while the directory does not answer"
		default:
			continue
		}
		rows[i].Account, rows[i].TokenCopy, rows[i].Setup, rows[i].Note = "unresolved", "unknown", "unknown", note
	}
}

// enterpriseACPPrincipalUID reads the uid of a uid:N principal.
func enterpriseACPPrincipalUID(principal string) (int, bool) {
	kind, value, _ := strings.Cut(principal, ":")
	uid, err := strconv.Atoi(value)
	return uid, kind == "uid" && err == nil && uid >= 0
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
			line := fmt.Sprintf("%s: the account no longer exists, but its ACP enrollment could not be revoked: %v", pair, err)
			// The timer cycle drops kept; a failed revoke left no line at all
			// (GAP-0697).
			fmt.Fprintf(stderr, "[acp-enrollments] warn: %s\n", line)
			kept = append(kept, line)
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
