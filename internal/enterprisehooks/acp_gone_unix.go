//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// UnixGoneACPOptions configures GoneUnixACPPrincipals; the account fields
// mean what they mean in UnixEnumerateOptions.
type UnixGoneACPOptions struct {
	// Principals are the principals of the managed ACP enrollments; only
	// uid:N principals name an account.
	Principals          []string
	Resolver            unixidentity.Resolver
	LocalAccounts       func() (map[string]int, error)
	DirectoryConfigured func() bool
	// DirectoryAnswered is set when a directory account resolved in the
	// same cycle.
	DirectoryAnswered bool
	State             *UnixEnumeratorState
	// Immediate is the repair pass: an account the local database shows
	// gone is revoked at once instead of after UnixRevokeAfterMisses cycles.
	Immediate bool
	Logger    EnumerationLogger
}

// GoneUnixACPPrincipals returns the uid principals of managed ACP
// enrollments whose account no longer exists, by the hook enumerator's rule:
// UnixRevokeAfterMisses consecutive definitive "no such user" answers (one in
// a repair pass), and never for a failed lookup or an answer an unreachable
// directory could also give. The credential of a deleted account stayed
// valid for whoever got its uid next (GAP-0367). kept explains the
// principals that did not resolve and stay.
func GoneUnixACPPrincipals(ctx context.Context, opts UnixGoneACPOptions) (gone, kept []string) {
	if opts.Resolver == nil || opts.State == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.State.ACPMisses == nil {
		opts.State.ACPMisses = map[string]int{}
	}
	if opts.State.ACPSources == nil {
		opts.State.ACPSources = map[string]string{}
	}
	sources := newUnixAccountSources(opts.LocalAccounts, opts.DirectoryConfigured, nil, opts.Logger)
	localUIDs := map[int]bool{}
	for _, uid := range sources.local {
		localUIDs[uid] = true
	}
	seen := map[string]bool{}
	for _, principal := range opts.Principals {
		kind, value, _ := strings.Cut(principal, ":")
		uid, err := strconv.Atoi(value)
		if kind != "uid" || err != nil || uid < 0 || seen[principal] || ctx.Err() != nil {
			continue
		}
		seen[principal] = true
		account, err := opts.Resolver.LookupUID(uid)
		switch {
		case err == nil && !(sources.localKnown && opts.State.ACPSources[principal] == unixSourceFiles && !localUIDs[uid]):
			delete(opts.State.ACPMisses, principal)
			if sources.localKnown {
				source := unixSourceDirectory
				if localUIDs[account.UID] {
					source = unixSourceFiles
				}
				opts.State.ACPSources[principal] = source
			}
			continue
		case err != nil && !unixidentity.IsNotFound(err):
			kept = append(kept, fmt.Sprintf("%s: the account lookup failed, so its ACP enrollments stay", principal))
			continue
		}
		// Not found, or a local account the local database no longer lists
		// (a cache can answer for minutes after the record is deleted).
		if !sources.localKnown {
			kept = append(kept, fmt.Sprintf("%s: account not found, but the local account database could not be read, so its ACP enrollments stay", principal))
			continue
		}
		if localUIDs[uid] {
			kept = append(kept, fmt.Sprintf("%s: account not found, but the local account database still lists it, so its ACP enrollments stay", principal))
			continue
		}
		if sources.directoryConfigured && opts.State.ACPSources[principal] != unixSourceFiles && !opts.DirectoryAnswered {
			kept = append(kept, fmt.Sprintf("%s: account not found, but the directory could not be confirmed reachable, so its ACP enrollments stay", principal))
			continue
		}
		opts.State.ACPMisses[principal]++
		if !opts.Immediate && opts.State.ACPMisses[principal] < UnixRevokeAfterMisses {
			logfSafely(opts.Logger, principal, fmt.Sprintf("account not found (%d/%d); keeping its ACP enrollments for now",
				opts.State.ACPMisses[principal], UnixRevokeAfterMisses))
			continue
		}
		gone = append(gone, principal)
	}
	for principal := range opts.State.ACPMisses {
		if !seen[principal] {
			delete(opts.State.ACPMisses, principal)
		}
	}
	for principal := range opts.State.ACPSources {
		if !seen[principal] {
			delete(opts.State.ACPSources, principal)
		}
	}
	sort.Strings(gone)
	return gone, kept
}

// ForgetUnixACPPrincipal drops the miss count and source of a revoked
// principal.
func ForgetUnixACPPrincipal(state *UnixEnumeratorState, principal string) {
	if state != nil {
		delete(state.ACPMisses, principal)
		delete(state.ACPSources, principal)
	}
}
