// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// peerDirectoryLookupTimeout bounds one background resolution (the getent
// calls), well beyond the hot-path budget a waiting request uses. A cold SSSD
// names a group in about 30 ms, one lookup at a time, so the bound grows with
// the largest membership DefenseClaw names (unixidentity.DirectoryLookupBudget,
// GAP-1247); a lookup that still runs out fails as a whole and is retried
// (GAP-0138). `guardrail profile explain` starts this lookup through the
// cache and waits for it at most identityExplainWait; a lookup still running
// then is cached when it ends.
var peerDirectoryLookupTimeout = unixidentity.DirectoryLookupBudget()

// peerIncarnationTimeout bounds the SID lookup that names which directory
// account holds a uid (managedHookPeerAccountIncarnation).
const peerIncarnationTimeout = 10 * time.Second

// managedHookPeerAccountIncarnation names which directory account holds the
// uid of account (unixidentity.AccountIncarnation): the SID SSSD holds for
// it. false when it cannot tell. Tests replace it.
var managedHookPeerAccountIncarnation = func(account unixidentity.Account) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), peerIncarnationTimeout)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return "", false
	}
	return resolver.AccountIncarnation(account.UID, account.Name)
}

// holderSpoolRecord is the guardian's current record of the uid key when it
// was resolved for account, the account that holds the uid now: its name and
// its account incarnation (unixidentity.AccountIncarnation) are the
// account's now. A uid handed from one domain's alice to another domain's
// alice keeps its key and its name, and laid over the second account's
// facts the first one's record gave it the first one's UPN, principal and
// domain, and the profile assigned to them, until the guardian's next pass
// (review of GAP-0551). A record that names no incarnation (an older
// guardian's), or an incarnation that cannot be told now, proves nothing:
// the facts are then the gateway's own, as without a guardian, and the
// cache looks them up again soon (awaitingSpoolUPN).
// A record of another SID is an error (readIdentitySpoolFactsForAccount): the
// account's own facts are then unproven.
func holderSpoolRecord(key string, account unixidentity.Account, accountSID string, now time.Time) (enterprisehooks.IdentitySpoolRecord, bool, error) {
	record, ok, err := readIdentitySpoolFactsForAccount(key, account.Name, accountSID, now)
	if err != nil {
		return enterprisehooks.IdentitySpoolRecord{}, false, err
	}
	if !ok || record.AccountIncarnation == "" {
		return enterprisehooks.IdentitySpoolRecord{}, false, nil
	}
	if incarnation, known := managedHookPeerAccountIncarnation(account); !known || incarnation != record.AccountIncarnation {
		return enterprisehooks.IdentitySpoolRecord{}, false, nil
	}
	return record, true, nil
}

// peerNSSFacts resolves a verified uid's facts (resolveNSSPeerFacts);
// tests replace it.
var peerNSSFacts = resolveNSSPeerFacts

// resolvePeerDirectoryFacts is the peer directory cache's lookup
// (peerNSSFacts). A lookup that fails leaves the account and its groups
// unproven, and the profile matcher selects the strictest profile that
// could apply (resolveIdentity); nothing is kept from it.
func resolvePeerDirectoryFacts(key string) (useridentity.DirectoryFacts, error) {
	return peerNSSFacts(key)
}

// resolveNSSPeerFacts resolves a verified uid's facts through NSS and
// merges the guardian's identity spool record for it.
func resolveNSSPeerFacts(key string) (useridentity.DirectoryFacts, error) {
	uid, err := strconv.Atoi(key)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), peerDirectoryLookupTimeout)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	account, err := resolver.LookupUID(uid)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	facts, err := resolver.DirectoryFactsForUID(uid, now)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	facts.SpoolSeenAt = identitySpoolSeenAt(key, now)
	record, ok, err := holderSpoolRecord(key, account, facts.AccountSID, now)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	var spool *enterprisehooks.IdentitySpoolRecord
	if ok {
		spool = &record
	}
	if err := sssdGroupsUnavailable(spool, facts, directoryUnreachable, now); err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	if ok {
		facts = mergeSpoolFacts(facts, record)
	}
	noteGroupDomains(facts.Groups)
	return facts, nil
}
