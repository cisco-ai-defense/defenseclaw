// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
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

// managedPeerIncarnation asks the current NSS owner for its incarnation. A
// current local guardian record may supply root's proof of an SSSD miss;
// NSS still checks whether SSSD now holds the uid.
func managedPeerIncarnation(account unixidentity.Account, recordedUnshared bool) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), peerIncarnationTimeout)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return "", false
	}
	if recordedUnshared {
		return resolver.AccountIncarnationForRecordedUnsharedUID(account.UID, account.Name)
	}
	return resolver.AccountIncarnation(account.UID, account.Name)
}

// Tests replace these boundaries for the account holding a verified uid.
var managedHookPeerAccountIncarnation = func(account unixidentity.Account) (string, bool) {
	return managedPeerIncarnation(account, false)
}

var managedHookPeerRecordedAccountIncarnation = func(account unixidentity.Account) (string, bool) {
	return managedPeerIncarnation(account, true)
}

// holderSpoolRecord is the guardian's current record of the uid key when it
// was resolved for account, the account that holds the uid now: its name and
// its account incarnation (unixidentity.AccountIncarnation) are the
// account's now. A uid handed from one domain's alice to another domain's
// alice keeps its key and its name, and laid over the second account's
// facts the first one's record gave it the first one's UPN, principal and
// domain, and the profile assigned to them, until the guardian's next pass
// (review of GAP-0551). A record that names no incarnation (an older
// guardian's), or an incarnation that cannot be told now even with the
// guardian's recorded SSSD miss, proves nothing:
// the facts are then the gateway's own, as without a guardian, and the
// cache looks them up again soon (awaitingSpoolUPN).
// A record of another SID is an error (readIdentitySpoolFactsForAccount): the
// account's own facts are then unproven.
func holderSpoolRecord(key string, account unixidentity.Account, accountSID string, now time.Time) (enterprisehooks.IdentitySpoolRecord, bool, error) {
	return holderSpoolRecordFor(key, account, accountSID, now, managedHookPeerAccountIncarnation)
}

// holderSpoolRecordFor is holderSpoolRecord with the gateway's own account
// incarnation lookup ownIncarnation.
func holderSpoolRecordFor(key string, account unixidentity.Account, accountSID string, now time.Time,
	ownIncarnation func(unixidentity.Account) (string, bool)) (enterprisehooks.IdentitySpoolRecord, bool, error) {
	record, ok, err := readIdentitySpoolFactsForAccount(key, account.Name, accountSID, now)
	if err != nil {
		return enterprisehooks.IdentitySpoolRecord{}, false, err
	}
	if !ok || record.AccountIncarnation == "" {
		return enterprisehooks.IdentitySpoolRecord{}, false, nil
	}
	incarnation, known := ownIncarnation(account)
	if !known && recordedLocalAccountIncarnation(record) {
		incarnation, known = managedHookPeerRecordedAccountIncarnation(account)
	}
	if !known || incarnation != record.AccountIncarnation {
		return enterprisehooks.IdentitySpoolRecord{}, false, nil
	}
	return record, true, nil
}

// recordedLocalAccountIncarnation reports whether record, the guardian's
// identity record of a uid, is of an account of a local account database
// without a SID: /etc/passwd ("files") or another local NSS service, such as
// systemd-userdb ("nss:systemd") or nss-altfiles. Only root can show that
// SSSD, asked before such a service, holds no account of the uid, so the
// non-root gateway takes the guardian's recorded proof of that miss
// (AccountIncarnationForRecordedUnsharedUID) for these accounts. Taking it
// for "files" only left a systemd-userdb account behind sss with no facts and
// no account incarnation: its hooks were decided without them, and an
// account deleted and created again under the same name, uid and home path
// kept the earlier holder's agent identity (rel-1-0-5 GAP-0022).
func recordedLocalAccountIncarnation(record enterprisehooks.IdentitySpoolRecord) bool {
	incarnation := record.AccountIncarnation
	return record.AccountSID == "" && record.Facts.Source == useridentity.SourceNSSFiles &&
		(incarnation == "files" || strings.HasPrefix(incarnation, "nss:"))
}

// managedHookPeerGuardianIncarnation is the account incarnation of account
// that the guardian's current identity record of its uid proves when the
// gateway cannot tell it alone (holderSpoolRecord): a local account behind
// SSSD in the passwd line. false without such a record. It is asked only
// after the gateway's own lookup (managedHookPeerAccountIncarnation) did not
// name the incarnation (peerAccountIncarnation), so it does not ask that
// lookup again: each recheck of such an account, every second on the hook
// path, made three NSS incarnation lookups instead of two (RVI1-1). Tests
// replace it.
var managedHookPeerGuardianIncarnation = func(account unixidentity.Account) (string, bool) {
	record, ok, err := holderSpoolRecordFor(strconv.Itoa(account.UID), account, "", time.Now().UTC(),
		func(unixidentity.Account) (string, bool) { return "", false })
	if err != nil || !ok {
		return "", false
	}
	return record.AccountIncarnation, true
}

// processCredentialFacts are the facts of the per-user gateway's own
// account, uid, from its kernel credentials: the groups its process holds
// (its primary group first), named through NSS as an account's groups are,
// and no fact of which account holds the uid (HolderUnproven): the uid may
// be another account's as well. false for any other uid and on a gateway
// that runs as a service account. Tests replace processGroupIDs.
func processCredentialFacts(resolver peerNSSResolver, uid int, now time.Time) (useridentity.DirectoryFacts, bool) {
	if gatewayRunsAsServiceAccount() || uid != os.Getuid() {
		return useridentity.DirectoryFacts{}, false
	}
	ids, err := processGroupIDs()
	if err != nil {
		return useridentity.DirectoryFacts{}, false
	}
	names, unconfirmed, err := resolver.GroupNames(ids)
	if err != nil {
		return useridentity.DirectoryFacts{}, false
	}
	return useridentity.DirectoryFacts{
		Source:            useridentity.SourceProcessCredentials,
		Groups:            names,
		UnconfirmedGroups: unconfirmed,
		HolderUnproven:    true,
		Assurance:         useridentity.AssuranceVerified,
		ResolvedAt:        now,
	}, true
}

// processGroupIDs are the gateway process's primary and supplementary gids.
var processGroupIDs = func() ([]int, error) {
	groups, err := os.Getgroups()
	if err != nil {
		return nil, err
	}
	ids := []int{os.Getgid()}
	for _, id := range groups {
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// peerNSSFacts resolves a verified uid's facts (resolveNSSPeerFacts);
// tests replace it.
var peerNSSFacts = resolveNSSPeerFacts

// peerNSSResolver is the NSS work this gateway does for one verified peer.
// Keep the resolver boundary replaceable so the managed path can be tested
// with a local uid absent from SSSD without changing the host's account DB.
type peerNSSResolver interface {
	LookupUID(int) (unixidentity.Account, error)
	DirectoryFactsForUID(int, time.Time) (useridentity.DirectoryFacts, error)
	DirectoryFactsForRecordedUnsharedUID(int, time.Time) (useridentity.DirectoryFacts, error)
	GroupNames([]int) ([]string, []string, error)
}

var newPeerNSSResolver = func(ctx context.Context) (peerNSSResolver, error) {
	return unixidentity.NewNSSResolver(ctx)
}

var peerUnsharedUIDNeedsRoot = unixidentity.UnsharedUIDNeedsRoot

// peerRootProofRecorded reports whether the hook guardian has recorded, for
// the account that holds the uid key now, the proof that SSSD holds no other
// account of it (holderSpoolRecord), so the next lookup of key takes it
// (resolveNSSPeerFacts). Tests replace it.
var peerRootProofRecorded = func(key string) bool {
	uid, err := strconv.Atoi(key)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), peerDirectoryLookupTimeout)
	defer cancel()
	resolver, err := newPeerNSSResolver(ctx)
	if err != nil {
		return false
	}
	account, err := resolver.LookupUID(uid)
	if err != nil {
		return false
	}
	_, recorded, err := holderSpoolRecord(key, account, "", time.Now().UTC())
	return err == nil && recorded
}

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
	resolver, err := newPeerNSSResolver(ctx)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	account, err := resolver.LookupUID(uid)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	facts, err := resolver.DirectoryFactsForUID(uid, now)
	if peerUnsharedUIDNeedsRoot(err) {
		// The gateway is not root, so it cannot show that SSSD holds no
		// other account of the uid (GAP-0653). The hook guardian, which
		// runs as root, records that proof for the account in its current
		// identity record; a per-user gateway's own account has the groups
		// its own kernel credentials list, which no other account's are.
		if _, recorded, _ := holderSpoolRecord(key, account, "", now); recorded {
			facts, err = resolver.DirectoryFactsForRecordedUnsharedUID(uid, now)
		} else if own, ok := processCredentialFacts(resolver, uid, now); ok {
			noteGroupDomains(own.Groups)
			return own, nil
		}
	}
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
