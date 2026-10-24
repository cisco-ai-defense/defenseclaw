// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"context"
	"strconv"
	"time"

	osuser "os/user"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// managedHookPeerAccountIncarnation names nothing on macOS: the listed
// record of a local account (managedHookPeerAccountRecord) tells one
// incarnation from the next, and Open Directory answers a uid with one
// account.
var managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "", false }

// resolvePeerDirectoryFacts returns a verified uid's directory facts: the
// account's own facts from the system account database, which on macOS
// answers through Open Directory (groups; directory local for an account of the local node), with the root
// enumerator's record laid over them when the guardian wrote one (a managed
// install: the dscl directory, Kerberos principal and domain of a bound Mac,
// the Platform SSO tenant). The record carries no groups, so the gateway's
// own answer stays under it, as on Linux; returning the record alone made
// every group assignment miss on a managed Mac. Guardrail profile explain
// resolves through the same function.
func resolvePeerDirectoryFacts(key string) (useridentity.DirectoryFacts, error) {
	now := time.Now().UTC()
	account, err := osuser.LookupId(key)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	// Groups that could not be listed fail the lookup: facts cached as
	// resolved without them would select the default profile as "default"
	// for 15 minutes instead of "default_lookup_failed".
	groups, err := accountGroups(account)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	own := useridentity.DirectoryFacts{
		Source:     useridentity.SourceMacOSOpenDirectory,
		Groups:     groups,
		Assurance:  useridentity.AssuranceVerified,
		ResolvedAt: now,
		// Read before the record (forgetOnSpoolChange).
		SpoolSeenAt: identitySpoolSeenAt(key, now),
	}
	// Open Directory answers a bound Mac's directory accounts too, so only an
	// account of the local node is local. Calling every account local let no
	// bare users entry select an AD account without the guardian's record,
	// once a bare name stopped selecting local accounts (GAP-0305).
	if darwinLocalNodeAccount(account.Username, account.Uid) {
		own.Directory = useridentity.DirectoryLocal
	}
	own.AccountRecord = accountRecordToken(managedHookPeerAccountRecord(account.Username))
	record, ok, _ := readIdentitySpoolFactsForAccount(key, account.Username, "", now)
	var spool *enterprisehooks.IdentitySpoolRecord
	if ok {
		spool = &record
	}
	if err := openDirectoryGroupsUnavailable(spool, own.Directory == useridentity.DirectoryLocal, account.Gid, primaryGroupNamed,
		openDirectoryOffline, directoryUnreachable, now); err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	if ok {
		return mergeSpoolFacts(own, record), nil
	}
	return own, nil
}

// openDirectoryOffline reports whether Open Directory lists the node of the
// bound Active Directory domain offline. Tests replace it.
var openDirectoryOffline = func() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return unixidentity.OpenDirectoryOffline(ctx)
}

// darwinLocalNodeAccount reports whether the local directory node holds the
// account name with this uid (dscl . -list /Users UniqueID) as an account of
// its own. A mobile account is held there too, but it is a copy of a
// directory account (its OriginalNodeName names the directory node): calling
// it local hid the outage that leaves its primary group unnamed once the
// guardian's record had aged out, and the account moved to the default
// profile as plain "default" (GAP-0496, GAP-0517). A failed listing says
// nothing, and the account's directory stays unknown. Tests replace it.
var darwinLocalNodeAccount = func(name, uid string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	local, err := unixidentity.LocalAccounts(ctx)
	if err != nil {
		return false
	}
	if id, ok := local[name]; !ok || strconv.Itoa(id) != uid {
		return false
	}
	mobile, err := unixidentity.MobileAccounts(ctx)
	return err == nil && mobile[name] == ""
}

// primaryGroupNamed reports whether Open Directory names the group gid.
// Tests replace it.
var primaryGroupNamed = func(gid string) bool {
	group, err := osuser.LookupGroupId(gid)
	return err == nil && group.Name != ""
}
