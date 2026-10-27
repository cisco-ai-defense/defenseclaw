// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// legacyAgentOwnerBound reports whether the upgrade's migration map
// (enterprisehooks.LegacyAgentOwnersFile) binds the 1.0.3 agent identities
// of uid identity to account, the account that holds the uid now: the map
// records the uid under that name, domain included, and the incarnation
// that holds it now has the recorded token (legacyAgentOwnerTokenMatches).
// Any other account, a namesake of another domain, an account created again
// under the uid and name, or a uid the map does not record, is not bound.
// Tests replace it.
var legacyAgentOwnerBound = func(identity, account string) bool {
	if useridentity.KindForID(identity) != useridentity.KindPOSIXUID {
		return false
	}
	uid, err := strconv.Atoi(identity)
	if err != nil || uid < 0 {
		return false
	}
	owner, _, ok := legacyAgentOwners.get(uid)
	if !ok || !legacyAgentOwnerSameAccount(owner.User, account) {
		return false
	}
	return legacyAgentOwnerTokenMatches(owner.Token, legacyAgentOwnerTokenNow(uid, account))
}

// legacyAgentOwnerTokenMatches reports whether now, the token of the
// incarnation that holds a uid now, is the one the migration map recorded.
// A SID token must be the same SID. A home token
// (home:<device>:<inode>[:<creation time>]) is compared without its device
// (normalizeHomeProof): an automounted home gets another device number at
// each mount, and an exact compare refused the account's 1.0.x agents entry
// after a remount (review of r104 Q-identity, continuation 2, loop round 2).
// The inode must be the same, and so must the creation time where the map
// recorded one: a home created again can get the inode the removed one
// freed, never its creation time, so a missing time now does not stand in
// for a recorded one.
func legacyAgentOwnerTokenMatches(recorded, now string) bool {
	if recorded == "" || now == "" {
		return false
	}
	if strings.HasPrefix(recorded, "sid:") {
		return recorded == now
	}
	inodeRecorded, birthRecorded, okRecorded := homeProofParts(normalizeHomeProof(recorded))
	inodeNow, birthNow, okNow := homeProofParts(normalizeHomeProof(now))
	return okRecorded && okNow && inodeRecorded == inodeNow && (birthRecorded == "" || birthRecorded == birthNow)
}

// legacyAgentOwnerSameAccount reports whether recorded and account are one
// account name: the same account and the same domain (none for both, or
// one), whatever their case.
func legacyAgentOwnerSameAccount(recorded, account string) bool {
	return agentidentity.AccountKey(recorded) != "" && agentidentity.AccountKey(recorded) == agentidentity.AccountKey(account) &&
		agentidentity.AccountDomain(recorded) == agentidentity.AccountDomain(account)
}

// legacyAgentOwnerTokenNow is the LegacyAgentOwnerToken of the account that
// holds uid now: its SID from the guardian's identity record of the uid when
// that record names account, else from the gateway's own lookup; or its home
// directory's, from the record while it is newer than the last change of the
// local account database (guardianHomeProofCurrent); the token the map
// recorded for a symlinked home before the GAP-0939 fix is kept as the
// guardian gives it (enterprisehooks.LegacyAgentOwnerTokenFor). Tests
// replace it.
var legacyAgentOwnerTokenNow = func(uid int, account string) string {
	incarnation := ""
	if dir := currentIdentitySpoolDir(); dir != "" {
		if record, err := enterprisehooks.ReadIdentitySpoolRecord(dir, strconv.Itoa(uid), validateManagedGuardianAuthorization); err == nil &&
			legacyAgentOwnerSameAccount(record.User, account) && !record.UpdatedAt.IsZero() &&
			!record.UpdatedAt.After(time.Now().Add(time.Minute)) && time.Since(record.UpdatedAt) <= enterprisehooks.IdentitySpoolMaxAge {
			if record.LegacyOwnerToken != "" && (strings.HasPrefix(record.LegacyOwnerToken, "sid:") || guardianHomeProofCurrent(record)) {
				return record.LegacyOwnerToken
			}
			if strings.HasPrefix(record.AccountIncarnation, "sid:") {
				incarnation = record.AccountIncarnation
			}
		}
	}
	if incarnation == "" {
		incarnation, _ = managedHookPeerHomes.incarnation(uid)
	}
	return enterprisehooks.LegacyAgentOwnerTokenFor(incarnation, managedHookPeerHome(uid), func() (string, time.Time) {
		owner, writtenAt, ok := legacyAgentOwners.get(uid)
		if !ok || !legacyAgentOwnerSameAccount(owner.User, account) {
			return "", time.Time{}
		}
		return owner.Token, writtenAt
	})
}

// guardianHomeProofCurrent reports whether the home proof the root guardian
// wrote into record can name the account that holds the record's uid now:
// the local account database did not change since the guardian read it.
// userdel and useradd rewrite /etc/passwd, so a record written before the
// last change can name the home of an account deleted since, whose name and
// uid a new account took over: the new account was bound to the earlier
// holder's 1.0.3 agents entries and got its agent identity until the
// guardian's next pass (GAP-0422, GAP-1876). The guardian writes the records
// again at its next tick after such a change. A record with the stamp the
// guardian read (enterprisehooks.LocalAccountsStamp) is current while that
// stamp is; the wall clock does not decide, so a database dated in the
// future (a useradd while the clock was ahead) does not keep every bound
// account refused once the guardian rewrote the records (GAP-2025). A record
// 1.0.4 wrote has no stamp: it is current when it is not older than the
// database. A database the gateway cannot stat (macOS, where the listed
// record tells a recreated account apart) tells nothing.
func guardianHomeProofCurrent(record enterprisehooks.IdentitySpoolRecord) bool {
	if record.AccountsStamp != "" {
		now := localAccountsStamp()
		return now == "" || now == record.AccountsStamp
	}
	changed := localAccountsChangedAt()
	return changed.IsZero() || !record.UpdatedAt.Before(changed)
}

// localAccountsStamp is enterprisehooks.LocalAccountsStamp. Tests replace
// it.
var localAccountsStamp = func() string { return enterprisehooks.LocalAccountsStamp() }

// localAccountsChangedAt is when /etc/passwd last changed on Linux, zero
// when it cannot be read and on other systems. Tests replace it.
var localAccountsChangedAt = func() time.Time {
	if runtime.GOOS != "linux" {
		return time.Time{}
	}
	info, err := os.Stat("/etc/passwd")
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// legacyAgentOwners is the migration map the gateway read. It is read until
// it is found, at most every legacyAgentOwnersRetry, and read again when its
// main file changes (checked as often): the guardian adds a pending
// account's owner once it proves it, and the accounts a rollback window
// served at its first pass after the upgrade back; a running gateway that
// kept the first map refused them until a restart (GAP-0709).
var legacyAgentOwners = &legacyAgentOwnerCache{}

const legacyAgentOwnersRetry = 30 * time.Second

type legacyAgentOwnerCache struct {
	mu        sync.Mutex
	dir       string
	owners    map[int]enterprisehooks.LegacyAgentOwner
	writtenAt time.Time
	loaded    bool
	open      bool
	stamp     string
	nextTry   time.Time
}

// legacyAgentOwnersStamp names the version of the map's main file in dir,
// which the guardian rewrites (renames into place) whenever it changes the
// map; "" when there is none.
func legacyAgentOwnersStamp(dir string) string {
	info, err := os.Stat(filepath.Join(dir, enterprisehooks.LegacyAgentOwnersFile))
	if err != nil {
		return ""
	}
	stamp := strconv.FormatInt(info.Size(), 10) + ":" + strconv.FormatInt(info.ModTime().UnixNano(), 10)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp += ":" + strconv.FormatUint(uint64(st.Ino), 10)
	}
	return stamp
}

// get returns the owner the map records for uid, and when the map was
// written.
func (c *legacyAgentOwnerCache) get(uid int) (enterprisehooks.LegacyAgentOwner, time.Time, bool) {
	dir := currentIdentitySpoolDir()
	if dir == "" {
		return enterprisehooks.LegacyAgentOwner{}, time.Time{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if dir != c.dir {
		c.dir, c.owners, c.writtenAt, c.loaded, c.open, c.stamp, c.nextTry = dir, nil, time.Time{}, false, false, "", time.Time{}
	}
	if !time.Now().Before(c.nextTry) {
		c.nextTry = time.Now().Add(legacyAgentOwnersRetry)
		if stamp := legacyAgentOwnersStamp(dir); !c.loaded || stamp != c.stamp {
			// A map that cannot be read now (a shard being written, a
			// transient error) keeps the owners read before.
			if owners, open, writtenAt, ok := enterprisehooks.ReadLegacyAgentOwners(dir, validateManagedGuardianAuthorization); ok {
				c.owners, c.open, c.writtenAt, c.loaded, c.stamp = owners, open, writtenAt, true, stamp
			}
		}
	}
	owner, ok := c.owners[uid]
	return owner, c.writtenAt, ok
}
