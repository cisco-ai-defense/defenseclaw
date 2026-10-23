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
	owner, ok := legacyAgentOwners.get(uid)
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
// directory's. Tests replace it.
var legacyAgentOwnerTokenNow = func(uid int, account string) string {
	incarnation := ""
	if dir := currentIdentitySpoolDir(); dir != "" {
		if record, err := enterprisehooks.ReadIdentitySpoolRecord(dir, strconv.Itoa(uid), validateManagedGuardianAuthorization); err == nil &&
			legacyAgentOwnerSameAccount(record.User, account) && !record.UpdatedAt.IsZero() &&
			!record.UpdatedAt.After(time.Now().Add(time.Minute)) && time.Since(record.UpdatedAt) <= enterprisehooks.IdentitySpoolMaxAge {
			if record.LegacyOwnerToken != "" {
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
	return enterprisehooks.LegacyAgentOwnerToken(incarnation, managedHookPeerHome(uid))
}

// legacyAgentOwners is the migration map the gateway read. It is read until
// it is found, at most every legacyAgentOwnersRetry. A map with an account
// still pending (open) is read again when its main file changes, checked
// at most every legacyAgentOwnersRetry, since the guardian adds a pending
// account's owner once it proves it; a map with none pending never changes
// and is kept.
var legacyAgentOwners = &legacyAgentOwnerCache{}

const legacyAgentOwnersRetry = 30 * time.Second

type legacyAgentOwnerCache struct {
	mu      sync.Mutex
	dir     string
	owners  map[int]enterprisehooks.LegacyAgentOwner
	loaded  bool
	open    bool
	stamp   string
	nextTry time.Time
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

func (c *legacyAgentOwnerCache) get(uid int) (enterprisehooks.LegacyAgentOwner, bool) {
	dir := currentIdentitySpoolDir()
	if dir == "" {
		return enterprisehooks.LegacyAgentOwner{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if dir != c.dir {
		c.dir, c.owners, c.loaded, c.open, c.stamp, c.nextTry = dir, nil, false, false, "", time.Time{}
	}
	if (!c.loaded || c.open) && !time.Now().Before(c.nextTry) {
		c.nextTry = time.Now().Add(legacyAgentOwnersRetry)
		if stamp := legacyAgentOwnersStamp(dir); !c.loaded || stamp != c.stamp {
			// A map that cannot be read now (a shard being written, a
			// transient error) keeps the owners read before.
			if owners, open, ok := enterprisehooks.ReadLegacyAgentOwners(dir, validateManagedGuardianAuthorization); ok {
				c.owners, c.open, c.loaded, c.stamp = owners, open, true, stamp
			}
		}
	}
	owner, ok := c.owners[uid]
	return owner, ok
}
