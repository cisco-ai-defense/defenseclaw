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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// legacyAgentOwnerBound reports whether the upgrade's migration map
// (enterprisehooks.LegacyAgentOwnersFile) binds the 1.0.3 agent identities
// of uid identity to account, the account that holds the uid now: the map
// records the uid under that name, domain included, and the incarnation
// that holds it now has the recorded token. Any other account, a namesake
// of another domain, an account created again under the uid and name, or a
// uid the map does not record, is not bound. Tests replace it.
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
	return legacyAgentOwnerTokenNow(uid, account) == owner.Token
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
// it is found, at most every legacyAgentOwnersRetry, and read again when the
// file changes (checked as often): the guardian adds the accounts a
// rollback window served at its first pass after the upgrade back, and a
// running gateway that kept the first map refused them until a restart
// (GAP-0709).
var legacyAgentOwners = &legacyAgentOwnerCache{}

const legacyAgentOwnersRetry = 30 * time.Second

type legacyAgentOwnerCache struct {
	mu      sync.Mutex
	dir     string
	owners  map[int]enterprisehooks.LegacyAgentOwner
	loaded  bool
	nextTry time.Time
	// stamp is the size and modification time of the map that was read.
	stamp legacyAgentOwnersStamp
}

type legacyAgentOwnersStamp struct {
	size    int64
	modTime time.Time
}

// legacyAgentOwnersFileStamp is the stamp of dir's map, false when it cannot
// be read. Tests replace it.
var legacyAgentOwnersFileStamp = func(dir string) (legacyAgentOwnersStamp, bool) {
	info, err := os.Lstat(filepath.Join(dir, enterprisehooks.LegacyAgentOwnersFile))
	if err != nil {
		return legacyAgentOwnersStamp{}, false
	}
	return legacyAgentOwnersStamp{size: info.Size(), modTime: info.ModTime()}, true
}

func (c *legacyAgentOwnerCache) get(uid int) (enterprisehooks.LegacyAgentOwner, bool) {
	dir := currentIdentitySpoolDir()
	if dir == "" {
		return enterprisehooks.LegacyAgentOwner{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if dir != c.dir {
		c.dir, c.owners, c.loaded, c.nextTry = dir, nil, false, time.Time{}
	}
	if !time.Now().Before(c.nextTry) {
		c.nextTry = time.Now().Add(legacyAgentOwnersRetry)
		stamp, stamped := legacyAgentOwnersFileStamp(dir)
		if !c.loaded || stamped && stamp != c.stamp {
			// A map that cannot be read now keeps the one read before.
			if owners, ok := enterprisehooks.ReadLegacyAgentOwners(dir, validateManagedGuardianAuthorization); ok {
				c.owners, c.loaded, c.stamp = owners, true, stamp
			}
		}
	}
	owner, ok := c.owners[uid]
	return owner, ok
}
