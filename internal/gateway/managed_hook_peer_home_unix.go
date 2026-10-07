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
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// managedHookPeerHomeTTL bounds how long a resolved home is reused, so a
// moved or recreated account is picked up without restarting the gateway.
const managedHookPeerHomeTTL = 5 * time.Minute

// managedHookPeerLookupRetry is how long a failed account lookup (a
// directory timeout or other transient error, not a definitive "no such
// account") is reused before the next request from that uid asks again. A
// slow or unreachable directory then costs one lookup per uid per interval
// instead of one per connection.
const managedHookPeerLookupRetry = 15 * time.Second

var errManagedHookPeerNoResolver = errors.New("no account resolver")

// managedHookPeerHome resolves the home directory of a kernel-verified
// hook-socket caller through the platform account database (NSS on Linux,
// DirectoryService-backed os/user on macOS). Directory users therefore
// resolve too. An unresolvable home is empty: callers must not fall back to
// the gateway's own home, which belongs to the service account.
var managedHookPeerHome = func(uid int) string {
	return managedHookPeerHomes.lookup(uid)
}

// managedHookPeerName resolves the caller's account name for attribution,
// exempt_users and ledger matching through the same account database as
// the home. os/user in a cgo-free build reads only /etc/passwd, so LDAP,
// SSSD, AD and userdb callers would otherwise have no name: exempt_users
// entries naming them would never match and their events would carry no
// user name. A lookup failure leaves the name empty; the uid is still
// authoritative.
var managedHookPeerName = func(uid int) string {
	return managedHookPeerHomes.lookupName(uid)
}

var managedHookPeerHomes = &managedHookPeerHomeCache{
	newResolver: func() unixidentity.Resolver {
		return unixidentity.Default(context.Background())
	},
	now: time.Now,
}

type managedHookPeerHomeCache struct {
	mu          sync.Mutex
	resolver    unixidentity.Resolver
	resolvedAt  time.Time
	newResolver func() unixidentity.Resolver
	now         func() time.Time
	// accounts holds one answer per uid. A lookup in flight is shared by
	// the requests of that uid and never holds up another uid.
	accounts map[int]*managedHookPeerAccount
	// directories holds each uid's verified directory facts with their own,
	// longer lifetime (identity_directory_cache.go): NSS backend, domain
	// and groups, plus the guardian identity spool's UPN.
	directoriesOnce sync.Once
	directories     *identityDirectoryCache
}

type managedHookPeerAccount struct {
	ready   chan struct{} // closed once account, ok and expires are set
	account unixidentity.Account
	ok      bool
	expires time.Time
}

// account resolves uid through the cached platform resolver; false when the
// account is unknown, the lookup failed, or the answer names a different
// uid. A definitive answer is reused for managedHookPeerHomeTTL, a failed
// lookup for managedHookPeerLookupRetry.
func (c *managedHookPeerHomeCache) account(uid int) (unixidentity.Account, bool) {
	if uid < 0 {
		return unixidentity.Account{}, false
	}
	c.mu.Lock()
	now := c.now()
	if c.resolver == nil || now.Sub(c.resolvedAt) > managedHookPeerHomeTTL {
		c.resolver = c.newResolver()
		c.resolvedAt = now
		c.accounts = nil
	}
	if entry := c.accounts[uid]; entry != nil {
		select {
		case <-entry.ready:
			if now.Before(entry.expires) {
				c.mu.Unlock()
				return entry.account, entry.ok
			}
		default:
			c.mu.Unlock()
			<-entry.ready
			return entry.account, entry.ok
		}
	}
	entry := &managedHookPeerAccount{ready: make(chan struct{})}
	if c.accounts == nil {
		c.accounts = make(map[int]*managedHookPeerAccount)
	}
	c.accounts[uid] = entry
	resolver := c.resolver
	c.mu.Unlock()

	account, err := unixidentity.Account{}, errManagedHookPeerNoResolver
	if resolver != nil {
		account, err = resolver.LookupUID(uid)
	}
	ok := err == nil && account.UID == uid
	retain := managedHookPeerHomeTTL
	if err != nil && !unixidentity.IsNotFound(err) {
		retain = managedHookPeerLookupRetry
	}
	if !ok {
		account = unixidentity.Account{}
	}
	c.mu.Lock()
	entry.account, entry.ok, entry.expires = account, ok, c.now().Add(retain)
	c.mu.Unlock()
	close(entry.ready)
	return account, ok
}

// directory returns uid's verified directory facts from the cache, waiting
// for a cold lookup up to its budget only when block is set.
func (c *managedHookPeerHomeCache) directory(uid int, block bool) (useridentity.DirectoryFacts, bool) {
	if uid < 0 {
		return useridentity.DirectoryFacts{}, false
	}
	return c.directoryCache().get(strconv.Itoa(uid), block)
}

// directoryCache returns the cache of verified directory facts per uid,
// created on first use.
func (c *managedHookPeerHomeCache) directoryCache() *identityDirectoryCache {
	c.directoriesOnce.Do(func() {
		c.directories = newIdentityDirectoryCache(resolvePeerDirectoryFacts)
		c.directories.incomplete = func(facts useridentity.DirectoryFacts) bool {
			return hasUnnamedGroup(facts) || awaitingSpoolUPN(facts)
		}
	})
	return c.directories
}

// peerDirectoryCache is the cache the hook path reads directory facts from.
func peerDirectoryCache() *identityDirectoryCache { return managedHookPeerHomes.directoryCache() }

// hasUnnamedGroup marks facts with a group that is still a number: no group
// answered for the id when it was looked up (an SSSD that was cold or could
// not reach its domain controller), so the name an assignment spells never
// matches it. The facts are served, and refreshed after the short incomplete
// lifetime rather than the full 15 minutes (GAP-0138).
func hasUnnamedGroup(facts useridentity.DirectoryFacts) bool {
	for _, group := range facts.Groups {
		if group != "" && strings.Trim(group, "0123456789") == "" {
			return true
		}
	}
	return false
}

// managedHookPeerDirectory resolves a verified uid's directory facts.
var managedHookPeerDirectory = func(uid int, block bool) (useridentity.DirectoryFacts, bool) {
	return managedHookPeerHomes.directory(uid, block)
}

// verifiedIdentityDirectory returns the directory facts of a verified uid
// (a hook-socket peer, a per-user credential's account, the process owner).
func verifiedIdentityDirectory(identity string, block bool) (useridentity.DirectoryFacts, bool) {
	uid, err := strconv.Atoi(identity)
	if err != nil {
		return useridentity.DirectoryFacts{}, false
	}
	return managedHookPeerDirectory(uid, block)
}

// lookup returns the caller's normalized home, or "".
func (c *managedHookPeerHomeCache) lookup(uid int) string {
	account, ok := c.account(uid)
	if !ok {
		return ""
	}
	return normalizeManagedHookPeerHome(account.Home)
}

// lookupName returns the caller's sanitized account name, or "".
func (c *managedHookPeerHomeCache) lookupName(uid int) string {
	account, ok := c.account(uid)
	if !ok {
		return ""
	}
	return sanitizeLLMEventUser(account.Name)
}

// normalizeManagedHookPeerHome keeps only an absolute, clean home below the
// root directory; anything else is treated as unresolved.
func normalizeManagedHookPeerHome(home string) string {
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	cleaned := filepath.Clean(home)
	if cleaned != home && cleaned+"/" != home {
		return ""
	}
	if cleaned == string(filepath.Separator) {
		return ""
	}
	return cleaned
}
