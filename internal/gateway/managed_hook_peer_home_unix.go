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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// managedHookPeerHomeTTL bounds how long a resolved home is reused, so a
// moved or recreated account is picked up without restarting the gateway.
const managedHookPeerHomeTTL = 5 * time.Minute

// managedHookPeerLookupRetry is how long a failed account lookup is reused
// before the next request from that uid asks again. A slow or unreachable
// directory then costs one lookup per uid per interval instead of one per
// connection. "No such account" counts as failed: the uid is the kernel's,
// so an account with a process exists, and an SSSD that is offline with a
// cold cache answers it for directory accounts until it is back (GAP-0256).
const managedHookPeerLookupRetry = 15 * time.Second

var errManagedHookPeerNoResolver = errors.New("no account resolver")

// managedHookPeerAccountsStamp identifies the state of the local account
// database: useradd, userdel and usermod replace /etc/passwd, and macOS
// keeps a local account's record in the dslocal users directory. When it
// changes, every cached account is looked up again at once, so a uid that
// was removed and handed to a new account inside managedHookPeerHomeTTL
// never gets the removed account's name, home, directory facts or agent
// identity (GAP-0947). "" when it cannot be read: the TTL alone applies.
var managedHookPeerAccountsStamp = func() string {
	path := "/etc/passwd"
	if runtime.GOOS == "darwin" {
		path = "/var/db/dslocal/nodes/Default/users"
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	stamp := strconv.FormatInt(info.ModTime().UnixNano(), 10) + "/" + strconv.FormatInt(info.Size(), 10)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp += "/" + strconv.FormatUint(uint64(st.Ino), 10)
	}
	return stamp
}

func managedHookPeerStamp() string {
	if ManagedEnterpriseActive() {
		// Secure Client keeps main's lifetime (#1092).
		return ""
	}
	return managedHookPeerAccountsStamp()
}

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
	stamp       string // managedHookPeerStamp when resolver was made
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
	// homes keeps the last home each uid resolved to, across resolver
	// refreshes. A later lookup that fails or answers "no such account" (an
	// offline SSSD answers that for directory accounts) serves it, so the
	// config root and the agent identity derived from it do not move while
	// the directory is away (GAP-0314).
	homes map[int]string
	// names keeps the last account name each uid resolved to for its agent
	// identity, which is keyed on the account too (GAP-0947), so an outage
	// moves it no more than the home (agentIdentityAccountName).
	names map[int]string
	// homesFile persists homes and names in the gateway's data directory,
	// so a gateway that starts while the directory is away still has the
	// last home and name of each uid and keeps its agent identity
	// (GAP-0314). Empty when nothing is persisted (per-user gateways,
	// Secure Client).
	homesFile   string
	homesLoaded bool
	// holders are useful only while the corresponding directory facts are
	// still served. Outside Secure Client, a local account database change
	// also rechecks a holder before it can make a live namesake ambiguous.
	holders map[int]managedHookPeerHolder
}

type managedHookPeerHolder struct {
	name, home string
	stamp      string
}

// managedHookPeerHomesFileMax bounds the persisted homes file read at start.
const managedHookPeerHomesFileMax = 4 << 20

// setStore names the file that persists the last resolved homes; "" turns
// persistence off. The file is read once, at the first lookup.
func (c *managedHookPeerHomeCache) setStore(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if path != c.homesFile {
		c.homesFile, c.homesLoaded = path, false
	}
}

// managedHookPeerLast is what the store keeps of one uid.
type managedHookPeerLast struct {
	Home string `json:"home,omitempty"`
	Name string `json:"name,omitempty"`
}

// loadHomesLocked merges the persisted homes and names under the ones this
// process resolved itself. c.mu is held.
func (c *managedHookPeerHomeCache) loadHomesLocked() {
	if c.homesLoaded || c.homesFile == "" {
		return
	}
	c.homesLoaded = true
	data, err := safefile.ReadRegularFileBounded(c.homesFile, managedHookPeerHomesFileMax)
	if err != nil {
		return
	}
	var stored map[string]managedHookPeerLast
	if json.Unmarshal(data, &stored) != nil {
		return
	}
	for key, last := range stored {
		uid, err := strconv.Atoi(key)
		if err != nil || uid < 0 {
			continue
		}
		if _, known := c.homes[uid]; !known && last.Home != "" &&
			normalizeManagedHookPeerHome(last.Home) == last.Home && len(c.homes) < managedHookPeerHomesMax {
			if c.homes == nil {
				c.homes = make(map[int]string)
			}
			c.homes[uid] = last.Home
		}
		if _, known := c.names[uid]; !known && last.Name != "" &&
			sanitizeLLMEventUser(last.Name) == last.Name && len(c.names) < managedHookPeerHomesMax {
			if c.names == nil {
				c.names = make(map[int]string)
			}
			c.names[uid] = last.Name
		}
	}
}

// saveHomesLocked writes homes and names to the store. c.mu is held; it
// runs only when a uid's home or name changes, which is rare.
func (c *managedHookPeerHomeCache) saveHomesLocked() {
	if c.homesFile == "" {
		return
	}
	stored := make(map[string]managedHookPeerLast, len(c.homes))
	for uid, home := range c.homes {
		stored[strconv.Itoa(uid)] = managedHookPeerLast{Home: home}
	}
	for uid, name := range c.names {
		last := stored[strconv.Itoa(uid)]
		last.Name = name
		stored[strconv.Itoa(uid)] = last
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return
	}
	_ = safefile.WritePrivate(c.homesFile, data)
}

// setManagedHookPeerHomeStore names the managed gateway's persisted homes
// file, or "" for none.
func setManagedHookPeerHomeStore(path string) { managedHookPeerHomes.setStore(path) }

// managedHookPeerHomesMax bounds the last resolved homes kept, one per uid.
const managedHookPeerHomesMax = 16384

type managedHookPeerAccount struct {
	ready    chan struct{} // closed once account, ok and expires are set
	account  unixidentity.Account
	ok       bool
	notFound bool
	expires  time.Time
}

// account resolves uid through the cached platform resolver; false when the
// account is unknown, the lookup failed, or the answer names a different
// uid. A definitive answer is reused for managedHookPeerHomeTTL, a failed
// lookup for managedHookPeerLookupRetry.
func (c *managedHookPeerHomeCache) account(uid int) (unixidentity.Account, bool) {
	if uid < 0 {
		return unixidentity.Account{}, false
	}
	stamp := managedHookPeerStamp()
	c.mu.Lock()
	now := c.now()
	if c.resolver == nil || now.Sub(c.resolvedAt) > managedHookPeerHomeTTL || stamp != c.stamp {
		c.resolver = c.newResolver()
		c.resolvedAt = now
		c.accounts = nil
		c.stamp = stamp
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
	switch {
	case ok:
	case ManagedEnterpriseActive() && unixidentity.IsNotFound(err):
		// Secure Client keeps main's lifetime for a "no such account" (#1092).
		account = unixidentity.Account{}
	default:
		retain = managedHookPeerLookupRetry
		account = unixidentity.Account{}
		if forget, can := resolver.(interface{ ForgetUID(int) }); can {
			forget.ForgetUID(uid)
		}
	}
	c.mu.Lock()
	entry.account, entry.ok, entry.notFound, entry.expires = account, ok, unixidentity.IsNotFound(err), c.now().Add(retain)
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
	key := strconv.Itoa(uid)
	c.noteHolder(uid, key)
	return c.directoryCache().get(key, block)
}

// explainDirectory is directory for `guardrail profile explain`: the facts a
// hook call of uid gets after explain's own lookup (explainDirectoryFacts),
// or why it gets none. Explain records the account it resolved as the holder
// of uid's facts, as a hook call does. Explain's lookup refreshes the facts
// hooks read, but only a hook call recorded whose they were, so an account
// explained before a directory outage and not yet seen by a hook kept the
// profile of those facts in its hooks while explain by name answered
// default_lookup_failed: a looser live decision than the one explain showed
// (GAP-0529).
func (c *managedHookPeerHomeCache) explainDirectory(uid int) (useridentity.DirectoryFacts, error) {
	key := strconv.Itoa(uid)
	c.noteHolder(uid, key)
	return explainDirectoryFacts(c.directoryCache(), key)
}

// noteHolder records the account (name and home) that uid's cached
// directory facts are used for, when the account database names uid now.
// When another account holds the uid (a removed account's uid given to a new
// one), its facts are dropped first (GAP-0720).
func (c *managedHookPeerHomeCache) noteHolder(uid int, key string) {
	if uid < 0 || !identityFactsEnabled.Load() {
		return
	}
	account, ok := c.account(uid)
	if !ok {
		return
	}
	holder := managedHookPeerHolder{name: account.Name, home: account.Home, stamp: managedHookPeerStamp()}
	c.mu.Lock()
	previous, known := c.holders[uid]
	changed := known && (previous.name != holder.name || previous.home != holder.home)
	if !known && len(c.holders) < managedHookPeerHomesMax || known {
		if c.holders == nil {
			c.holders = make(map[int]managedHookPeerHolder)
		}
		c.holders[uid] = holder
	}
	c.mu.Unlock()
	if changed {
		c.directoryCache().forget(key)
	}
}

// directoryCache returns the cache of verified directory facts per uid,
// created on first use.
func (c *managedHookPeerHomeCache) directoryCache() *identityDirectoryCache {
	c.directoriesOnce.Do(func() {
		c.directories = newIdentityDirectoryCache(resolvePeerDirectoryFacts)
		c.directories.incomplete = func(facts useridentity.DirectoryFacts) bool {
			return hasUnnamedGroup(facts) || awaitingSpoolUPN(facts)
		}
		c.directories.settling = openDirectorySettling
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

// lookup returns the caller's normalized home, or "". A lookup that fails
// returns the last home the uid resolved to.
func (c *managedHookPeerHomeCache) lookup(uid int) string {
	account, ok := c.account(uid)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadHomesLocked()
	if !ok {
		return c.homes[uid]
	}
	home := normalizeManagedHookPeerHome(account.Home)
	previous, known := c.homes[uid]
	if home == "" {
		if known {
			delete(c.homes, uid)
			c.saveHomesLocked()
		}
	} else if known || len(c.homes) < managedHookPeerHomesMax {
		if c.homes == nil {
			c.homes = make(map[int]string)
		}
		c.homes[uid] = home
		if previous != home {
			c.saveHomesLocked()
		}
	}
	return home
}

// lookupName returns the caller's sanitized account name, or "".
// cachedHolder returns the uid and name of the account whose cached
// directory facts were last used under name (compared without regard to
// case) or under the uid name spells.
func (c *managedHookPeerHomeCache) cachedHolder(name string) (int, string, bool) {
	name = strings.TrimSpace(name)
	holders := c.liveHolders()
	if uid, err := strconv.Atoi(name); err == nil && strconv.Itoa(uid) == name {
		if holder, ok := holders[uid]; ok {
			return uid, holder.name, holder.name != ""
		}
		return 0, "", false
	}
	var foundUID int
	var foundName string
	for uid, holder := range holders {
		if holder.name != "" && useridentity.EqualFold(holder.name, name) {
			if foundName != "" {
				return 0, "", false
			}
			foundUID, foundName = uid, holder.name
		}
	}
	return foundUID, foundName, foundName != ""
}

// cachedNamesakes lists other verified uids last held under a bare name.
// The account database may temporarily stop answering for a directory uid,
// while explain can still use its cached facts by that uid.
func (c *managedHookPeerHomeCache) cachedNamesakes(name string, exceptUID int) []unixidentity.Account {
	var accounts []unixidentity.Account
	for uid, holder := range c.liveHolders() {
		if uid != exceptUID && holder.name != "" && useridentity.EqualFold(holder.name, name) {
			accounts = append(accounts, unixidentity.Account{UID: uid, Name: holder.name})
		}
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].UID < accounts[j].UID })
	return accounts
}

// liveHolders keeps only holders whose facts a hook still gets. A changed
// local account database makes a definitive missing local uid stale at once;
// an offline directory can report the same lookup error, so its holder stays
// while the verified facts are served. No resolver call holds c.mu.
func (c *managedHookPeerHomeCache) liveHolders() map[int]managedHookPeerHolder {
	c.mu.Lock()
	holders := make(map[int]managedHookPeerHolder, len(c.holders))
	for uid, holder := range c.holders {
		holders[uid] = holder
	}
	c.mu.Unlock()
	stamp := managedHookPeerStamp()
	for uid, holder := range holders {
		facts, _, served := c.directoryCache().peek(strconv.Itoa(uid))
		forgetFacts := false
		if served && stamp != "" && stamp != holder.stamp {
			account, ok := c.account(uid)
			switch {
			case ok && (account.Name != holder.name || account.Home != holder.home):
				served, forgetFacts = false, true
			case !ok && facts.Directory == useridentity.DirectoryLocal:
				c.mu.Lock()
				entry := c.accounts[uid]
				missing := entry != nil && entry.notFound
				c.mu.Unlock()
				served, forgetFacts = !missing, missing
			case ok:
				holder.stamp = stamp
				c.mu.Lock()
				if c.holders[uid] == holders[uid] {
					c.holders[uid] = holder
				}
				c.mu.Unlock()
			}
		}
		if !served {
			c.mu.Lock()
			if c.holders[uid] == holders[uid] {
				delete(c.holders, uid)
			}
			c.mu.Unlock()
			delete(holders, uid)
			if forgetFacts {
				c.directoryCache().forget(strconv.Itoa(uid))
			}
		}
	}
	return holders
}

func (c *managedHookPeerHomeCache) lookupName(uid int) string {
	account, ok := c.account(uid)
	if !ok {
		return ""
	}
	name := sanitizeLLMEventUser(account.Name)
	if name != "" {
		c.rememberName(uid, name)
	}
	return name
}

// managedHookPeerLastName is the last account name uid resolved to, which
// a managed gateway keeps across restarts; "" for a uid that never did. It
// stands in for the name only where the account database gives none (a
// directory outage) and a record bound to that name says who the caller is
// (sandboxCheckSubject).
var managedHookPeerLastName = func(uid int) string { return managedHookPeerHomes.lastName(uid) }

// rememberName records the name uid resolved to for lastName.
func (c *managedHookPeerHomeCache) rememberName(uid int, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadHomesLocked()
	if previous, known := c.names[uid]; previous == name || !known && len(c.names) >= managedHookPeerHomesMax {
		return
	}
	if c.names == nil {
		c.names = make(map[int]string)
	}
	c.names[uid] = name
	c.saveHomesLocked()
}

// lastName returns the last name rememberName recorded for uid, or "".
func (c *managedHookPeerHomeCache) lastName(uid int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadHomesLocked()
	return c.names[uid]
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
