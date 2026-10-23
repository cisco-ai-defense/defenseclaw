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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

var managedHookDirectoryNeedsFresh = runtime.GOOS == "darwin"

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

// managedHookPeerAccountRecheck is how long a uid's account (name, home and
// incarnation) is served before a request asks the account database again,
// while identity facts are on. A directory hands a uid from one account to
// another without changing /etc/passwd, so the managedHookPeerHomeTTL answer
// served the facts and the agent identity of the account that held the uid
// before to the one that holds it now for up to 5 minutes (review of
// GAP-0551). Requests of one uid share one recheck, and one that the
// directory cannot answer keeps the last answer (the facts are served
// through an outage) until managedHookPeerLookupRetry.
const managedHookPeerAccountRecheck = time.Second

var errManagedHookPeerNoResolver = errors.New("no account resolver")

// managedHookPeerAccountsStamp identifies the state of the local account
// database (managedHookPeerAccountsSource: /etc/passwd on Linux, the listed
// local accounts on macOS, where the service account cannot read the
// database). When it changes, every cached account is looked up again at
// once, so a uid that was removed and handed to a new account inside
// managedHookPeerHomeTTL never gets the removed account's name, home,
// directory facts or agent identity (GAP-0947, GAP-0669). "" when no source
// can be read: the TTL alone applies.
var managedHookPeerAccountsStamp = func() string { return managedHookPeerAccounts.get() }

// managedHookPeerAccountsRefresh brings the stamp up to date before an
// administrator view (explain) compares it, as a listed stamp a request
// reads can be up to managedHookPeerListedStampInterval old.
var managedHookPeerAccountsRefresh = func() { managedHookPeerAccounts.refresh() }

// managedHookPeerAccountRecord is the listed record of the local account
// name (macOS): another one under the same name, uid and home is another
// account, deleted and created again (GAP-0669). "" where none is listed.
var managedHookPeerAccountRecord = func(name string) string {
	if ManagedEnterpriseActive() {
		return ""
	}
	return managedHookPeerAccounts.record(name)
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
	// incarnations keeps, per uid, the first account token (accountToken)
	// this gateway saw hold the uid and the last one, persisted with the
	// homes and names (agentIncarnation).
	incarnations map[int]managedHookPeerIncarnations
	// legacy marks the uids a build before 1.0.4 saw hold an account (the
	// homes file it wrote names them) for which no account token has been
	// adopted yet (agentIncarnation). It is kept across restarts with the
	// homes.
	legacy map[int]bool
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

// managedHookPeerIncarnations are the first and the last account token a
// uid resolved to. base is agentIncarnationUnproven when the first account
// this gateway saw hold the uid cannot be shown to be the one older builds
// saw (agentIncarnation).
type managedHookPeerIncarnations struct {
	base, last string
}

// agentIncarnationUnproven is the base token of a uid whose first account
// seen after an upgrade from a build that kept no account token cannot be
// shown to be the account the older build saw: no account holds the uid's
// agent identities of before, and every account derives its own.
const agentIncarnationUnproven = "unproven:legacy"

// managedHookPeerHomesFormatKey is the entry of the homes file that marks
// it written by a build that keeps account tokens (Format 1). Its key is no
// uid, so every build skips it as an entry. A file without it was written
// by an older build: each uid it names was seen before account tokens were
// kept (legacy).
const managedHookPeerHomesFormatKey = "format"

type managedHookPeerHolder struct {
	name, home string
	stamp      string
	record     string // managedHookPeerAccountRecord of name, "" when none was listed
	// incarnation is the managedHookPeerAccountIncarnation of the account,
	// "" while none was known.
	incarnation string
}

// replacedBy reports whether record, the account's listed record now, is
// another record than the one the holder's facts were cached for: the
// account was deleted and created again under the same name and uid
// (GAP-0669). A record unknown on either side is no change.
func (h managedHookPeerHolder) replacedBy(record string) bool {
	return h.record != "" && record != "" && h.record != record
}

// reincarnated reports whether incarnation, the account incarnation that
// holds the uid now (known), is another than the one the holder's facts
// were cached for. A uid handed from one domain's alice to another domain's
// alice with the same home keeps its name and home, and its cached facts
// gave the second account the first one's groups (review of GAP-0551). An
// incarnation known now and not when the facts were cached cannot be
// matched to them, so they are looked up again; one unknown now (SSSD does
// not answer) changes nothing, as the facts are served through an outage.
func (h managedHookPeerHolder) reincarnated(incarnation string, known bool) bool {
	return known && h.incarnation != incarnation
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
	// BaseIncarnation is the first account token this gateway saw hold the
	// uid and Incarnation the last one (agentIncarnation). Builds before
	// 1.0.4 ignore them.
	BaseIncarnation string `json:"base_incarnation,omitempty"`
	Incarnation     string `json:"incarnation,omitempty"`
	// LegacyHolder marks a uid an older build saw for which no account
	// token was adopted yet (managedHookPeerHomeCache.legacy).
	LegacyHolder bool `json:"legacy_holder,omitempty"`
	// Format is set on the managedHookPeerHomesFormatKey entry only.
	Format int `json:"format,omitempty"`
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
	legacyFile := stored[managedHookPeerHomesFormatKey].Format < 1
	for key, last := range stored {
		uid, err := strconv.Atoi(key)
		if err != nil || uid < 0 {
			continue
		}
		if _, adopted := c.incarnations[uid]; !adopted && (legacyFile || last.LegacyHolder) && !validAccountToken(last.BaseIncarnation) &&
			len(c.legacy) < managedHookPeerHomesMax {
			if c.legacy == nil {
				c.legacy = make(map[int]bool)
			}
			c.legacy[uid] = true
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
		if _, known := c.incarnations[uid]; !known && validAccountToken(last.BaseIncarnation) &&
			(last.Incarnation == "" || validAccountToken(last.Incarnation)) && len(c.incarnations) < managedHookPeerHomesMax {
			if c.incarnations == nil {
				c.incarnations = make(map[int]managedHookPeerIncarnations)
			}
			c.incarnations[uid] = managedHookPeerIncarnations{base: last.BaseIncarnation, last: firstNonEmpty(last.Incarnation, last.BaseIncarnation)}
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
	for uid, tokens := range c.incarnations {
		last := stored[strconv.Itoa(uid)]
		last.BaseIncarnation, last.Incarnation = tokens.base, tokens.last
		stored[strconv.Itoa(uid)] = last
	}
	for uid := range c.legacy {
		last := stored[strconv.Itoa(uid)]
		last.LegacyHolder = true
		stored[strconv.Itoa(uid)] = last
	}
	stored[managedHookPeerHomesFormatKey] = managedHookPeerLast{Format: 1}
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
	// incarnation names which directory account holds the uid
	// (managedHookPeerAccountIncarnation); incarnationKnown is false when
	// that could not be told.
	incarnation      string
	incarnationKnown bool
	// checked is when account and incarnation were last confirmed (or,
	// after a recheck the directory could not answer, when the next one is
	// due less managedHookPeerAccountRecheck); recheck is closed when the
	// recheck in flight ends (recheckAccount). Both are guarded by c.mu,
	// and so are account and the incarnation once a recheck may run.
	checked time.Time
	recheck chan struct{}
}

// rechecksAccounts reports whether account answers are rechecked every
// managedHookPeerAccountRecheck: while identity facts are on, outside
// Secure Client (which keeps main's lifetime, #1092).
func rechecksAccounts() bool {
	return identityFactsEnabled.Load() && !ManagedEnterpriseActive()
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
	if stamp == "" && !managedHookPeerAccountsConfirmed() {
		// A listing that has not confirmed the accounts yet changes nothing
		// here; directory serves no facts until it does.
		stamp = c.stamp
	}
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
				if entry.ok && rechecksAccounts() && !now.Before(entry.checked.Add(managedHookPeerAccountRecheck)) {
					resolver := c.resolver
					c.mu.Unlock()
					c.recheckAccount(uid, entry, resolver)
					c.mu.Lock()
				}
				account, ok := entry.account, entry.ok
				c.mu.Unlock()
				return account, ok
			}
		default:
			c.mu.Unlock()
			<-entry.ready
			c.mu.Lock()
			account, ok := entry.account, entry.ok
			c.mu.Unlock()
			return account, ok
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
	incarnation, incarnationKnown := "", false
	if ok && identityFactsEnabled.Load() && !ManagedEnterpriseActive() {
		incarnation, incarnationKnown = managedHookPeerAccountIncarnation(account)
	}
	c.mu.Lock()
	entry.account, entry.ok, entry.notFound, entry.expires = account, ok, unixidentity.IsNotFound(err), c.now().Add(retain)
	entry.incarnation, entry.incarnationKnown = incarnation, incarnationKnown
	entry.checked = c.now()
	c.mu.Unlock()
	close(entry.ready)
	return account, ok
}

// recheckAccount asks the account database again for the account of uid
// that entry holds (managedHookPeerAccountRecheck), and records its answer:
// another name, home or incarnation then makes noteHolder drop the facts
// cached for the former account before they are served. Concurrent
// requests of the uid wait for the one recheck. An answer the directory
// cannot give (a failed lookup, an incarnation it cannot name) keeps the
// last one and is asked again after managedHookPeerLookupRetry.
func (c *managedHookPeerHomeCache) recheckAccount(uid int, entry *managedHookPeerAccount, resolver unixidentity.Resolver) {
	c.mu.Lock()
	if wait := entry.recheck; wait != nil {
		c.mu.Unlock()
		<-wait
		return
	}
	if c.now().Before(entry.checked.Add(managedHookPeerAccountRecheck)) {
		c.mu.Unlock()
		return
	}
	done := make(chan struct{})
	entry.recheck = done
	c.mu.Unlock()
	defer close(done)

	account, err := unixidentity.Account{}, errManagedHookPeerNoResolver
	if resolver != nil {
		if forget, can := resolver.(interface{ ForgetUID(int) }); can {
			forget.ForgetUID(uid)
		}
		account, err = resolver.LookupUID(uid)
	}
	ok := err == nil && account.UID == uid
	incarnation, incarnationKnown := "", false
	if ok {
		incarnation, incarnationKnown = managedHookPeerAccountIncarnation(account)
		if managedHookPeerRecordChanged(account) {
			// The account's own record is newer than the listing (deleted
			// and created again, or another primary group): the listing
			// confirms nothing until the next one (GAP-0494, GAP-0392).
			managedHookPeerAccountsInvalidate()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry.recheck = nil
	now := c.now()
	if !ok || !incarnationKnown {
		entry.checked = now.Add(managedHookPeerLookupRetry - managedHookPeerAccountRecheck)
		if !ok {
			return
		}
	} else {
		entry.checked = now
	}
	entry.account = account
	entry.incarnation, entry.incarnationKnown = incarnation, incarnationKnown
}

// incarnation returns the account incarnation of uid that the last
// completed account lookup found; false when it is unknown.
func (c *managedHookPeerHomeCache) incarnation(uid int) (string, bool) {
	c.mu.Lock()
	entry := c.accounts[uid]
	c.mu.Unlock()
	if entry == nil {
		return "", false
	}
	select {
	case <-entry.ready:
		c.mu.Lock()
		defer c.mu.Unlock()
		return entry.incarnation, entry.incarnationKnown
	default:
		return "", false
	}
}

// forgetOnSpoolAccountChange checks a managed Unix UID's spool identity. The
// account database cache may still name the preceding owner of the same UID,
// name and home while the guardian has published a new SID.
func forgetOnSpoolAccountChange(cache *identityDirectoryCache, key string, now time.Time) {
	forgetOnSpoolChange(cache, key, now, false)
}

// directory returns uid's verified directory facts from the cache, waiting
// for a cold lookup up to its budget only when block is set.
func (c *managedHookPeerHomeCache) directory(uid int, block bool) (useridentity.DirectoryFacts, bool) {
	return c.directoryWithin(uid, block, identityDirectoryBudget)
}

// directoryWithin is directory with freshWait bounding a managed Mac's wait
// for a current answer.
func (c *managedHookPeerHomeCache) directoryWithin(uid int, block bool, freshWait time.Duration) (useridentity.DirectoryFacts, bool) {
	cache, key, ok := c.directoryOf(uid)
	if !ok {
		return useridentity.DirectoryFacts{}, false
	}
	if managedHookDirectoryNeedsFresh && identityFactsEnabled.Load() && managedServiceHosted.Load() {
		if !block {
			return cache.getNonblocking(key)
		}
		return cache.getFresh(key, freshWait)
	}
	return cache.get(key, block)
}

// settledDirectory returns uid's cached directory facts without waiting or
// starting more than a background refresh, and only when they are settled:
// an incomplete or settling answer (a UPN or a group not given yet) may miss
// a name that a current answer has, so it binds nothing.
func (c *managedHookPeerHomeCache) settledDirectory(uid int) (useridentity.DirectoryFacts, bool) {
	cache, key, ok := c.directoryOf(uid)
	if !ok {
		return useridentity.DirectoryFacts{}, false
	}
	facts, ok := cache.getNonblocking(key)
	if !ok || facts.ResolvedAt.IsZero() || cache.unsettled(facts) {
		return useridentity.DirectoryFacts{}, false
	}
	return facts, true
}

// directoryOf returns the cache and key of uid's directory facts after the
// checks every read makes first: the account that holds the uid now, and
// the guardian's record of it.
func (c *managedHookPeerHomeCache) directoryOf(uid int) (*identityDirectoryCache, string, bool) {
	if uid < 0 {
		return nil, "", false
	}
	key := strconv.Itoa(uid)
	c.noteHolder(uid, key)
	if !managedHookPeerAccountsConfirmed() {
		// A group fact newer than the last macOS account listing is not
		// proven: the listing that would tie the cached facts to the
		// account holding the uid now has not ended (GAP-0392, GAP-0494).
		// An assignment that needs the unproven account or group fact
		// refuses the request with that fact named.
		return nil, "", false
	}
	cache := c.directoryCache()
	forgetOnSpoolAccountChange(cache, key, time.Now())
	return cache, key, true
}

// managedHookExemptFreshWait bounds how long a managed Mac hook call waits
// for a current directory answer that confirms a possible named exemption
// (managedHookAuthorizer.exempt). It stays well inside the 2 s some hook
// clients allow a whole call (Codex SessionEnd): a slow or unavailable Open
// Directory costs the call its exemption, which then needs enrollment, not
// the call. A lookup that finishes after the wait serves the next hook
// (identityCache.getFresh).
const managedHookExemptFreshWait = 750 * time.Millisecond

// exemptIdentityDirectory returns the directory facts exempt matches uid's
// names with. cached returns settled facts already cached (settledDirectory);
// otherwise a managed Mac waits at most managedHookExemptFreshWait for a
// current answer, and other hosts read the cache as a blocking hook call does.
func exemptIdentityDirectory(uid int, cached bool) (useridentity.DirectoryFacts, bool) {
	if cached {
		return managedHookPeerHomes.settledDirectory(uid)
	}
	return managedHookPeerHomes.directoryWithin(uid, true, managedHookExemptFreshWait)
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
	cache := c.directoryCache()
	forgetOnSpoolAccountChange(cache, key, time.Now())
	if managedHookDirectoryNeedsFresh && identityFactsEnabled.Load() && managedServiceHosted.Load() {
		if facts, ok := cache.getFresh(key, identityDirectoryBudget); ok {
			return facts, nil
		}
		if _, reason, failed := cache.failing(key); failed {
			return useridentity.DirectoryFacts{}, fmt.Errorf("current directory facts for uid %s are unavailable: %s", key, reason)
		}
		return useridentity.DirectoryFacts{}, fmt.Errorf("current directory facts for uid %s did not answer within %s", key, identityDirectoryBudget)
	}
	return explainDirectoryFacts(cache, key)
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
	incarnation, incarnationKnown := c.incarnation(uid)
	holder := managedHookPeerHolder{name: account.Name, home: account.Home, stamp: managedHookPeerStamp(),
		record: managedHookPeerAccountRecord(account.Name), incarnation: incarnation}
	c.mu.Lock()
	previous, known := c.holders[uid]
	changed := known && (previous.name != holder.name || previous.home != holder.home || previous.replacedBy(holder.record) ||
		previous.reincarnated(incarnation, incarnationKnown))
	if known && !changed && holder.record == "" {
		holder.record = previous.record // a failed listing forgets no record
	}
	if known && !changed && !incarnationKnown {
		holder.incarnation = previous.incarnation // nor does a directory that does not answer
	}
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
			return hasUnnamedGroup(facts) || awaitingSpoolUPN(facts) || facts.OnlyPrimaryGroup
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

// cachedHolder returns the uid and name of the account whose cached
// directory facts were last used under name (compared without regard to
// case) or under the uid name spells. A name no holder was used under may
// still be another accepted spelling of one holder's account, which its
// cached facts confirm (cachedFactsSpell): its UPN or principal, or
// DOMAIN\name and name@domain of its own domain, so every spelling explain
// accepts finds the facts the hooks apply during an outage (GAP-0551).
//
// The account database is asked first which account holds the uid now
// (holderNow): a uid a directory handed to another account (another name,
// home, record or incarnation) gets its former holder's facts dropped, as
// its next hook call would drop them, so explain never shows them. Those
// facts were served until a hook rechecked the uid (review of r104 W2B,
// loop round 3). A spelling only the cached facts confirm (a UPN, a
// principal, DOMAIN\name or name@domain) is a name rel/1.0.4 did not take
// from them, and is served only while the account database names the
// holder and its incarnation now, the one the facts were cached for
// (confirmCachedSpelling).
func (c *managedHookPeerHomeCache) cachedHolder(name string) (int, string, bool) {
	uid, holder, err := c.cachedHolderFor(name)
	return uid, holder, err == nil
}

// errNoCachedHolder is cachedHolderFor's answer for a name no cached facts
// were used under.
var errNoCachedHolder = errors.New("no cached directory facts were used under this name")

// cachedHolderFor is cachedHolder with why it names no holder:
// errNoCachedHolder, or why the holder of the cached facts a qualified
// spelling names cannot be confirmed now.
func (c *managedHookPeerHomeCache) cachedHolderFor(name string) (int, string, error) {
	name = strings.TrimSpace(name)
	holders := c.liveHolders()
	if uid, err := strconv.Atoi(name); err == nil && strconv.Itoa(uid) == name {
		holder, ok := holders[uid]
		if !ok || holder.name == "" || c.holderChanged(uid, holder) {
			return 0, "", errNoCachedHolder
		}
		return uid, holder.name, nil
	}
	var foundUID int
	var foundName string
	for uid, holder := range holders {
		if holder.name != "" && useridentity.EqualFold(holder.name, name) {
			if foundName != "" {
				return 0, "", errNoCachedHolder
			}
			foundUID, foundName = uid, holder.name
		}
	}
	if foundName != "" {
		if c.holderChanged(foundUID, holders[foundUID]) {
			return 0, "", errNoCachedHolder
		}
		return foundUID, foundName, nil
	}
	if !useridentity.QualifiedAccountName(name) {
		return 0, "", errNoCachedHolder
	}
	for uid, holder := range holders {
		if holder.name == "" {
			continue
		}
		facts, _, served := c.directoryCache().peek(strconv.Itoa(uid))
		if !served || !cachedFactsSpell(name, holder.name, facts) {
			continue
		}
		if foundName != "" {
			return 0, "", errNoCachedHolder
		}
		foundUID, foundName = uid, holder.name
	}
	if foundName == "" {
		return 0, "", errNoCachedHolder
	}
	if err := c.confirmCachedSpelling(name, foundUID, holders[foundUID]); err != nil {
		return 0, "", err
	}
	return foundUID, foundName, nil
}

// holderNow asks the account database at once which account holds uid, and
// its account incarnation (managedHookPeerAccountIncarnation). A completed
// answer is recorded as recheckAccount records one, so the hook path
// compares its holder with it (noteHolder). ok is false when the database
// does not name the uid now.
func (c *managedHookPeerHomeCache) holderNow(uid int) (account unixidentity.Account, incarnation string, ok, incarnationKnown bool) {
	c.account(uid)
	c.mu.Lock()
	resolver, entry := c.resolver, c.accounts[uid]
	c.mu.Unlock()
	if resolver == nil {
		return unixidentity.Account{}, "", false, false
	}
	if forget, can := resolver.(interface{ ForgetUID(int) }); can {
		forget.ForgetUID(uid)
	}
	found, err := resolver.LookupUID(uid)
	if err != nil || found.UID != uid {
		return unixidentity.Account{}, "", false, false
	}
	incarnation, incarnationKnown = managedHookPeerAccountIncarnation(found)
	if entry != nil {
		select {
		case <-entry.ready:
			c.mu.Lock()
			entry.account, entry.ok, entry.notFound = found, true, false
			entry.incarnation, entry.incarnationKnown = incarnation, incarnationKnown
			entry.checked = c.now()
			c.mu.Unlock()
		default:
		}
	}
	return found, incarnation, true, incarnationKnown
}

// holderChanged reports whether the account database names another account
// than holder for uid now (holderNow), and then drops holder and the facts
// cached for it, as noteHolder does. A database that does not answer
// changes nothing: the facts are served through an outage.
func (c *managedHookPeerHomeCache) holderChanged(uid int, holder managedHookPeerHolder) bool {
	account, incarnation, ok, known := c.holderNow(uid)
	if !ok || !holderReplaced(holder, account, incarnation, known) {
		return false
	}
	c.dropHolder(uid, holder)
	return true
}

// holderReplaced reports whether account, of incarnation (known), the
// account that holds the uid now, is another than holder.
func holderReplaced(holder managedHookPeerHolder, account unixidentity.Account, incarnation string, known bool) bool {
	return account.Name != holder.name || account.Home != holder.home ||
		holder.replacedBy(managedHookPeerAccountRecord(account.Name)) || holder.reincarnated(incarnation, known)
}

// dropHolder forgets holder as uid's and the facts cached for it.
func (c *managedHookPeerHomeCache) dropHolder(uid int, holder managedHookPeerHolder) {
	key := strconv.Itoa(uid)
	c.mu.Lock()
	if current, known := c.holders[uid]; known && current == holder {
		delete(c.holders, uid)
	}
	c.mu.Unlock()
	c.directoryCache().forget(key)
}

// confirmCachedSpelling reports, with nil, that the account that holds uid
// now is holder, the account whose cached facts spell name: the account
// database names it with the name and home it had, and the incarnation the
// facts were cached for. Otherwise the facts are not shown for a spelling
// only they confirm: a uid and its UPN given to other accounts showed the
// former holder's groups and profile under the reused UPN (review of r104
// W2B, loop round 3). A holder replaced now is dropped (errNoCachedHolder).
func (c *managedHookPeerHomeCache) confirmCachedSpelling(name string, uid int, holder managedHookPeerHolder) error {
	account, incarnation, ok, known := c.holderNow(uid)
	switch {
	case !ok:
		return fmt.Errorf("the gateway has directory facts cached for uid %d that spell %q, but the account database does not name "+
			"the account that holds uid %d now, so they are not shown for that spelling; name the account by its uid or its account "+
			"name, or try again when the directory answers", uid, name, uid)
	case holderReplaced(holder, account, incarnation, known):
		c.dropHolder(uid, holder)
		return errNoCachedHolder
	case !known || holder.incarnation == "":
		return fmt.Errorf("the gateway has directory facts cached for uid %d that spell %q, but cannot confirm that the account that "+
			"holds uid %d now is the one they were cached for (the directory does not name its account incarnation), so they are "+
			"not shown for that spelling; name the account by its uid or its account name, or try again when the directory answers",
			uid, name, uid)
	}
	return nil
}

// cachedFactsSpell reports whether name, a qualified account name, is a
// spelling of the account held as holder with facts: its UPN or principal,
// or its bare name qualified with a domain its facts name (DNS domain,
// NetBIOS domain or realm).
func cachedFactsSpell(name, holder string, facts useridentity.DirectoryFacts) bool {
	for _, principal := range []string{facts.UPN, facts.Principal} {
		if principal != "" && useridentity.EqualFold(principal, name) {
			return true
		}
	}
	bare, domain := useridentity.SplitQualifiedName(name)
	holderBare, _ := useridentity.SplitQualifiedName(holder)
	if domain == "" || !useridentity.EqualFold(bare, holderBare) {
		return false
	}
	for _, own := range []string{facts.Domain, facts.AccountDomain, facts.Realm} {
		if own != "" && useridentity.EqualFold(own, domain) {
			return true
		}
	}
	return false
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
	if !ManagedEnterpriseActive() {
		managedHookPeerAccountsRefresh()
	}
	stamp := managedHookPeerStamp()
	for uid, holder := range holders {
		facts, _, served := c.directoryCache().peek(strconv.Itoa(uid))
		forgetFacts := false
		if served && stamp != "" && stamp != holder.stamp {
			account, ok := c.account(uid)
			record, incarnation, incarnationKnown := "", "", false
			if ok {
				record = managedHookPeerAccountRecord(account.Name)
				incarnation, incarnationKnown = c.incarnation(uid)
			}
			switch {
			case ok && (account.Name != holder.name || account.Home != holder.home || holder.replacedBy(record) ||
				holder.reincarnated(incarnation, incarnationKnown)):
				served, forgetFacts = false, true
			case !ok && facts.Directory == useridentity.DirectoryLocal:
				c.mu.Lock()
				entry := c.accounts[uid]
				missing := entry != nil && entry.notFound
				c.mu.Unlock()
				served, forgetFacts = !missing, missing
			case ok:
				holder.stamp = stamp
				if record != "" {
					holder.record = record
				}
				if incarnationKnown {
					holder.incarnation = incarnation
				}
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

// lookupName returns the caller's sanitized account name, or "".
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

// accountToken names the account that holds uid now where its name, uid and
// home cannot: its account incarnation (Linux), or else its listed record
// (macOS). false when neither is known.
func (c *managedHookPeerHomeCache) accountToken(uid int) (string, bool) {
	account, ok := c.account(uid)
	if !ok {
		return "", false
	}
	if incarnation, known := c.incarnation(uid); known && validAccountToken(incarnation) {
		return incarnation, true
	}
	if record := managedHookPeerAccountRecord(account.Name); record != "" && validAccountToken("record:"+record) {
		return "record:" + record, true
	}
	return "", false
}

// agentIncarnation is the account incarnation uid's agent identities are
// keyed on besides the account name (agentidentity.Inputs.Incarnation): ""
// while the account that holds the uid is the first one this gateway saw
// hold it, so the agent identities it had before keep their IDs, and that
// account's token while another one holds it. One bare name, uid and home in
// two domains, or an account deleted and created again, then derive other
// IDs (review of GAP-0947). While the token cannot be told (a directory
// outage) the last one stands, as the last name does. The tokens are kept
// across restarts with the homes.
//
// After an upgrade from a build that kept no token, the account that holds
// a uid the older build saw when this gateway first sees it is not proved
// to be the account the older build saw: another domain's account of the
// same name and home may have taken the uid over in between, and it got
// the former account's agent IDs, match.agents profile and ledger history
// (review of GAP-0947, loop 3). It keeps the IDs of before only when its
// token shows continuity (legacyContinuity); otherwise the base is
// agentIncarnationUnproven, every account derives its own IDs, and the rows
// of before are retired. A uid's 1.0.3 agents entries are bound by the
// upgrade's migration map instead (legacyAgentOwnerBound).
func (c *managedHookPeerHomeCache) agentIncarnation(uid int) string {
	token, known := c.accountToken(uid)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadHomesLocked()
	tokens, seen := c.incarnations[uid]
	switch {
	case known && (!seen || tokens.last != token):
		if !seen {
			if len(c.incarnations) >= managedHookPeerHomesMax {
				return ""
			}
			tokens.base = token
			if c.legacy[uid] && !legacyContinuity(uid, token) {
				tokens.base = agentIncarnationUnproven
			}
			delete(c.legacy, uid)
		}
		tokens.last = token
		if c.incarnations == nil {
			c.incarnations = make(map[int]managedHookPeerIncarnations)
		}
		c.incarnations[uid] = tokens
		c.saveHomesLocked()
	case !known:
		token = tokens.last
	}
	if token == "" || token == tokens.base {
		return ""
	}
	return token
}

// legacyContinuity reports whether token, the first account token seen for
// a uid an older build saw, shows that its account is the one the older
// build saw. A token that does not tell accounts of one name and home apart
// (files, sss, nss:<service>) cannot differ from the older account's either,
// so this build would give both the same IDs: it shows continuity. A SID
// does when uid is the one SSSD's default id mapping gives it
// (sssdDefaultIDMapping): the uid then belongs to that SID, and an account
// of another SID never held it. Only the uid of the SID's own domain slice
// counts: a uid that matched the RID only modulo the range size (an
// RFC 2307 uid 201105 for RID 1105 with ldap_id_mapping off) was taken for
// a mapped one, and an account that replaced the former holder kept its
// agent IDs and match.agents profile (review of GAP-0947, loop 4). Any
// other SID (an RFC 2307 uid, winbind, custom id-mapping ranges) or a
// listed record (macOS) does not.
func legacyContinuity(uid int, token string) bool {
	sid, isSID := strings.CutPrefix(token, "sid:")
	if !isSID {
		return !strings.HasPrefix(token, "record:")
	}
	mapped, ok := sssdDefaultIDMapping(sid)
	return ok && int64(uid) == mapped
}

// SSSD's default id mapping (sssd-ad, ldap_idmap_range_min 200000,
// ldap_idmap_range_max 2000200000, ldap_idmap_range_size 200000): a domain
// gets the slice murmurhash3 of its SID (seed 0xdeadbeef) names, modulo the
// number of slices, and an account the uid range min + slice * size + RID.
const (
	sssdIDMapRangeMin  = 200000
	sssdIDMapRangeMax  = 2000200000
	sssdIDMapRangeSize = 200000
	sssdIDMapSeed      = 0xdeadbeef
)

// sssdDefaultIDMapping is the uid SSSD's default id mapping gives sid, the
// primary slice of its domain. ok is false for a SID it does not map so
// (no RID, or a RID past the primary slice).
func sssdDefaultIDMapping(sid string) (int64, bool) {
	i := strings.LastIndexByte(sid, '-')
	if i <= 0 || !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-21-") {
		return 0, false
	}
	rid, err := strconv.ParseInt(sid[i+1:], 10, 64)
	if err != nil || rid < 0 || rid >= sssdIDMapRangeSize {
		return 0, false
	}
	sliceCount := uint32((sssdIDMapRangeMax - sssdIDMapRangeMin) / sssdIDMapRangeSize)
	slice := int64(murmurHash3x86_32([]byte(strings.ToUpper(sid[:i])), sssdIDMapSeed) % sliceCount)
	return sssdIDMapRangeMin + slice*sssdIDMapRangeSize + rid, true
}

// murmurHash3x86_32 is MurmurHash3 (x86, 32 bits), the hash SSSD's
// sss_idmap picks a domain's slice with.
func murmurHash3x86_32(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	blocks := len(data) / 4
	for i := 0; i < blocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[blocks*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// rowToken is the account token an agent identity row of uid is recorded
// with: the token of the account that holds the uid now, or while that
// cannot be told the last one (agentIncarnation). "" when none was ever
// known.
func (c *managedHookPeerHomeCache) rowToken(uid int) string {
	if token, known := c.accountToken(uid); known {
		return token
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadHomesLocked()
	return c.incarnations[uid].last
}

// holderHistory returns the last account token of uid and whether another
// account than its holder is known to have held it, or the first holder
// this gateway saw is not proved to be the one older builds saw: a row of
// the uid that names no token is then not taken for the holder's.
func (c *managedHookPeerHomeCache) holderHistory(uid int) (last string, changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadHomesLocked()
	tokens, seen := c.incarnations[uid]
	if !seen {
		return "", false
	}
	return tokens.last, tokens.base != tokens.last || tokens.base == agentIncarnationUnproven
}

// validAccountToken bounds an account token kept or read back.
func validAccountToken(token string) bool {
	if token == "" || len(token) > 256 {
		return false
	}
	for _, r := range token {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
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
