// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Directory facts on the hot path.
//
// Hook calls read only memory. A cached answer is served even when it is
// older than identityDirectoryTTL, and one background refresh replaces it
// (stale-while-revalidate). A key never seen before starts one shared
// lookup (singleflight), and the request that started it waits for it at
// most identityDirectoryBudget, so an account's first record after a
// gateway start (an upgrade, a restart) carries its verified facts rather
// than falling back to claimed ones. Other requests wait for an unresolved
// key only when asked to block; otherwise they get no facts this time and a
// later request finds them cached. A failed lookup is retried no sooner than
// identityDirectoryRetry.
//
// Callers block when a guardrail profile assignment selects by user or
// group, so the budget covers a cold SSSD or Active Directory lookup (often
// one to two seconds) and every request still gets its group profile while
// the first lookup is in flight or after it failed. A lookup slower than
// that selects the default profile with match default_lookup_failed; the
// budget stays well inside the hook request timeout.
//
// The first failure of a key's lookup, and its recovery, are logged once
// (logf) with the resolver's own reason, so an account that cannot resolve at
// all (in more groups than DefenseClaw names, a directory that never answers)
// leaves a line in the gateway log instead of only a default_lookup_failed on
// every record (GAP-0124).
//
// Facts whose refreshes keep failing are not served forever: past maxAge
// (identityDirectoryMaxAge for directory facts, four times the TTL) they are
// dropped, and directory-dependent assignments use default_lookup_failed
// until a lookup succeeds. Without the bound a user removed from the directory kept the
// profile of the group they had left, and a user added to one stayed on the
// default, for as long as the outage lasted (GAP-0145). health reports how many
// accounts are failing and how stale their facts are, for doctor and status.
//
// A resolver can call its own answer incomplete (an AD account whose UPN a
// slow domain controller has not given yet). That answer is served, but is
// refreshed after identityDirectoryIncompleteTTL, not after the full TTL.

const (
	identityDirectoryTTL    = 15 * time.Minute
	identityDirectoryBudget = 2 * time.Second
	identityDirectoryRetry  = 15 * time.Second
	identityDirectoryMax    = 4096
	// identityDirectoryIncompleteTTL is how long an incomplete answer lasts.
	identityDirectoryIncompleteTTL = 2 * time.Minute
	// identityDirectoryMaxAge is the age past which directory facts are no
	// longer served, even when their refresh keeps failing. It is also how long
	// the guardian's identity spool record is trusted (identitySpoolMaxAge).
	identityDirectoryMaxAge = 4 * identityDirectoryTTL
)

// identityDirectoryCache caches directory facts per uid or SID.
type identityDirectoryCache = identityCache[useridentity.DirectoryFacts]

// identityCache is the stale-while-revalidate, singleflight cache behind
// the directory and session lookups.
type identityCache[T any] struct {
	resolve func(key string) (T, error)
	now     func() time.Time
	// incomplete, when set, marks an answer to refresh after
	// identityDirectoryIncompleteTTL.
	incomplete func(T) bool
	// partial, when set, marks an answer built from stale inputs (Windows
	// groups from an account's last signed-in session, GAP-0243): it is
	// refreshed as soon as a lookup may retry, so a sign-in shows within
	// about one enumerator cycle.
	partial func(T) bool
	// logf, when set, reports a key's first failure and its recovery.
	logf func(format string, args ...any)
	// maxAge, when set, is the age past which facts are no longer served.
	maxAge time.Duration
	// gone, when set, marks a lookup error in which the directory answered
	// that the account does not exist.
	gone        func(error) bool
	confirmGone bool

	mu      sync.Mutex
	entries map[string]*identityCacheEntry[T]
	// answeredAt is when a lookup of any key last succeeded.
	answeredAt time.Time
	// staleBefore makes facts fetched before it due for a refresh that a
	// blocking request waits for (invalidate).
	staleBefore time.Time
}

type identityCacheEntry[T any] struct {
	facts       T
	ok          bool
	fetchedAt   time.Time
	nextAttempt time.Time
	inflight    chan struct{}
	// failedSince is when the key's lookup began failing (zero while it
	// succeeds) and lastErr the reason last logged for it.
	failedSince time.Time
	lastErr     string
	// lastFailedAt is when a lookup of the key last failed.
	lastFailedAt time.Time
	// gone is set when the last failure said the account does not exist.
	gone bool
}

func newIdentityDirectoryCache(resolve func(string) (useridentity.DirectoryFacts, error)) *identityDirectoryCache {
	cache := newIdentityCache(resolve)
	cache.maxAge = identityDirectoryMaxAge
	cache.gone = definitiveMissingAccount
	cache.confirmGone = reliableMissingAccountConfirmation()
	cache.logf = func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[identity] "+format+"\n", args...)
	}
	return cache
}

func newIdentityCache[T any](resolve func(string) (T, error)) *identityCache[T] {
	return &identityCache[T]{resolve: resolve, now: time.Now, entries: map[string]*identityCacheEntry[T]{}}
}

// get returns key's facts. ok is false when nothing is cached yet and the
// lookup did not finish within the budget (or, after the first request for
// key, the caller did not ask to block).
func (c *identityCache[T]) get(key string, block bool) (T, bool) {
	var zero T
	if c == nil || key == "" || c.resolve == nil {
		return zero, false
	}
	c.mu.Lock()
	now := c.now()
	entry := c.entries[key]
	first := entry == nil
	if first {
		if len(c.entries) >= identityDirectoryMax {
			c.evictLocked()
		}
		entry = &identityCacheEntry[T]{}
		c.entries[key] = entry
	}
	age := now.Sub(entry.fetchedAt)
	if entry.ok && c.maxAge > 0 && age >= c.maxAge {
		var none T
		entry.facts, entry.ok = none, false
		if c.logf != nil {
			c.logf("directory facts for %s are %s old and no longer used; the account gets the default guardrail profile "+
				"(default_lookup_failed) until a lookup succeeds", key, age.Round(time.Minute))
		}
	}
	invalidated := entry.ok && entry.fetchedAt.Before(c.staleBefore)
	expired := age >= c.lifetime(entry.facts) || invalidated
	if (!entry.ok || expired) && entry.inflight == nil && !now.Before(entry.nextAttempt) {
		c.refreshLocked(key, entry)
	}
	if entry.ok {
		facts, wait, fetchedAt := entry.facts, entry.inflight, entry.fetchedAt
		// An incomplete answer past its lifetime (a group no name answered
		// for, as a directory outage leaves) is replaced before a blocking
		// caller uses it again, so a group that answers again applies at the
		// next request rather than the one after (GAP-0326). Expired
		// partial groups also wait: old memberships can select a lenient profile.
		partial := c.partial != nil && c.partial(facts)
		incomplete := c.incomplete != nil && c.incomplete(facts)
		if !block || !expired || (!partial && !incomplete && !invalidated) {
			c.mu.Unlock()
			return facts, true
		}
		if wait == nil {
			c.mu.Unlock()
			if partial {
				return zero, false
			}
			return facts, true
		}
		c.mu.Unlock()
		timer := time.NewTimer(identityDirectoryBudget)
		defer timer.Stop()
		select {
		case <-wait:
		case <-timer.C:
			if partial {
				return zero, false
			}
			return facts, true
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if partial && !entry.fetchedAt.After(fetchedAt) {
			return zero, false
		}
		if entry.ok {
			return entry.facts, true
		}
		return facts, true
	}
	wait := entry.inflight
	c.mu.Unlock()
	if !(block || first) || wait == nil {
		return zero, false
	}
	timer := time.NewTimer(identityDirectoryBudget)
	defer timer.Stop()
	select {
	case <-wait:
	case <-timer.C:
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return entry.facts, entry.ok
}

// lifetime is how long facts are served before a refresh: the full TTL,
// identityDirectoryIncompleteTTL for an answer the resolver calls
// incomplete, or identityDirectoryRetry for one built from stale inputs.
func (c *identityCache[T]) lifetime(facts T) time.Duration {
	switch {
	case c == nil:
		return identityDirectoryTTL
	case c.partial != nil && c.partial(facts):
		return identityDirectoryRetry
	case c.incomplete != nil && c.incomplete(facts):
		return identityDirectoryIncompleteTTL
	default:
		return identityDirectoryTTL
	}
}

// failing reports a key whose lookups fail and that has no facts to serve:
// its requests get default_lookup_failed until a lookup succeeds. reason is
// the resolver's own text for the failure.
func (c *identityCache[T]) failing(key string) (since time.Time, reason string, ok bool) {
	if c == nil {
		return time.Time{}, "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	if entry == nil || entry.ok || entry.failedSince.IsZero() {
		return time.Time{}, "", false
	}
	return entry.failedSince, entry.lastErr, true
}

// peek returns key's cached facts and when they were fetched, without
// starting a lookup or waiting for one.
func (c *identityCache[T]) peek(key string) (T, time.Time, bool) {
	var zero T
	if c == nil {
		return zero, time.Time{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	if entry == nil || !entry.ok {
		return zero, time.Time{}, false
	}
	return entry.facts, entry.fetchedAt, true
}

// invalidate makes every cached answer due for a refresh. A pushed profile
// assignment that selects by group applied only once the facts cached before
// the push expired, up to 15 minutes later, while profile-explain already
// showed the new profile (GAP-1036). A blocking request now waits for the
// refresh (within the budget); facts stay while the directory is down, as
// their age still counts from when they were fetched.
func (c *identityCache[T]) invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.staleBefore = c.now()
	for _, entry := range c.entries {
		if entry.ok {
			entry.nextAttempt = time.Time{}
		}
	}
}

// forget drops key's entry, so the next get resolves it afresh. A lookup in
// flight finishes on the dropped entry.
func (c *identityCache[T]) forget(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// forgetAll drops every entry, so each key resolves afresh.
func (c *identityCache[T]) forgetAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	clear(c.entries)
	c.mu.Unlock()
}

func (c *identityCache[T]) refreshLocked(key string, entry *identityCacheEntry[T]) {
	done := make(chan struct{})
	entry.inflight = done
	go func() {
		facts, err := c.resolve(key)
		c.mu.Lock()
		now := c.now()
		if err == nil {
			entry.facts, entry.ok, entry.fetchedAt = facts, true, now
		}
		entry.nextAttempt = now.Add(identityDirectoryRetry)
		entry.inflight = nil
		note := c.noteResultLocked(key, entry, err, now)
		c.mu.Unlock()
		if note != "" && c.logf != nil {
			c.logf("%s", note)
		}
		close(done)
	}()
}

// noteResultLocked records a lookup's outcome on entry and returns the line to
// log: the first failure of the key (or a failure with another reason), and
// its recovery. A key that keeps failing for the same reason logs nothing more.
func (c *identityCache[T]) noteResultLocked(key string, entry *identityCacheEntry[T], err error, now time.Time) string {
	if err == nil {
		c.answeredAt = now
		entry.gone = false
		if entry.failedSince.IsZero() {
			return ""
		}
		down := now.Sub(entry.failedSince).Round(time.Second)
		entry.failedSince, entry.lastErr = time.Time{}, ""
		return fmt.Sprintf("directory lookup for %s works again after %s", key, down)
	}
	entry.lastFailedAt = now
	entry.gone = c.gone != nil && c.gone(err)
	reason := err.Error()
	if len(reason) > 300 {
		reason = reason[:300] + "..."
	}
	if !entry.failedSince.IsZero() && entry.lastErr == reason {
		return ""
	}
	if entry.failedSince.IsZero() {
		entry.failedSince = now
	}
	entry.lastErr = reason
	keeps := "directory-dependent assignments use the default guardrail profile (default_lookup_failed) until a lookup succeeds"
	if entry.ok && c.maxAge > 0 {
		keeps = fmt.Sprintf("the account keeps its last facts for at most %s, then directory-dependent assignments use the default guardrail "+
			"profile (default_lookup_failed) until a lookup succeeds", c.maxAge)
	}
	return fmt.Sprintf("directory lookup for %s failed: %s; %s", key, reason, keeps)
}

// evictLocked drops the oldest settled entry.
func (c *identityCache[T]) evictLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, entry := range c.entries {
		if entry.inflight != nil {
			continue
		}
		if oldestKey == "" || entry.fetchedAt.Before(oldest) {
			oldestKey, oldest = key, entry.fetchedAt
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// identityCacheHealth summarises the lookups that failed in the last TTL.
type identityCacheHealth struct {
	// Failing counts accounts whose latest lookup failed within the TTL;
	// Since is the earliest of their first failures and LastError the reason
	// recorded for that one.
	Failing   int
	Since     time.Time
	LastError string
	// Stale counts the failing accounts still served facts older than the TTL,
	// and OldestAge is the age of the oldest of them.
	Stale     int
	OldestAge time.Duration
	// Accounts are the keys (uid or SID) of the failing accounts, sorted, at
	// most identityHealthMaxAccounts of them.
	Accounts []string
}

// identityHealthMaxAccounts bounds identityCacheHealth.Accounts.
const identityHealthMaxAccounts = 10

// health reports the failing accounts. An idle account whose last failure is
// older than the TTL is not counted: nothing retries it until it is used.
func (c *identityCache[T]) health() identityCacheHealth {
	var h identityCacheHealth
	if c == nil {
		return h
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for key, entry := range c.entries {
		if entry.failedSince.IsZero() || now.Sub(entry.lastFailedAt) >= identityDirectoryTTL {
			continue
		}
		if c.confirmGone && entry.gone && c.answeredAt.After(entry.lastFailedAt) {
			// On a backend where another answer confirms this absence, the
			// account is gone and the directory is not failing (GAP-0696).
			continue
		}
		h.Failing++
		h.Accounts = append(h.Accounts, key)
		if h.Since.IsZero() || entry.failedSince.Before(h.Since) {
			h.Since, h.LastError = entry.failedSince, entry.lastErr
		}
		if age := now.Sub(entry.fetchedAt); entry.ok && age >= identityDirectoryTTL {
			h.Stale++
			h.OldestAge = max(h.OldestAge, age)
		}
	}
	sort.Strings(h.Accounts)
	if len(h.Accounts) > identityHealthMaxAccounts {
		h.Accounts = h.Accounts[:identityHealthMaxAccounts]
	}
	return h
}
