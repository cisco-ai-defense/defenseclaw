// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
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
	// settling, when set, marks an answer that may still miss part of the
	// account's groups right after a directory outage (a bound Mac's Open
	// Directory, GAP-0517): it is served like an incomplete one but refreshed
	// as soon as a lookup may retry, so the account's profile comes back
	// within one retry cycle of the directory answering in full.
	settling func(T) bool
	// logf, when set, reports a key's first failure and its recovery.
	logf func(format string, args ...any)
	// maxAge, when set, is the age past which facts are no longer served.
	maxAge time.Duration
	// gone, when set, marks a lookup error in which the directory answered
	// that the account does not exist.
	gone        func(error) bool
	confirmGone bool
	// trustedUntil, when set, is when the inputs of a lookup of key started
	// at now stop being trusted (zero: no bound beyond maxAge): the
	// guardian's identity record, trusted identitySpoolMaxAge from when it
	// was written. Facts built from it are not served past that, also inside
	// the TTL (GAP-1268).
	trustedUntil func(key string, now time.Time) time.Time
	// describe, when set, names the identity source and directory of an
	// answer, for the per-source ages /health reports (identity_health.go).
	describe func(T) (source, directory string)

	mu      sync.Mutex
	entries map[string]*identityCacheEntry[T]
	// answeredAt is when a lookup of any key last succeeded.
	answeredAt time.Time
	// answered is when each (source, directory) pair describe names last
	// answered a lookup, at most identitySourcesMax pairs.
	answered map[[2]string]time.Time
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
	// trustedUntil is when the inputs of the served facts stop being
	// trusted (identityCache.trustedUntil); zero for no bound.
	trustedUntil time.Time
	// staleBefore makes the facts due for a refresh that a blocking request
	// waits for, when they were fetched before it (refreshSoon).
	staleBefore time.Time
}

func newIdentityDirectoryCache(resolve func(string) (useridentity.DirectoryFacts, error)) *identityDirectoryCache {
	cache := newIdentityCache(resolve)
	cache.maxAge = identityDirectoryMaxAge
	cache.gone = definitiveMissingAccount
	cache.confirmGone = reliableMissingAccountConfirmation()
	cache.trustedUntil = identitySpoolTrustedUntil
	cache.describe = func(facts useridentity.DirectoryFacts) (string, string) { return facts.Source, string(facts.Directory) }
	cache.logf = func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[identity] "+format+"\n", args...)
	}
	return cache
}

// identitySpoolTrustedUntil is when the guardian's current identity record
// of key stops being trusted: identitySpoolMaxAge after it was written.
// Facts merged from a record read at minute 59 were cached for the full TTL,
// so its UPN and groups applied until minute 74 (GAP-1268). Zero without a
// current record. It is read before the lookup, so a record the guardian
// rewrites during the lookup only makes the bound earlier.
func identitySpoolTrustedUntil(key string, now time.Time) time.Time {
	record, ok := readIdentitySpoolFacts(key, now)
	if !ok {
		return time.Time{}
	}
	return record.UpdatedAt.Add(identitySpoolMaxAge)
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
	c.dropAgedLocked(key, entry, now)
	age := now.Sub(entry.fetchedAt)
	invalidated := entry.ok && (entry.fetchedAt.Before(c.staleBefore) || entry.fetchedAt.Before(entry.staleBefore))
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
		incomplete := c.incomplete != nil && c.incomplete(facts) || c.settling != nil && c.settling(facts)
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
		// The lookup dropped the facts: nothing confirms them any more
		// (identityFactsUnconfirmedError), so this request gets none either
		// (GAP-0191).
		return zero, false
	}
	wait := entry.inflight
	c.mu.Unlock()
	if (!block && !first) || wait == nil {
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

// dropAgedLocked stops serving entry's facts once they are maxAge old, or
// once the inputs they were built from are no longer trusted
// (entry.trustedUntil); the next request then looks the account up again.
func (c *identityCache[T]) dropAgedLocked(key string, entry *identityCacheEntry[T], now time.Time) {
	if !entry.ok {
		return
	}
	var none T
	if !entry.trustedUntil.IsZero() && !now.Before(entry.trustedUntil) {
		entry.facts, entry.ok, entry.trustedUntil = none, false, time.Time{}
		// Look again at once: the facts did not fail, their record aged out.
		entry.nextAttempt = time.Time{}
		return
	}
	age := now.Sub(entry.fetchedAt)
	if c.maxAge <= 0 || age < c.maxAge {
		return
	}
	entry.facts, entry.ok = none, false
	if c.logf != nil {
		c.logf("directory facts for %s are %s old and no longer used; the account gets the default guardrail profile "+
			"(default_lookup_failed) until a lookup succeeds", key, age.Round(time.Minute))
	}
}

// What `guardrail profile explain --user` reports.
//
// Explain answers from this cache, the one hook calls read, after a lookup
// of its own. It used to resolve the account through the operating system
// on a path of its own, so the oracle and the hooks disagreed exactly when
// it mattered: a lookup that failed for explain (an SSSD responder slow to
// answer right after a configuration apply, a domain controller away) gave
// default_lookup_failed while hook calls kept the group profile of the facts
// they had cached, and two explain calls seconds apart gave two profiles for
// one account and one configuration (GAP-0307, GAP-0361, GAP-0363,
// GAP-0383). Now a lookup explain starts refreshes the facts hooks use, and
// a lookup that fails leaves explain with what hooks keep: the facts cached
// before it, with their age (explainCacheView), or none.

const (
	// identityExplainFresh is how recent a lookup's outcome must be for
	// explain to reuse it instead of starting another: the spelling check
	// and the facts of one explain call, and calls seconds apart, share one
	// lookup.
	identityExplainFresh = 5 * time.Second
	// identityExplainFreshIncomplete is the same for an outcome whose facts
	// the cache itself calls incomplete or settling (an account whose
	// guardian record or UPN has not arrived yet): explain looks again at
	// once instead of repeating them for identityExplainFresh. Right after a
	// restart the startup check had resolved the account just before the
	// administrator's first explain, which repeated its incomplete facts, and
	// a users entry written as a UPN or in upper case then selected nobody
	// for about eight seconds (GAP-0575).
	identityExplainFreshIncomplete = time.Second
	// identityExplainWait bounds how long explain waits for its lookup. The
	// lookup goes on within its own bound and its answer is cached; the CLI
	// waits 35 s for the whole answer.
	identityExplainWait = 12 * time.Second
)

// identityExplainAnswer is what the cache holds for a key after explain's
// lookup.
type identityExplainAnswer[T any] struct {
	facts     T
	fetchedAt time.Time
	ok        bool
	// failedSince and reason are set while the key's lookups fail; facts,
	// when ok, are then the ones cached before the failure.
	failedSince time.Time
	reason      string
	// running is set when the lookup had not finished within the wait.
	running bool
}

// explain refreshes key's facts unless a lookup of it ran in the last
// identityExplainFresh or is running, waits for that lookup at most wait,
// and returns what hook calls of key get from then on: the new facts, the
// facts cached before a failed lookup (within maxAge), or none.
func (c *identityCache[T]) explain(key string, wait time.Duration) identityExplainAnswer[T] {
	var answer identityExplainAnswer[T]
	if c == nil || key == "" || c.resolve == nil {
		return answer
	}
	c.mu.Lock()
	now := c.now()
	entry := c.entries[key]
	if entry == nil {
		if len(c.entries) >= identityDirectoryMax {
			c.evictLocked()
		}
		entry = &identityCacheEntry[T]{}
		c.entries[key] = entry
	}
	c.dropAgedLocked(key, entry, now)
	last := entry.fetchedAt
	if entry.lastFailedAt.After(last) {
		last = entry.lastFailedAt
	}
	fresh := identityExplainFresh
	if entry.ok && c.unsettled(entry.facts) {
		fresh = identityExplainFreshIncomplete
	}
	if entry.inflight == nil && (last.IsZero() || now.Sub(last) >= fresh) {
		c.refreshLocked(key, entry)
	}
	done := entry.inflight
	c.mu.Unlock()
	if done != nil {
		timer := time.NewTimer(wait)
		select {
		case <-done:
		case <-timer.C:
			answer.running = true
		}
		timer.Stop()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	answer.facts, answer.fetchedAt, answer.ok = entry.facts, entry.fetchedAt, entry.ok
	answer.failedSince, answer.reason = entry.failedSince, entry.lastErr
	return answer
}

// explainDirectoryFacts returns the directory facts a hook call of key gets
// after explain's lookup (identityCache.explain), or why it gets none.
func explainDirectoryFacts(cache *identityDirectoryCache, key string) (useridentity.DirectoryFacts, error) {
	answer := cache.explain(key, identityExplainWait)
	switch {
	case answer.ok:
		return answer.facts, nil
	case answer.reason != "":
		return useridentity.DirectoryFacts{}, errors.New(answer.reason)
	case answer.running:
		return useridentity.DirectoryFacts{}, fmt.Errorf("the directory lookup for %s has not finished after %s; "+
			"hook calls get no directory facts for it until it does", key, identityExplainWait)
	default:
		return useridentity.DirectoryFacts{}, fmt.Errorf("the directory lookup for %s returned no facts", key)
	}
}

// refreshFailing reports a key whose latest lookups fail while its requests
// still use facts cached before the failure.
func (c *identityCache[T]) refreshFailing(key string) (since time.Time, reason string, ok bool) {
	if c == nil {
		return time.Time{}, "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	if entry == nil || !entry.ok || entry.failedSince.IsZero() {
		return time.Time{}, "", false
	}
	return entry.failedSince, entry.lastErr, true
}

// unsettled reports facts the cache serves but expects to replace soon: an
// incomplete answer, one built from stale inputs, or one resolved while a
// directory outage settles.
func (c *identityCache[T]) unsettled(facts T) bool {
	return c.partial != nil && c.partial(facts) || c.settling != nil && c.settling(facts) ||
		c.incomplete != nil && c.incomplete(facts)
}

// lifetime is how long facts are served before a refresh: the full TTL,
// identityDirectoryIncompleteTTL for an answer the resolver calls
// incomplete, or identityDirectoryRetry for one built from stale inputs or
// resolved while a directory outage settles.
func (c *identityCache[T]) lifetime(facts T) time.Duration {
	switch {
	case c == nil:
		return identityDirectoryTTL
	case c.partial != nil && c.partial(facts), c.settling != nil && c.settling(facts):
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
// starting a lookup or waiting for one. Facts a request would no longer be
// served (past maxAge, or built from a guardian record no longer trusted)
// are dropped first, as get drops them: explain served them by name during
// an outage while the hooks of the account had moved to
// default_lookup_failed (GAP-0529).
func (c *identityCache[T]) peek(key string) (T, time.Time, bool) {
	var zero T
	if c == nil {
		return zero, time.Time{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	if entry == nil {
		return zero, time.Time{}, false
	}
	c.dropAgedLocked(key, entry, c.now())
	if !entry.ok {
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

// refreshSoon makes key's cached answer due for a refresh that a blocking
// request waits for within the budget, as invalidate does for every key.
// Unlike forget it keeps the answer: when the refresh fails or does not
// finish in time, the facts are served as before. News that only adds to
// the facts (a guardian record that names the account's UPN, or one written
// after the facts were resolved without one) never costs a request the
// facts it had, so a slow directory cannot send it to a weaker
// default_lookup_failed profile (loop round 3).
func (c *identityCache[T]) refreshSoon(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry := c.entries[key]; entry != nil && entry.ok {
		entry.staleBefore = c.now()
		entry.nextAttempt = time.Time{}
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

// identityFactsUnconfirmedError is a failed lookup that also says nothing
// confirms the facts cached before it any more, so they are dropped at once
// instead of at maxAge: a bound Mac's Open Directory answering without an
// account's domain groups once the guardian has not confirmed the account for
// an hour (openDirectoryGroupsUnavailable).
type identityFactsUnconfirmedError struct{ err error }

func (e *identityFactsUnconfirmedError) Error() string { return e.err.Error() }
func (e *identityFactsUnconfirmedError) Unwrap() error { return e.err }

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
	trustedUntil := c.trustedUntil
	started := c.now()
	go func() {
		var until time.Time
		if trustedUntil != nil {
			until = trustedUntil(key, started)
		}
		facts, err := c.resolve(key)
		c.mu.Lock()
		now := c.now()
		var unconfirmed *identityFactsUnconfirmedError
		switch {
		case err == nil:
			entry.facts, entry.ok, entry.fetchedAt, entry.trustedUntil = facts, true, now, until
		case entry.ok && errors.As(err, &unconfirmed):
			var none T
			entry.facts, entry.ok = none, false
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
		c.noteAnsweredLocked(entry.facts, now)
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
