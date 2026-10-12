// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// oracleTestCache is a directory cache on a clock the test moves, whose
// resolver answers groups or err.
type oracleTestCache struct {
	cache *identityDirectoryCache
	calls atomic.Int32
	mu    sync.Mutex
	now   time.Time
	group string
	err   error
}

func newOracleTestCache() *oracleTestCache {
	c := &oracleTestCache{now: time.Unix(1_800_000_000, 0), group: "dc-sbx-contractors@dclab.test"}
	c.cache = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		c.calls.Add(1)
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.err != nil {
			return useridentity.DirectoryFacts{}, c.err
		}
		return useridentity.DirectoryFacts{Groups: []string{c.group}, ResolvedAt: c.now}, nil
	})
	c.cache.logf = nil
	c.cache.now = func() time.Time {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.now
	}
	return c
}

func (c *oracleTestCache) set(advance time.Duration, group string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(advance)
	c.group, c.err = group, err
}

// GAP-0383, GAP-0307: explain answers from the cache hook calls read, after a
// lookup of its own. Right after a reload its first answer is the new facts,
// not the ones cached before; hook calls then read those same facts; and a
// second explain seconds later shares the lookup instead of racing it.
func TestIdentityCacheExplainRefreshesTheFactsHooksUse(t *testing.T) {
	c := newOracleTestCache()
	if facts, ok := c.cache.get("94404077", true); !ok || facts.Groups[0] != "dc-sbx-contractors@dclab.test" {
		t.Fatalf("first hook facts = %+v, %v", facts, ok)
	}
	c.set(time.Minute, "dc-sbx-devs@dclab.test", nil)
	c.cache.invalidate()
	facts, err := explainDirectoryFacts(c.cache, "94404077")
	if err != nil || facts.Groups[0] != "dc-sbx-devs@dclab.test" {
		t.Fatalf("explain after the reload = %+v, %v; want the new facts", facts, err)
	}
	if hook, ok := c.cache.get("94404077", true); !ok || hook.Groups[0] != "dc-sbx-devs@dclab.test" {
		t.Fatalf("hook facts after explain = %+v, %v; want the facts explain reported", hook, ok)
	}
	calls := c.calls.Load()
	c.set(time.Second, "dc-sbx-admins@dclab.test", nil)
	if again, err := explainDirectoryFacts(c.cache, "94404077"); err != nil || again.Groups[0] != "dc-sbx-devs@dclab.test" || c.calls.Load() != calls {
		t.Fatalf("explain a second later = %+v, %v after %d lookups; want the same answer from the same lookup", again, err, c.calls.Load()-calls)
	}
}

// GAP-0575: right after a restart the startup check had resolved the account
// with facts that are still incomplete (the guardian's record has not arrived),
// and the administrator's first explain repeated them for the next five
// seconds, so a users entry written as a UPN or in upper case selected nobody
// until the lookup was repeated. Explain looks again once the incomplete
// outcome is a second old, and shares the lookup of one call.
func TestIdentityCacheExplainLooksAgainAtIncompleteFacts(t *testing.T) {
	c := newOracleTestCache()
	var upn atomic.Value
	upn.Store("")
	c.cache.resolve = func(string) (useridentity.DirectoryFacts, error) {
		c.calls.Add(1)
		c.mu.Lock()
		defer c.mu.Unlock()
		return useridentity.DirectoryFacts{UPN: upn.Load().(string), ResolvedAt: c.now}, nil
	}
	c.cache.incomplete = func(facts useridentity.DirectoryFacts) bool { return facts.UPN == "" }

	if facts, err := explainDirectoryFacts(c.cache, "94404077"); err != nil || facts.UPN != "" {
		t.Fatalf("first explain = %+v, %v", facts, err)
	}
	calls := c.calls.Load()
	// The same call asks again a moment later: one lookup answers both.
	if _, err := explainDirectoryFacts(c.cache, "94404077"); err != nil || c.calls.Load() != calls {
		t.Fatalf("a second asking within the call looked up again: %d lookups", c.calls.Load()-calls)
	}
	// The guardian's record arrived; the incomplete outcome is two seconds old.
	upn.Store("ent-alice@dclab.test")
	c.set(2*time.Second, "", nil)
	if facts, err := explainDirectoryFacts(c.cache, "94404077"); err != nil || facts.UPN != "ent-alice@dclab.test" {
		t.Fatalf("explain two seconds after the incomplete facts = %+v, %v; want the facts with the UPN", facts, err)
	}
	// Complete facts are still shared for identityExplainFresh.
	calls = c.calls.Load()
	c.set(2*time.Second, "", nil)
	if _, err := explainDirectoryFacts(c.cache, "94404077"); err != nil || c.calls.Load() != calls {
		t.Fatalf("complete facts were looked up again after two seconds: %d lookups", c.calls.Load()-calls)
	}
}

// GAP-0361: a lookup that fails (SSSD offline with a valid cache, a domain
// controller away) leaves explain with what hook calls keep: the facts cached
// before it, reported with the failure. Explain printed default_lookup_failed
// while hook calls still got the group profile. With nothing cached, explain
// reports the lookup's own reason.
func TestIdentityCacheExplainKeepsTheFactsHooksKeepWhenTheLookupFails(t *testing.T) {
	c := newOracleTestCache()
	if _, ok := c.cache.get("94404077", true); !ok {
		t.Fatal("no first facts")
	}
	c.set(5*time.Minute, "", errors.New("SSSD NSS responder: i/o timeout"))
	facts, err := explainDirectoryFacts(c.cache, "94404077")
	if err != nil || facts.Groups[0] != "dc-sbx-contractors@dclab.test" {
		t.Fatalf("explain while the lookup fails = %+v, %v; want the cached facts", facts, err)
	}
	if hook, ok := c.cache.get("94404077", true); !ok || hook.Groups[0] != facts.Groups[0] {
		t.Fatalf("hook facts = %+v, %v; want the facts explain reported", hook, ok)
	}
	if _, reason, failing := c.cache.refreshFailing("94404077"); !failing || !strings.Contains(reason, "i/o timeout") {
		t.Fatalf("refreshFailing = %q, %v; want the failure reported", reason, failing)
	}
	if _, err := explainDirectoryFacts(c.cache, "94404078"); err == nil || !strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("explain of an account with no cached facts = %v; want the lookup's reason", err)
	}
}

// GAP-0361: explain names the cached facts its answer comes from while the
// gateway's lookups for the account fail, with their age.
func TestExplainCacheViewNamesCachedFactsWhileTheLookupFails(t *testing.T) {
	set := &guardrailProfileSet{
		profiles:       map[string]config.DerivedGuardrailProfile{"engineering": {Digest: "d1"}, "offline-floor": {Digest: "d2"}},
		assignments:    []config.ProfileAssignment{{Profile: "engineering", Match: config.ProfileMatch{Groups: []string{"dc-sbx-devs@dclab.test"}}}},
		defaultProfile: "offline-floor",
	}
	now := time.Now()
	cached := useridentity.DirectoryFacts{Groups: []string{"dc-sbx-devs@dclab.test"}, ResolvedAt: now.Add(-5 * time.Minute)}
	prevFacts, prevFailure := cachedDirectoryFacts, cachedDirectoryRefreshFailure
	t.Cleanup(func() { cachedDirectoryFacts, cachedDirectoryRefreshFailure = prevFacts, prevFailure })
	cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) { return cached, cached.ResolvedAt, true }
	cachedDirectoryRefreshFailure = func(string) (time.Time, string, bool) {
		return now.Add(-time.Minute), "SSSD NSS responder: i/o timeout", true
	}
	explained := &profileSubject{UserID: "94404077", UserName: "ent-bob", Groups: cached.Groups}
	decision := set.match(explained, profileSubjectLookup, "claudecode", "")
	view, warning := explainCacheView(set, explained, decision, "claudecode", "", now)
	if decision.Name != "engineering" || view["stale"] != true || view["differs"] != false || view["age_seconds"] != 300 ||
		!strings.Contains(warning, "has failed since") || !strings.Contains(warning, "cached 5m0s ago") {
		t.Fatalf("decision %+v, view %v, warning %q; want the cached group profile named as cached", decision, view, warning)
	}
}
