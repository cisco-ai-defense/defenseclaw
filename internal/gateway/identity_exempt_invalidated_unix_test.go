// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of r104 Q-identity (continuation 2, loop round 3): a profile
// assignment change invalidates every cached directory answer
// (refreshDirectoryFactsOnProfileChange), and a guardian record with news
// makes one account's answer due for a refresh (refreshSoon). The cache
// still called those facts current until their lifetime ended, so an
// exempt_users UPN they gave exempted the caller at once, although the
// directory had dropped it; the release waited for the refresh. On Linux
// the blocking read behind an exemption also handed back expired settled
// facts at once, and invalidated ones once its wait ended. Every such match
// now needs the refresh: the current answer decides, and a directory that
// does not answer exempts no one within identityDirectoryBudget. Managed
// macOS and Linux reads alike.
func TestInvalidatedOrExpiredExemptNameNeedsTheRefresh(t *testing.T) {
	alice := managedMacAliceFacts()
	dropped := managedMacAliceFacts()
	dropped.UPN, dropped.Principal = "", ""
	const (
		profileChange = iota
		guardianRecord
		expired
	)
	for i, tc := range []struct {
		name       string
		linux      bool
		change     int
		current    useridentity.DirectoryFacts
		never      bool // the refresh never answers
		wantExempt bool
	}{
		{name: "mac, profile change, UPN dropped", change: profileChange, current: dropped},
		{name: "mac, profile change, directory does not answer", change: profileChange, never: true},
		{name: "mac, profile change, UPN still given", change: profileChange, current: alice, wantExempt: true},
		{name: "mac, guardian record, UPN dropped", change: guardianRecord, current: dropped},
		{name: "linux, profile change, UPN dropped", linux: true, change: profileChange, current: dropped},
		{name: "linux, profile change, directory does not answer", linux: true, change: profileChange, never: true},
		{name: "linux, profile change, UPN still given", linux: true, change: profileChange, current: alice, wantExempt: true},
		{name: "linux, guardian record, UPN dropped", linux: true, change: guardianRecord, current: dropped},
		{name: "linux, guardian record, directory does not answer", linux: true, change: guardianRecord, never: true},
		{name: "linux, expired, UPN dropped", linux: true, change: expired, current: dropped},
		{name: "linux, expired, directory does not answer", linux: true, change: expired, never: true},
		{name: "linux, expired, UPN still given", linux: true, change: expired, current: alice, wantExempt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid := 42110 + i
			var lookups atomic.Int32
			never := make(chan struct{})
			releaseNever := sync.OnceFunc(func() { close(never) })
			t.Cleanup(releaseNever)
			cache, clock := managedMacExemptFixture(t, uid, func() (useridentity.DirectoryFacts, error) {
				if lookups.Add(1) == 1 {
					return alice, nil
				}
				if tc.never {
					<-never
				}
				return tc.current, nil
			})
			if tc.linux {
				managedHookDirectoryNeedsFresh = false
			}
			z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"alice@corp.example.com"}}, nil,
				func() (managedHookLedger, error) { return managedHookLedger{}, nil })
			peer := managedHookPeer{UID: uid, Name: "alice"}
			if decision := z.decide(peer, "codex", "cli"); !decision.Allow || !decision.Exempt {
				t.Fatalf("hook 1: the first answer gives the exempt UPN, and the caller was not exempt: %+v", decision)
			}
			waitDirectoryPublished(t, cache, uid)
			switch tc.change {
			case profileChange:
				clock.Add(int64(time.Millisecond)) // inside the fresh-read coalesce window
				refreshDirectoryFactsOnProfileChange(&config.Config{}, &config.Config{Guardrail: config.GuardrailConfig{DefaultProfile: "strict"}})
			case guardianRecord:
				clock.Add(int64(time.Millisecond))
				cache.directories.refreshSoon(strconv.Itoa(uid))
			case expired:
				clock.Add(int64(cache.directories.lifetime(alice) + time.Second))
			}
			hooks := 3
			if tc.never {
				hooks = 2 // each waits the whole budget
			}
			for hook := 2; hook <= hooks; hook++ {
				started := time.Now()
				decision := z.decide(peer, "codex", "cli")
				if elapsed := time.Since(started); elapsed > identityDirectoryBudget+time.Second {
					t.Fatalf("hook %d waited %s for the directory; want at most about %s", hook, elapsed, identityDirectoryBudget)
				}
				if decision.Exempt != tc.wantExempt || decision.Allow != tc.wantExempt {
					t.Fatalf("hook %d: %+v; want exempt=%t", hook, decision, tc.wantExempt)
				}
				clock.Add(int64(identityDirectoryFreshCoalesce + time.Second))
			}
			if got := lookups.Load(); got != 2 {
				t.Fatalf("%d directory lookups; want the first and one refresh", got)
			}
		})
	}
}

// The cache side of the same review: facts fetched before an invalidation
// are not current (getCached), are not shared by a fresh read inside its
// coalesce window (getFresh), and are never the answer of getCurrent, which
// waits for the refresh and gives nothing when it fails. A later answer is
// current again.
func TestInvalidatedFactsAreNotCurrent(t *testing.T) {
	for _, how := range []string{"invalidate", "refreshSoon"} {
		t.Run(how, func(t *testing.T) {
			var lookups atomic.Int32
			fail := make(chan bool, 4)
			cache := newIdentityCache(func(string) (string, error) {
				n := lookups.Add(1)
				select {
				case f := <-fail:
					if f {
						return "", errors.New("directory down")
					}
				default:
				}
				return "answer " + strconv.Itoa(int(n)), nil
			})
			clock := new(atomic.Int64)
			clock.Store(time.Unix(1_000_000, 0).UnixNano())
			cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
			if got, ok := cache.getCurrent("k", identityDirectoryBudget); !ok || got != "answer 1" {
				t.Fatalf("cold getCurrent = %q, %t", got, ok)
			}
			if _, current, ok := cache.getCached("k"); !ok || !current {
				t.Fatalf("fresh facts: current=%t ok=%t", current, ok)
			}
			clock.Add(int64(time.Millisecond)) // inside the fresh-read coalesce window
			if how == "invalidate" {
				cache.invalidate()
			} else {
				cache.refreshSoon("k")
			}
			fail <- true // the refresh the invalidation needs fails
			if got, ok := cache.getFresh("k", identityDirectoryBudget); ok {
				t.Fatalf("a fresh read gave %q; want the refresh, which failed, and no facts from before the invalidation", got)
			}
			if _, current, ok := cache.getCached("k"); !ok || current {
				t.Fatalf("invalidated facts: current=%t ok=%t; want served and not current", current, ok)
			}
			if got, ok := cache.getCurrent("k", identityDirectoryBudget); ok {
				t.Fatalf("getCurrent after a failed refresh = %q; want none", got)
			}
			clock.Add(int64(identityDirectoryRetry + time.Second))
			if got, ok := cache.getCurrent("k", identityDirectoryBudget); !ok || got != "answer 3" {
				t.Fatalf("getCurrent once the directory answers = %q, %t; want answer 3", got, ok)
			}
			if _, current, ok := cache.getCached("k"); !ok || !current {
				t.Fatalf("refreshed facts: current=%t ok=%t", current, ok)
			}
		})
	}
}
