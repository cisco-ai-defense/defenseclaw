// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of r104 Q-identity (continuation 3, loop round 1), the cache side:
// a lookup in flight when an invalidation lands answers with what the
// directory gave before it. Its facts are not current (getCached), are not
// the answer of a read that needs current facts (getCurrent) or fresh ones
// (getFresh), and a read already waiting for that lookup when the
// invalidation lands waits on, within its budget, for the lookup started
// after it.
func TestInvalidationDuringALookupIsNotCurrent(t *testing.T) {
	reads := map[string]func(*identityCache[string]) (string, bool){
		"getCurrent": func(c *identityCache[string]) (string, bool) { return c.getCurrent("k", identityDirectoryBudget) },
		"getFresh":   func(c *identityCache[string]) (string, bool) { return c.getFresh("k", identityDirectoryBudget) },
	}
	for _, how := range []string{"invalidate", "refreshSoon"} {
		for name, read := range reads {
			t.Run(how+", "+name+" after the lookup", func(t *testing.T) {
				cache, clock, lookups, release := inflightInvalidationFixture(t)
				if got, ok := cache.get("k", true); !ok || got != "answer 1" {
					t.Fatalf("cold read = %q, %t", got, ok)
				}
				startInflightLookup(t, cache, clock, lookups)
				invalidateDuringLookup(cache, clock, how)
				release()
				waitIdentityCacheIdle(t, cache, "k")
				if got, current, ok := cache.getCached("k"); !ok || current {
					t.Fatalf("facts of the lookup the invalidation landed in: %q current=%t ok=%t; want served and not current", got, current, ok)
				}
				if got, ok := read(cache); !ok || got != "answer 3" {
					t.Fatalf("%s = %q, %t after %d lookups; want the lookup started after the invalidation (answer 3)", name, got, ok, lookups.Load())
				}
				if _, current, ok := cache.getCached("k"); !ok || !current {
					t.Fatalf("answer 3: current=%t ok=%t; want current", current, ok)
				}
			})
			t.Run(how+", "+name+" waiting for the lookup", func(t *testing.T) {
				cache, clock, lookups, release := inflightInvalidationFixture(t)
				if got, ok := cache.get("k", true); !ok || got != "answer 1" {
					t.Fatalf("cold read = %q, %t", got, ok)
				}
				startInflightLookup(t, cache, clock, lookups)
				type answer struct {
					facts string
					ok    bool
				}
				done := make(chan answer, 1)
				go func() {
					facts, ok := read(cache)
					done <- answer{facts, ok}
				}()
				time.Sleep(20 * time.Millisecond) // the read waits for lookup 2
				invalidateDuringLookup(cache, clock, how)
				release()
				select {
				case got := <-done:
					if !got.ok || got.facts != "answer 3" {
						t.Fatalf("%s = %q, %t after %d lookups; want the lookup started after the invalidation (answer 3)",
							name, got.facts, got.ok, lookups.Load())
					}
				case <-time.After(identityDirectoryBudget + time.Second):
					t.Fatalf("%s did not return within its budget", name)
				}
			})
		}
	}
}

// The decision: an exempt_users UPN that a lookup in flight still gave when
// the directory dropped it (the guardian's record with the news, or a
// profile assignment change, lands during the lookup) no longer exempts
// the caller; with the UPN kept, the caller is exempt after the lookup that
// follows. Managed macOS and Linux reads alike.
func TestExemptNameAfterAnInvalidationDuringALookup(t *testing.T) {
	alice := managedMacAliceFacts()
	dropped := managedMacAliceFacts()
	dropped.UPN, dropped.Principal = "", ""
	for i, tc := range []struct {
		name       string
		linux      bool
		record     bool // the guardian's record, otherwise a profile change
		current    useridentity.DirectoryFacts
		wantExempt bool
	}{
		{name: "mac, guardian record, UPN dropped", record: true, current: dropped},
		{name: "mac, profile change, UPN dropped", current: dropped},
		{name: "mac, guardian record, UPN still given", record: true, current: alice, wantExempt: true},
		{name: "linux, guardian record, UPN dropped", linux: true, record: true, current: dropped},
		{name: "linux, profile change, UPN dropped", linux: true, current: dropped},
		{name: "linux, guardian record, UPN still given", linux: true, record: true, current: alice, wantExempt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid := 42150 + i
			var lookups atomic.Int32
			gate := make(chan struct{})
			release := sync.OnceFunc(func() { close(gate) })
			t.Cleanup(release)
			cache, clock := managedMacExemptFixture(t, uid, func() (useridentity.DirectoryFacts, error) {
				switch lookups.Add(1) {
				case 1:
					return alice, nil
				case 2:
					<-gate
					return alice, nil // read before the directory dropped the UPN
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
			key := strconv.Itoa(uid)
			clock.Add(int64(cache.directories.lifetime(alice) + time.Second))
			cache.directories.getCached(key) // starts lookup 2 in the background
			deadline := time.Now().Add(2 * time.Second)
			for lookups.Load() < 2 {
				if time.Now().After(deadline) {
					t.Fatal("lookup 2 did not start")
				}
				time.Sleep(time.Millisecond)
			}
			clock.Add(int64(time.Millisecond))
			if tc.record {
				cache.directories.refreshSoon(key)
			} else {
				refreshDirectoryFactsOnProfileChange(&config.Config{}, &config.Config{Guardrail: config.GuardrailConfig{DefaultProfile: "strict"}})
			}
			release()
			waitDirectoryPublished(t, cache, uid)
			if decision := z.decide(peer, "codex", "cli"); decision.Exempt != tc.wantExempt || decision.Allow != tc.wantExempt {
				t.Fatalf("hook 2 after %d lookups: %+v; want exempt=%t", lookups.Load(), decision, tc.wantExempt)
			}
			if got := lookups.Load(); got != 3 {
				t.Fatalf("%d directory lookups; want the lookup after the invalidation as well", got)
			}
		})
	}
}
