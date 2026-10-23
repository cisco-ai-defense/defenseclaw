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

// Review of r104 Q-identity (continuation 3, loop round 3): settled cached
// facts held an old UPN, the directory then gave the account the UPN
// exempt_users lists, and a profile reload (or a guardian record with news)
// invalidated the cache. The first hook rejected the exemption at once,
// because the old facts did not match, although the invalidation had
// started the refresh that gives the new UPN; the release waited for it.
// Invalidated facts now wait for the current answer whatever they match,
// and a refresh that does not answer within identityDirectoryBudget
// exempts no one. Facts that only outlived their TTL still reject a
// nonmatch without waiting (the refresh they start serves the next hook).
// Managed macOS and Linux reads alike.
func TestInvalidatedNonmatchingFactsWaitForANewExemptUPN(t *testing.T) {
	renamed := managedMacAliceFacts() // the UPN exempt_users lists
	old := managedMacAliceFacts()
	old.UPN, old.Principal = "alice.old@corp.example.com", "alice.old@corp.example.com"
	const (
		profileChange = iota
		guardianRecord
		expired
	)
	for i, tc := range []struct {
		name   string
		linux  bool
		change int
		never  bool // the refresh never answers
	}{
		{name: "mac, profile change", change: profileChange},
		{name: "mac, guardian record", change: guardianRecord},
		{name: "mac, profile change, directory does not answer", change: profileChange, never: true},
		{name: "mac, expired", change: expired},
		{name: "linux, profile change", linux: true, change: profileChange},
		{name: "linux, guardian record", linux: true, change: guardianRecord},
		{name: "linux, guardian record, directory does not answer", linux: true, change: guardianRecord, never: true},
		{name: "linux, expired", linux: true, change: expired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid := 42210 + i
			var lookups atomic.Int32
			hold := make(chan struct{})
			release := sync.OnceFunc(func() { close(hold) })
			t.Cleanup(release)
			cache, clock := managedMacExemptFixture(t, uid, func() (useridentity.DirectoryFacts, error) {
				if lookups.Add(1) == 1 {
					return old, nil
				}
				if tc.never || tc.change == expired {
					<-hold
				}
				return renamed, nil
			})
			if tc.linux {
				managedHookDirectoryNeedsFresh = false
			}
			z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"alice@corp.example.com"}}, nil,
				func() (managedHookLedger, error) { return managedHookLedger{}, nil })
			peer := managedHookPeer{UID: uid, Name: "alice"}
			if decision := z.decide(peer, "codex", "cli"); decision.Exempt {
				t.Fatalf("hook 1: the old UPN exempted the caller: %+v", decision)
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
				clock.Add(int64(cache.directories.lifetime(old) + time.Second))
			}
			started := time.Now()
			decision := z.decide(peer, "codex", "cli")
			elapsed := time.Since(started)
			if elapsed > identityDirectoryBudget+time.Second {
				t.Fatalf("hook 2 waited %s for the directory; want at most about %s", elapsed, identityDirectoryBudget)
			}
			switch {
			case tc.never:
				if decision.Exempt || decision.Allow {
					t.Fatalf("hook 2: a refresh that does not answer exempted the caller: %+v", decision)
				}
			case tc.change == expired:
				if decision.Exempt || elapsed >= identityDirectoryBudget {
					t.Fatalf("hook 2 on expired nonmatching facts: %+v after %s; want rejected without waiting", decision, elapsed)
				}
				release()
				waitDirectoryPublished(t, cache, uid)
				if decision := z.decide(peer, "codex", "cli"); !decision.Exempt || !decision.Allow {
					t.Fatalf("hook 3: the refresh the expiry started gave the exempt UPN, and the caller was not exempt: %+v", decision)
				}
			default:
				if !decision.Exempt || !decision.Allow {
					t.Fatalf("hook 2: the invalidation's refresh gives the exempt UPN, and the caller was not exempt: %+v", decision)
				}
			}
			if got := lookups.Load(); got != 2 {
				t.Fatalf("%d directory lookups; want the first and one refresh", got)
			}
		})
	}
}
