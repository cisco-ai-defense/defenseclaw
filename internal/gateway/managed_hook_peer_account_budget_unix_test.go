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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// stallingAccounts answers uid 6001 with name, and blocks every lookup made
// while stall is set until it is cleared (a stopped SSSD responder).
type stallingAccounts struct {
	unixidentity.Resolver
	mu      sync.Mutex
	name    string
	stall   chan struct{}
	lookups atomic.Int32
}

func (r *stallingAccounts) LookupUID(uid int) (unixidentity.Account, error) {
	r.lookups.Add(1)
	r.mu.Lock()
	stall := r.stall
	r.mu.Unlock()
	if stall != nil {
		<-stall
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return unixidentity.Account{Name: r.name, UID: uid, Home: "/home/" + r.name}, nil
}

func (r *stallingAccounts) setStall(stall chan struct{}) {
	r.mu.Lock()
	r.stall = stall
	r.mu.Unlock()
}

func useStallingAccounts(t *testing.T, resolver *stallingAccounts) *managedHookPeerHomeCache {
	t.Helper()
	previousManaged, previousFacts := ManagedEnterpriseActive(), identityFactsEnabled.Load()
	previousStamp, previousConfirmed := managedHookPeerAccountsStamp, managedHookPeerAccountsConfirmed
	previousIncarnation, previousChanged := managedHookPeerAccountIncarnation, managedHookPeerRecordChanged
	t.Cleanup(func() {
		SetManagedEnterpriseActive(previousManaged)
		setIdentityFactsEnabled(previousFacts)
		managedHookPeerAccountsStamp, managedHookPeerAccountsConfirmed = previousStamp, previousConfirmed
		managedHookPeerAccountIncarnation, managedHookPeerRecordChanged = previousIncarnation, previousChanged
	})
	SetManagedEnterpriseActive(false)
	setIdentityFactsEnabled(true)
	managedHookPeerAccountsStamp = func() string { return "listing-1" }
	managedHookPeerAccountsConfirmed = func() bool { return true }
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "files", true }
	managedHookPeerRecordChanged = func(unixidentity.Account) bool { return false }
	return &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver { return resolver }, now: time.Now}
}

// accountWithin calls cache.account(uid) and fails the test when it does
// not return within limit (a request held by a stalled lookup).
func accountWithin(t *testing.T, cache *managedHookPeerHomeCache, uid int, limit time.Duration) (unixidentity.Account, bool) {
	t.Helper()
	type answer struct {
		account unixidentity.Account
		ok      bool
	}
	done := make(chan answer, 1)
	go func() {
		account, ok := cache.account(uid)
		done <- answer{account, ok}
	}()
	select {
	case got := <-done:
		return got.account, got.ok
	case <-time.After(limit):
		t.Fatalf("a request waited more than %s for a stalled account lookup (budget %s)", limit, managedHookPeerAccountBudget)
		return unixidentity.Account{}, false
	}
}

// GAP-0397: with the SSSD responder stopped, the first account lookup of a
// directory caller (getent up to 5 s, the SID of its incarnation up to 8 s)
// held the hook request past the managed hook's 3.5 s answer watchdog, which
// denied a benign call the gateway allowed seconds later. A request waits
// for the lookup only up to managedHookPeerAccountBudget from its start and
// is then served as a failed lookup (no account); requests that arrive while
// it still runs do not wait again, the lookup is not started twice, and its
// answer serves the requests after it.
func TestAStalledFirstAccountLookupAnswersWithinTheAccountBudget(t *testing.T) {
	resolver := &stallingAccounts{name: "dcad-eng2"}
	stall := make(chan struct{})
	resolver.setStall(stall)
	cache := useStallingAccounts(t, resolver)
	defer func() {
		select {
		case <-stall:
		default:
			close(stall)
		}
	}()

	if account, ok := accountWithin(t, cache, 6001, managedHookPeerAccountBudget+time.Second); ok {
		t.Fatalf("a stalled first lookup served %+v", account)
	}
	if account, ok := accountWithin(t, cache, 6001, 100*time.Millisecond); ok {
		t.Fatalf("a request during the stalled lookup was served %+v", account)
	}
	close(stall)
	resolver.setStall(nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if account, ok := cache.account(6001); ok {
			if account.Name != "dcad-eng2" {
				t.Fatalf("the finished lookup served %+v", account)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stalled lookup's answer never served a later request")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := resolver.lookups.Load(); got != 1 {
		t.Fatalf("lookups of the stalled uid = %d, want the one shared lookup", got)
	}
}

// A recheck of a served account (managedHookPeerAccountRecheck) that the
// stalled directory does not answer within the budget serves the last
// account, as a recheck the directory cannot answer does, and its later
// answer replaces it.
func TestAStalledAccountRecheckServesTheLastAccountWithinTheAccountBudget(t *testing.T) {
	resolver := &stallingAccounts{name: "dcad-eng2"}
	cache := useStallingAccounts(t, resolver)
	if account, ok := cache.account(6001); !ok || account.Name != "dcad-eng2" {
		t.Fatalf("first lookup = %+v, %v", account, ok)
	}
	cache.mu.Lock()
	cache.accounts[6001].checked = time.Now().Add(-2 * managedHookPeerAccountRecheck)
	cache.mu.Unlock()
	stall := make(chan struct{})
	resolver.setStall(stall)
	resolver.mu.Lock()
	resolver.name = "dcad-eng2-new"
	resolver.mu.Unlock()
	defer func() {
		select {
		case <-stall:
		default:
			close(stall)
		}
	}()

	if account, ok := accountWithin(t, cache, 6001, managedHookPeerAccountBudget+time.Second); !ok || account.Name != "dcad-eng2" {
		t.Fatalf("a stalled recheck served %+v, %v; want the last account", account, ok)
	}
	if account, ok := accountWithin(t, cache, 6001, 100*time.Millisecond); !ok || account.Name != "dcad-eng2" {
		t.Fatalf("a request during the stalled recheck = %+v, %v; want the last account", account, ok)
	}
	close(stall)
	resolver.setStall(nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		cache.mu.Lock()
		name, inFlight := cache.accounts[6001].account.Name, cache.accounts[6001].recheck != nil
		cache.mu.Unlock()
		if name == "dcad-eng2-new" && !inFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the stalled recheck's answer was never recorded (name %q)", name)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := resolver.lookups.Load(); got != 2 {
		t.Fatalf("lookups = %d, want the first lookup and one shared recheck", got)
	}
}
