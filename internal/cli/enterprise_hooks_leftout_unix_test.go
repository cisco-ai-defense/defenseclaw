//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// leftOutTestResolver answers like standaloneTestResolver, except that a
// name lookup of a name in stuck blocks until release closes, as an Open
// Directory call that never answers does, and every name lookup is counted.
type leftOutTestResolver struct {
	standaloneTestResolver
	mu      *sync.Mutex
	stuck   map[string]bool
	release chan struct{}
	calls   *atomic.Int32
}

func (r leftOutTestResolver) LookupUser(name string) (unixidentity.Account, error) {
	r.calls.Add(1)
	r.mu.Lock()
	stuck := r.stuck[name]
	r.mu.Unlock()
	if stuck {
		<-r.release
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
	return r.standaloneTestResolver.LookupUser(name)
}

func (r leftOutTestResolver) setStuck(name string, stuck bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stuck[name] = stuck
}

// W2B-G-enum review loop 5: the guardian resolved every exclude_users and
// exempt_users name synchronously, without a deadline, on each reconcile,
// even when no account was listed (an empty eligible-accounts file). On a
// Mac an Open Directory lookup that never answers then stopped the watch
// loop, and with it later reconciles and repairs. The names are now
// resolved only when a listed account or an identity record is not left
// out by its uid or spelling already, the lookups end with the reconcile
// context and a short wait, a name whose lookup has not returned starts no
// second one, and a name keeps the uid its last answer gave while its
// lookup does not answer.
func TestExclusionNameLookupsNeverHoldTheGuardian(t *testing.T) {
	previousCfg, previousWait := cfg, enterpriseHookLeftOutLookupWait
	previousEligible, previousIdentity := enterpriseHookLoadEligibleAccounts, enterpriseHookLoadIdentityAccounts
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		cfg, enterpriseHookLeftOutLookupWait = previousCfg, previousWait
		enterpriseHookLoadEligibleAccounts, enterpriseHookLoadIdentityAccounts = previousEligible, previousIdentity
		enterprisehooks.SetStandaloneResolver(nil)
	})
	enterpriseHookLeftOutLookupWait = 100 * time.Millisecond
	const aliceUID, carolUID = 4242, 4244
	calls := &atomic.Int32{}
	resolver := leftOutTestResolver{
		standaloneTestResolver: standaloneTestResolver{accounts: map[string]unixidentity.Account{
			"alice":              {Name: "alice", UID: aliceUID, GID: aliceUID},
			"carol@corp.example": {Name: "carol@corp.example", UID: carolUID, GID: carolUID},
			"carol":              {Name: "carol@corp.example", UID: carolUID, GID: carolUID},
		}},
		mu: &sync.Mutex{}, stuck: map[string]bool{"stuck-empty": true, "stuck-listed": true}, release: release, calls: calls,
	}
	enterprisehooks.SetStandaloneResolver(resolver)
	exclude := func(names ...string) {
		cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
		cfg.Enterprise.Profile = managed.ProfileStandalone
		cfg.Enterprise.Enrollment.ExcludeUsers = names
	}
	const manifest = "/etc/defenseclaw/hooks/manifest.json"
	eligible := []enterprisehooks.UnixEligibleAccount{}
	load := func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return eligible, nil }
	enterpriseHookLoadEligibleAccounts, enterpriseHookLoadIdentityAccounts = load, load
	// within runs one guardian pass's account listing and fails when it
	// waits for a lookup past the bound.
	within := func(ctx context.Context, when string, run enterpriseHookReconcileRun) ([]enterprisehooks.IdentitySpoolAccount, []enterpriseHookReconcileRow) {
		t.Helper()
		type result struct {
			accounts []enterprisehooks.IdentitySpoolAccount
			rows     []enterpriseHookReconcileRow
		}
		done := make(chan result, 1)
		go func() {
			rows := enterpriseHookEnrolledAccountRows(ctx, io.Discard, run)
			accounts, _, _ := enterpriseHookIdentitySpoolAccounts(ctx, io.Discard, "", run)
			done <- result{accounts, rows}
		}()
		select {
		case got := <-done:
			return got.accounts, got.rows
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the guardian pass waited for an exclude_users lookup that does not answer", when)
		}
		return nil, nil
	}

	// No account listed, an empty eligible file: nothing is looked up.
	exclude("stuck-empty")
	within(context.Background(), "no listed account", enterpriseHookReconcileRun{Manifest: manifest})
	if got := calls.Load(); got != 0 {
		t.Fatalf("lookups with no listed account = %d, want 0", got)
	}

	// A listed account its spelling does not exclude: the lookup is
	// bounded, and the next pass starts no second one while it runs.
	exclude("stuck-listed")
	run := enterpriseHookReconcileRun{Manifest: manifest,
		Rows: []enterpriseHookReconcileRow{{User: "alice", UserHome: "/home/alice", Connector: "opencode", OK: true, UID: aliceUID}}}
	for pass := 1; pass <= 3; pass++ {
		accounts, _ := within(context.Background(), "stuck lookup", run)
		if len(accounts) != 1 || accounts[0].UID != aliceUID || accounts[0].Left {
			t.Fatalf("pass %d: accounts %+v, want alice enrolled", pass, accounts)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("lookups of the stuck name over 3 passes = %d, want 1", got)
	}
	// The reconcile context ends the wait too.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	exclude("stuck-canceled")
	resolver.setStuck("stuck-canceled", true)
	started := time.Now()
	within(canceled, "canceled pass", run)
	if waited := time.Since(started); waited >= enterpriseHookLeftOutLookupWait {
		t.Fatalf("a canceled pass waited %s for its lookups", waited)
	}

	// carol is listed as carol@corp.example and excluded as carol: the
	// lookup gives her uid. While it does not answer, the last answer
	// keeps applying; a not-found answer forgets it.
	eligible = []enterprisehooks.UnixEligibleAccount{{User: "carol@corp.example", UID: carolUID, Home: "/home/carol"}}
	exclude("carol")
	carolLeft := func(when string) bool {
		t.Helper()
		accounts, rows := within(context.Background(), when, run)
		left := slices.ContainsFunc(accounts, func(a enterprisehooks.IdentitySpoolAccount) bool { return a.UID == carolUID && a.Left })
		enrolled := slices.ContainsFunc(accounts, func(a enterprisehooks.IdentitySpoolAccount) bool { return a.UID == carolUID && !a.Left })
		scanned := slices.ContainsFunc(rows, func(r enterpriseHookReconcileRow) bool { return r.UID == carolUID })
		if left == enrolled || left == scanned {
			t.Fatalf("%s: accounts %+v, rows %+v: carol must be either left out or enrolled and scanned", when, accounts, rows)
		}
		return left
	}
	if !carolLeft("the name resolves") {
		t.Fatal("carol, excluded by another spelling, is enrolled")
	}
	resolver.setStuck("carol", true)
	if !carolLeft("the lookup does not answer") {
		t.Fatal("carol's exclusion was lost while the directory did not answer")
	}
	resolver.setStuck("carol", false)
	releaseOnce.Do(func() { close(release) })
	delete(resolver.accounts, "carol")
	deadline := time.Now().Add(5 * time.Second)
	// The released lookup returns on its own; until it has, a pass's lookup
	// of carol does not start, and the scans and the identity pass of one
	// guardian pass could read her name apart.
	for {
		if _, err := enterprisehooks.LookupStandaloneUserBounded(context.Background(), "carol"); unixidentity.IsNotFound(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the released lookup of carol did not return")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for carolLeft("the name no longer resolves") {
		if time.Now().After(deadline) {
			t.Fatal("carol stays excluded after her name stopped resolving")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The record of an account a partial listing omitted is matched against the
// settings by the name it carries, in the pass, so excluding that account
// withdraws the record without a name lookup.
func TestExclusionWithdrawsTheRecordOfAnOmittedAccountByItsName(t *testing.T) {
	previousCfg := cfg
	t.Cleanup(func() {
		cfg = previousCfg
		enterprisehooks.SetStandaloneResolver(nil)
	})
	calls := &atomic.Int32{}
	enterprisehooks.SetStandaloneResolver(leftOutTestResolver{
		standaloneTestResolver: standaloneTestResolver{accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: 4242, GID: 4242}}},
		mu:                     &sync.Mutex{}, stuck: map[string]bool{}, release: make(chan struct{}), calls: calls,
	})
	dir := t.TempDir()
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{Key: "4243", User: "bob@corp.example", UpdatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "4243.json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{}
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"bob@corp.example"}
	accounts, keys, withdraw := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if !slices.Contains(keys, "exclude:bob@corp.example") {
		t.Fatalf("keys %v do not follow exclude_users", keys)
	}
	if err := enterprisehooks.WriteIdentitySpool(context.Background(), dir, accounts, nil, nil, withdraw); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, strconv.Itoa(4243)+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bob's record was not withdrawn: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("name lookups = %d, want 0: the record's name already matches", got)
	}
}
