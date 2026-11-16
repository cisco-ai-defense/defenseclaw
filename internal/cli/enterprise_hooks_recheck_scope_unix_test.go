// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// recheckScopeFixture is a standalone pass over alice and bob, distinct
// uids, each with a Hermes target; alice also has Claude Code, which is in
// machine policy and sorts first, so it creates alice's worker job.
func recheckScopeFixture(t *testing.T, resolver unixidentity.Resolver, accounts standaloneTestResolver) (*standaloneFixture, string, string) {
	t.Helper()
	f := newStandaloneFixture(t, resolver)
	alice, bob := f.home(t, "alice", 0o700), f.home(t, "bob", 0o700)
	accounts.accounts["alice"] = unixidentity.Account{Name: "alice", UID: 5001, GID: 5001, Home: alice, Shell: "/bin/bash"}
	accounts.accounts["bob"] = unixidentity.Account{Name: "bob", UID: 5002, GID: 5002, Home: bob, Shell: "/bin/bash"}
	previousCheck, previousSet, previousCovered := enterpriseHookCheckHome, enterpriseHookStandaloneMachinePolicySet, enterpriseHookStandaloneMachinePolicyCovered
	previousWindow, previousPaths, previousAll := enterpriseHookReconcileRecheckWindow, enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll
	t.Cleanup(func() {
		enterpriseHookCheckHome, enterpriseHookStandaloneMachinePolicySet, enterpriseHookStandaloneMachinePolicyCovered = previousCheck, previousSet, previousCovered
		enterpriseHookReconcileRecheckWindow, enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll = previousWindow, previousPaths, previousAll
	})
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} { return map[string]struct{}{"claudecode": {}} }
	enterpriseHookStandaloneMachinePolicyCovered = func(string) (bool, error) { return true, nil }
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"},
		enterprisehooks.ManifestTarget{User: "bob", Connector: "hermes"},
	)
	f.writeLedger(t, protectedRow("alice", alice, "hermes"), protectedRow("bob", bob, "hermes"))
	return f, alice, bob
}

// recheckMillisByHome is the recheck window of each account's worker job.
func (f *standaloneFixture) recheckMillisByHome() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for _, request := range f.requests {
		for _, target := range request.Targets {
			out[target.Options.UserHome] = request.RecheckMillis
		}
	}
	return out
}

// GAP-1825 review R4-1 and R4-2: a pass a file change in alice's Hermes
// config armed gives the recheck window to alice's job, also when her
// machine-policy Claude Code row created that job (R4-1: it had none, so her
// Hermes was checked once), and not to bob, whose home no event named (R4-2:
// every account got one, which made a pass one window longer per wave of
// four workers).
func TestStandaloneRecheckWindowGoesToTheAccountsTheEventsNamed(t *testing.T) {
	accounts := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f, alice, bob := recheckScopeFixture(t, accounts, accounts)
	enterpriseHookReconcileRecheckWindow = 300 * time.Millisecond
	enterpriseHookReconcileRecheckPaths = []string{filepath.Join(alice, ".hermes", "config.yaml")}
	enterpriseHookReconcileRecheckAll = false
	if _, err := runEnterpriseHookReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := f.recheckMillisByHome()
	if got[alice] != 300 || got[bob] != 0 {
		t.Fatalf("recheck_ms by home = %v; want 300 for alice (her event, machine-policy job first) and 0 for bob", got)
	}

	// Dropped events (an overflow) name nobody: every account gets it.
	f.requests = nil
	enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll = nil, true
	if _, err := runEnterpriseHookReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.recheckMillisByHome(); got[alice] != 300 || got[bob] != 300 {
		t.Fatalf("after an overflow recheck_ms by home = %v; want 300 for both", got)
	}

	// Interval, startup and retry passes have no window.
	f.requests = nil
	enterpriseHookReconcileRecheckWindow = 0
	if _, err := runEnterpriseHookReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.recheckMillisByHome(); got[alice] != 0 || got[bob] != 0 {
		t.Fatalf("a pass without a window sent recheck_ms %v", got)
	}
}

// countingGroupResolver counts the group lists the directory is asked for.
type countingGroupResolver struct {
	standaloneTestResolver
	groupIDs *atomic.Int32
}

func (r countingGroupResolver) GroupIDs(account unixidentity.Account) ([]int, error) {
	r.groupIDs.Add(1)
	return r.standaloneTestResolver.GroupIDs(account)
}

// GAP-1825 (pass latency on macOS): every pass dropped the resolver cache,
// so each worker's supplementary groups were confirmed again with one
// dsmemberutil run per group, about 1.5 s per pass on an Active Directory
// Mac, and the repair of a rewritten Hermes hooks block came 3.5 s or more
// into the burst. A pass a file change armed reuses a group list from the
// last minute and a half; an interval pass asks again.
func TestFilesystemPassReusesRecentWorkerGroups(t *testing.T) {
	accounts := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	var asked atomic.Int32
	resolver := unixidentity.NewCachingResolver(countingGroupResolver{standaloneTestResolver: accounts, groupIDs: &asked})
	f, _, _ := recheckScopeFixture(t, resolver, accounts)
	runner := enterpriseHookWorkerRunner
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		// The real runner resolves the worker's groups before it starts it.
		enterpriseHookWorkerGroupIDs(account)
		return runner(ctx, account, request)
	}
	pass := func(window time.Duration) {
		t.Helper()
		enterpriseHookReconcileRecheckWindow = window
		enterpriseHookReconcileRecheckPaths, enterpriseHookReconcileRecheckAll = nil, true
		if _, err := runEnterpriseHookReconcileOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	pass(0)
	first := asked.Load()
	if first != 2 {
		t.Fatalf("an interval pass asked for %d group lists, want one per account (2)", first)
	}
	pass(300 * time.Millisecond)
	if got := asked.Load(); got != first {
		t.Fatalf("a pass a file change armed asked the directory again for %d group lists; want the lists of the last pass reused", got-first)
	}
	pass(0)
	if got := asked.Load(); got != first+2 {
		t.Fatalf("an interval pass reused group lists (asked %d, want %d)", got, first+2)
	}
	previousReuse := enterpriseHookFilesystemPassGroupReuse
	t.Cleanup(func() { enterpriseHookFilesystemPassGroupReuse = previousReuse })
	enterpriseHookFilesystemPassGroupReuse = time.Nanosecond
	before := asked.Load()
	pass(300 * time.Millisecond)
	if got := asked.Load(); got != before+2 {
		t.Fatalf("a file-change pass reused group lists older than the reuse bound (asked %d, want %d)", got-before, 2)
	}
	_ = f
}
