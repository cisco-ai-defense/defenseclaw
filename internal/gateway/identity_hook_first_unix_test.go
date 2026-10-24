// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// r103 GAP-0173: authenticate and resolve a hook's profile before any explain
// call. The hook itself starts the macOS account-list refresh and then drops
// the former cached groups once that listing completes.
func TestHookFirstProfileFollowsLiveAccountRecordWithoutExplain(t *testing.T) {
	const uid = 94203
	account := unixidentity.LocalAccountRecord{UID: uid, RecordID: "hook-first", Home: "/Users/Shared/hook-first", PrimaryGID: "20"}
	resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{uid: {Name: "hook-first", UID: uid, Home: account.Home}}}
	facts := &accountFacts{groups: []string{"r103-hook-first"}}
	listing := &listedAccounts{accounts: map[string]unixidentity.LocalAccountRecord{"hook-first": account}}
	installListedAccounts(t, listing, factsTestCache(t, resolver, facts))
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	managedHookPeerAccounts.now = func() time.Time { return time.Unix(0, clock.Load()) }
	previousBlocking := identityLookupBlocking.Load()
	identityLookupBlocking.Store(true)
	t.Cleanup(func() { identityLookupBlocking.Store(previousBlocking) })
	set := &guardrailProfileSet{
		profiles: map[string]config.DerivedGuardrailProfile{
			"assigned": {Config: &config.Config{}}, "strict": {Config: &config.Config{}},
		},
		defaultProfile: "strict",
		assignments:    []config.ProfileAssignment{{Profile: "assigned", Match: config.ProfileMatch{Groups: []string{"r103-hook-first"}}}},
	}
	hook := func() profileDecision {
		ctx := attachVerifiedSubject(context.Background(), nil, strconv.Itoa(uid), "hook-first", subjectSourcePeerCredentials)
		ctx = withGuardrailProfile(ctx, set, "claudecode")
		return resolvedGuardrailProfileFrom(ctx).decision
	}
	hook() // a cold hook starts the listing; no administrator read warms it
	waitListed(t, managedHookPeerAccounts)
	if got := hook(); got.Name != "assigned" || got.MatchedGroup != "r103-hook-first" {
		t.Fatalf("initial hook profile = %+v", got)
	}
	facts.set("staff")
	account.PrimaryGID = "80"
	listing.set(map[string]unixidentity.LocalAccountRecord{"hook-first": account})
	clock.Add(int64(managedHookPeerListedStampInterval + time.Second))
	hook() // the first request after the interval starts its own refresh
	waitListed(t, managedHookPeerAccounts)
	if got := hook(); got.Name != "strict" || got.MatchedGroup != "" {
		t.Fatalf("hook kept the prior account groups without explain: %+v", got)
	}
}
