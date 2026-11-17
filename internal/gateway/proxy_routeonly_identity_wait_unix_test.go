// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// rel-1-0-10:GAP-1155: when several directory accounts start agents at once
// the first lookup of each account outlasts the 2 s hook budget. The first
// route-only model calls of every new session were refused
// identity_unconfirmed:identity and routing status listed every user and
// group rule as matched. A route-only call now waits for the cold lookup
// (routeOnlyIdentityWait), so each account gets its own rule only; an
// account whose lookup fails is refused naming the directory, and no rule is
// listed as matched.
func TestRouteOnlyManagedWaitsForAColdDirectoryLookup(t *testing.T) {
	f := newRouteOnlyFixture(t)
	f.cfg.DeploymentMode = "managed_enterprise"
	f.cfg.Enterprise.Profile = "standalone"
	f.cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{
		{ID: "eng1-haiku", Match: config.RoutingAdminMatch{Users: []string{"1001"}}, Allow: []string{"haiku"}},
		{ID: "eng2-haiku", Match: config.RoutingAdminMatch{Users: []string{"1002"}}, Allow: []string{"haiku"}},
		{ID: "contractors-no-cloud", Match: config.RoutingAdminMatch{Groups: []string{"contractors"}}, Action: "deny", Message: "contractors use the local model"},
	}}

	const slow = identityDirectoryBudget + 600*time.Millisecond
	groups := map[string][]string{"1001": {"eng"}, "1002": {"eng"}, "1003": {"contractors"}}
	previousHomes, previousFacts, previousBlocking := managedHookPeerHomes, identityFactsEnabled.Load(), identityLookupBlocking.Load()
	previousConfirmed, previousFresh, previousExists := managedHookPeerAccountsConfirmed, managedHookDirectoryNeedsFresh, profileGroupExists
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountsConfirmed, managedHookDirectoryNeedsFresh = previousHomes, previousConfirmed, previousFresh
		profileGroupExists = previousExists
		setIdentityFactsEnabled(previousFacts)
		setIdentityLookupBlocking(previousBlocking)
	})
	setIdentityFactsEnabled(true)
	setIdentityLookupBlocking(true)
	managedHookPeerAccountsConfirmed = func() bool { return true }
	managedHookDirectoryNeedsFresh = false
	profileGroupExists = func(context.Context, string) (bool, error) { return true, nil }
	homes := &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver {
		return readOnlyPeerResolver{accounts: map[int]unixidentity.Account{
			1001: {Name: "eng1", UID: 1001, Home: "/home/eng1"},
			1002: {Name: "eng2", UID: 1002, Home: "/home/eng2"},
			1003: {Name: "ctr1", UID: 1003, Home: "/home/ctr1"},
			1004: {Name: "gone1", UID: 1004, Home: "/home/gone1"},
		}}
	}, now: time.Now}
	homes.directoriesOnce.Do(func() {
		homes.directories = newIdentityDirectoryCache(func(key string) (useridentity.DirectoryFacts, error) {
			if key == "1004" {
				return useridentity.DirectoryFacts{}, errors.New("sssd: domain controller unreachable")
			}
			// A cold SSSD answering a burst of sign-ins.
			time.Sleep(slow)
			return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Groups: groups[key], ResolvedAt: time.Now()}, nil
		})
	})
	managedHookPeerHomes = homes

	decideAs := func(uid string) SemanticRouteOutcome {
		r := httptest.NewRequest(http.MethodPost, "/r/claudecode/v1/messages", nil)
		r = r.WithContext(routeOnlyManagedContext(r.Context(), uid, "claudecode"))
		caller, profiles := routeOnlyCaller(r.Context(), uid)
		body := []byte(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"a quick question"}]}`)
		_, out, _ := f.srv.decide(r, f.cfg, "claudecode", "/v1/messages", config.RoutingAPIMessages, f.cfg.Routing.RouteOnly.Upstreams["claudecode"], engine.CredentialAPIKey, nil, body, caller, profiles)
		return out
	}
	ruleIDs := func(o SemanticRouteOutcome) []string {
		if o.Route == nil {
			return nil
		}
		return o.Route.RuleIDs
	}
	denyCode := func(o SemanticRouteOutcome) string {
		if o.Deny == nil {
			return ""
		}
		return o.Deny.Code
	}

	// Three accounts start their sessions at once; every lookup is cold.
	accounts := []string{"1001", "1002", "1003"}
	outs := make([]SemanticRouteOutcome, len(accounts))
	var wg sync.WaitGroup
	for i, uid := range accounts {
		wg.Add(1)
		go func() { defer wg.Done(); outs[i] = decideAs(uid) }()
	}
	wg.Wait()
	for i, want := range []string{"eng1-haiku", "eng2-haiku"} {
		if outs[i].Result == SemanticRouteDenied || !slices.Equal(ruleIDs(outs[i]), []string{want}) {
			t.Fatalf("%s first call: deny %q rule ids %v, want allowed by %s only", accounts[i], denyCode(outs[i]), ruleIDs(outs[i]), want)
		}
	}
	if contractor := outs[2]; denyCode(contractor) != "rule_deny:contractors-no-cloud" || !slices.Equal(ruleIDs(contractor), []string{"contractors-no-cloud"}) {
		t.Fatalf("1003 first call: deny %q rule ids %v, want its own group deny only", denyCode(contractor), ruleIDs(contractor))
	}

	// A lookup that fails is not waited for, names the directory, and lists
	// no rule as matched.
	start := time.Now()
	failed := decideAs("1004")
	if denyCode(failed) != "identity_unconfirmed:directory" || len(ruleIDs(failed)) != 0 {
		t.Fatalf("failed lookup: deny %q rule ids %v, want identity_unconfirmed:directory and no rule", denyCode(failed), ruleIDs(failed))
	}
	if waited := time.Since(start); waited > identityDirectoryBudget+time.Second {
		t.Fatalf("a failed lookup was waited for %s", waited)
	}
}

// readOnlyPeerResolver answers account lookups from a fixed table; it keeps
// no call count, so concurrent sessions can share it under -race.
type readOnlyPeerResolver struct {
	unixidentity.Resolver
	accounts map[int]unixidentity.Account
}

func (r readOnlyPeerResolver) LookupUID(uid int) (unixidentity.Account, error) {
	if account, ok := r.accounts[uid]; ok {
		return account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}
