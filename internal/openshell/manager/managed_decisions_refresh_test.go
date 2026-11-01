// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0608: a managed daemon's start-up refresh of the policies runs
// before it serves, and loaded each sandbox's saved decisions in turn, up
// to loadDecisionsTimeout each: with the managed gateway slow to answer
// them, three sandboxes held the daemon back 15 s. A refresh now waits one
// load for all of them. The start refreshes again at once (the egress
// proxy, the confirmed floor): those do not wait for a registration whose
// load got no answer within decisionsRetryAfter. The first refresh after
// that asks again and applies its decisions.
func TestARefreshWaitsOneDecisionsLoadNotOnePerSandbox(t *testing.T) {
	e, auth := managedEnv(t, nil)
	names := []string{"slowbox1", "slowbox2", "slowbox3"}
	for _, n := range names {
		e.live(sandboxapi.CreateRequest{Name: n, Copy: true})
		e.register(n)
	}
	st := e.m.managedSide()
	st.mu.Lock()
	clear(st.decisions) // as a daemon that just started: nothing loaded yet
	st.mu.Unlock()
	auth.hang.Store(true)
	start := time.Now()
	e.m.RefreshPolicies()
	if took := time.Since(start); took >= 2*loadDecisionsTimeout {
		t.Fatalf("a refresh of %d sandboxes took %s on a gateway that does not answer their decisions, want under %s",
			len(names), took.Round(time.Second), 2*loadDecisionsTimeout)
	}
	hung := auth.hungLoads.Load()
	if hung < int64(len(names)) {
		t.Fatalf("the refresh asked %d decisions loads, want one per sandbox (%d)", hung, len(names))
	}
	// The start-up refreshes that follow at once do not wait again.
	e.m.RefreshPolicies()
	e.m.RefreshPolicies()
	if again := auth.hungLoads.Load() - hung; again != 0 {
		t.Fatalf("%d decisions loads waited again within decisionsRetryAfter of no answer", again)
	}
	// decisionsRetryAfter passes: the misses move that far into the past
	// (the running manager reads its clock, which the test leaves alone).
	st.mu.Lock()
	if len(st.unanswered) < len(names) {
		t.Fatalf("missed loads recorded: %v", st.unanswered)
	}
	for r, at := range st.unanswered {
		st.unanswered[r] = at.Add(-decisionsRetryAfter)
	}
	st.mu.Unlock()
	auth.hang.Store(false)
	id := sandboxreg.IDPrefix + strings.Repeat("a", sandboxreg.IDRandomChars-len(names[0])) + names[0]
	auth.set(func(a *fakeAuthority) {
		a.saved = map[string][]sandboxrelay.Decision{id: {{ID: "dec-1", Registration: id, Kind: sandboxrelay.DecisionUnblock,
			Host: "webhook.site", Scope: sandboxrelay.DecisionScopeAlways}}}
	})
	e.m.RefreshPolicies()
	if !e.decideEgress(names[0], "webhook.site").Allowed {
		t.Fatal("the next refresh did not load the saved decisions the slow load missed")
	}
}
