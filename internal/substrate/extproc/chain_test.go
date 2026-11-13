// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type panicChecker struct{}

func (panicChecker) CheckEgress(context.Context, ChainStep) (ChainVerdict, error) { panic("boom") }

// gateChecker holds every check until released.
type gateChecker struct {
	gate chan struct{}
	mu   sync.Mutex
	n    int
}

func (g *gateChecker) CheckEgress(ctx context.Context, _ ChainStep) (ChainVerdict, error) {
	g.mu.Lock()
	g.n++
	g.mu.Unlock()
	<-g.gate
	return ChainVerdict{}, nil
}

// unattendedPolicies marks every actor unattended (what a
// registration-backed PolicySource does for an unattended registration).
type unattendedPolicies struct{ base PolicySource }

func (u unattendedPolicies) PolicyFor(ctx context.Context, a ActorRef) (*Policy, error) {
	p, err := u.base.PolicyFor(ctx, a)
	if err != nil {
		return nil, err
	}
	cp := *p
	cp.Unattended = true
	return &cp, nil
}

// TestChainUncheckedFollowsFailureMode is GAP-0090: an error, a timeout or
// a panic in the chain check is not a silent allow.
func TestChainUncheckedFollowsFailureMode(t *testing.T) {
	ctx := context.Background()
	// A budget a loaded race-detector run can't miss for an immediate error
	// or panic; the timeout checker sleeps well past it.
	const budget = 200 * time.Millisecond
	checkers := map[string]ChainChecker{
		uncheckedError:    fakeChecker{err: errors.New("leader down")},
		uncheckedTimeout:  fakeChecker{delay: 2 * budget},
		uncheckedInternal: panicChecker{},
	}
	for why, chk := range checkers {
		t.Run(why, func(t *testing.T) {
			// auto, interactive: allowed with an alert.
			h := newHarness(t, func(c *Config, o *Options) { o.ChainChecker = chk; c.Chain.CheckBudget = budget })
			v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
			if !v.Allow || !v.Alert || !strings.Contains(strings.Join(v.Findings, ","), "chain_unchecked:"+why) {
				t.Fatalf("interactive: %+v", v)
			}
			// auto, unattended: refused, retryable.
			h = newHarness(t, func(c *Config, o *Options) {
				o.ChainChecker = chk
				c.Chain.CheckBudget = budget
				sp, err := NewStaticPolicies(c)
				if err != nil {
					t.Fatal(err)
				}
				o.Policies = unattendedPolicies{sp}
			})
			v = h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
			if v.Allow || v.Category != CategoryChainUnchecked || !v.Retryable || v.Rule != why {
				t.Fatalf("unattended: %+v", v)
			}
			// closed: refused for everyone; open: never.
			h = newHarness(t, func(c *Config, o *Options) { o.ChainChecker = chk; c.Chain.FailureMode = FailureClosed })
			if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); v.Allow {
				t.Fatalf("closed: %+v", v)
			}
			h = newHarness(t, func(c *Config, o *Options) {
				o.ChainChecker = chk
				c.Chain.FailureMode = FailureOpen
				sp, _ := NewStaticPolicies(c)
				o.Policies = unattendedPolicies{sp}
			})
			if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow || !v.Alert {
				t.Fatalf("open: %+v", v)
			}
		})
	}
}

// TestChainShippedWiring is GAP-0090 as shipped: the resolver's
// registration names the UID, profile and attendance. An actor with no
// registration is unchecked (an alert on OSS, refused on a managed
// install), an unattended registration is refused on an unchecked step,
// and the registration's profile wins over the atespace's.
func TestChainShippedWiring(t *testing.T) {
	ctx := context.Background()
	var seen []ChainStep
	var mu sync.Mutex
	rec := checkerFunc(func(_ context.Context, s ChainStep) (ChainVerdict, error) {
		mu.Lock()
		seen = append(seen, s)
		mu.Unlock()
		return ChainVerdict{}, nil
	})

	// Unregistered (live, no UID): never "clear", the checker is not asked.
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = rec })
	h.uids.uid = ""
	v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
	if !v.Allow || !v.Alert || !strings.Contains(strings.Join(v.Findings, ","), "chain_unchecked:"+uncheckedUnregistered) || len(seen) != 0 {
		t.Fatalf("oss unregistered: %+v (checker saw %d)", v, len(seen))
	}
	hm := newHarness(t, func(c *Config, o *Options) { c.Managed = true; o.ChainChecker = rec })
	hm.uids.uid = ""
	if v := hm.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); v.Allow || v.Category != CategoryChainUnchecked ||
		v.Rule != uncheckedUnregistered || !v.Retryable {
		t.Fatalf("managed unregistered: %+v", v)
	}

	// Registered: the checker gets the registration's UID.
	h = newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = rec })
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow || v.Alert || len(seen) != 1 || seen[0].Actor.UID != "uid-1" {
		t.Fatalf("registered: %+v steps %+v", v, seen)
	}

	// Unattended registration, OSS auto: an unchecked step is refused,
	// with the default StaticPolicies (no test-only PolicySource).
	h = newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = fakeChecker{err: errors.New("leader down")} })
	h.uids.unattended = true
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); v.Allow || v.Category != CategoryChainUnchecked {
		t.Fatalf("unattended registration: %+v", v)
	}
	h.uids.unattended = false
	h.eng.InvalidateActor("eng-web", "a1")
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow || !v.Alert {
		t.Fatalf("interactive registration: %+v", v)
	}

	// The registration's profile wins: an actor in an atespace the base
	// profile covers, registered with eng, gets eng's block list.
	h = newHarness(t, nil)
	h.uids.profile = "eng"
	if v := h.eng.DecideHeaders(ctx, req("ops", "GET", "blocked.example.net", "/")); v.Allow || v.Profile != "eng" {
		t.Fatalf("registration profile: %+v", v)
	}
	// A profile this callout does not have falls back to the atespace.
	h = newHarness(t, nil)
	h.uids.profile = "gone"
	if v := h.eng.DecideHeaders(ctx, req("ops", "GET", "blocked.example.net", "/")); !v.Allow || v.Profile != "base" {
		t.Fatalf("unknown registration profile: %+v", v)
	}
}

type checkerFunc func(context.Context, ChainStep) (ChainVerdict, error)

func (f checkerFunc) CheckEgress(ctx context.Context, s ChainStep) (ChainVerdict, error) {
	return f(ctx, s)
}

// A burst of parallel requests from one actor (a package install) is
// checked, not refused: over the cap a check waits for a slot within its
// budget.
func TestChainBurstIsChecked(t *testing.T) {
	slowish := checkerFunc(func(context.Context, ChainStep) (ChainVerdict, error) {
		time.Sleep(2 * time.Millisecond)
		return ChainVerdict{}, nil
	})
	h := newHarness(t, func(c *Config, o *Options) {
		c.Managed = true
		o.ChainChecker = slowish
		c.Chain.CheckBudget = 200 * time.Millisecond
	})
	ctx := context.Background()
	var wg sync.WaitGroup
	var refused sync.Map
	for i := 0; i < 4*chainPerActorInflight; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow {
				refused.Store(i, v.Rule)
			}
		}()
	}
	wg.Wait()
	refused.Range(func(k, v any) bool { t.Errorf("request %v refused: %v", k, v); return true })
}

// One actor's flood of checks takes at most chainPerActorInflight slots;
// another actor's check still runs.
func TestChainPerActorCap(t *testing.T) {
	g := &gateChecker{gate: make(chan struct{})}
	h := newHarness(t, func(c *Config, o *Options) { o.ChainChecker = g; c.Chain.CheckBudget = 150 * time.Millisecond })
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < chainPerActorInflight; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")) }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		g.mu.Lock()
		n := g.n
		g.mu.Unlock()
		if n == chainPerActorInflight || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	start := time.Now()
	v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
	if !strings.Contains(strings.Join(v.Findings, ","), "chain_unchecked:"+uncheckedBusy) || time.Since(start) > time.Second {
		t.Fatalf("over the cap: %+v after %s", v, time.Since(start))
	}
	other := req("eng-web", "GET", "example.com", "/")
	other.Actor.Name = "a2"
	done := make(chan Verdict, 1)
	go func() { done <- h.eng.DecideHeaders(ctx, other) }()
	time.Sleep(20 * time.Millisecond)
	close(g.gate)
	if v := <-done; strings.Contains(strings.Join(v.Findings, ","), uncheckedBusy) {
		t.Fatalf("another actor was capped: %+v", v)
	}
	wg.Wait()
}
