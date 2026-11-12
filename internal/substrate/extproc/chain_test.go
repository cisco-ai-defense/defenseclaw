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
	checkers := map[string]ChainChecker{
		uncheckedError:    fakeChecker{err: errors.New("leader down")},
		uncheckedTimeout:  fakeChecker{delay: 80 * time.Millisecond},
		uncheckedInternal: panicChecker{},
	}
	for why, chk := range checkers {
		t.Run(why, func(t *testing.T) {
			// auto, interactive: allowed with an alert.
			h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = chk })
			v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/"))
			if !v.Allow || !v.Alert || !strings.Contains(strings.Join(v.Findings, ","), "chain_unchecked:"+why) {
				t.Fatalf("interactive: %+v", v)
			}
			// auto, unattended: refused, retryable.
			h = newHarness(t, func(c *Config, o *Options) {
				o.ChainChecker = chk
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

// One actor's flood of checks takes at most chainPerActorInflight slots;
// another actor's check still runs.
func TestChainPerActorCap(t *testing.T) {
	g := &gateChecker{gate: make(chan struct{})}
	h := newHarness(t, func(c *Config, o *Options) { o.ChainChecker = g; c.Chain.CheckBudget = 300 * time.Millisecond })
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
	if !strings.Contains(strings.Join(v.Findings, ","), "chain_unchecked:"+uncheckedBusy) || time.Since(start) > 100*time.Millisecond {
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
