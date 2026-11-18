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
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// GAP-0601 follow-up (balanced defaults): a chain check whose miss refuses
// the request waits chain.send_budget (250 ms), and so does the registration
// refresh that confirms a pass, so a slow but healthy leader (GAP-0564)
// still answers HTTPS git, which starts every fetch and push with a GET of
// info/refs. Only a leader that is down, or slower than the budget, gets the
// refusal.

// gitRequests is what HTTPS git sends: a clone, a fetch on the cached
// registration, and a push, each a GET of info/refs and a POST with a body.
func gitRequests(atespace string) []*Request {
	get := func(svc string) *Request {
		return req(atespace, "GET", "example.com", "/acme/app.git/info/refs?service="+svc)
	}
	post := func(svc string) *Request {
		r := req(atespace, "POST", "example.com", "/acme/app.git/"+svc, "content-type", "application/x-"+svc+"-request")
		r.EndOfStream, r.ContentLength = false, 230
		return r
	}
	return []*Request{get("git-upload-pack"), post("git-upload-pack"), get("git-upload-pack"),
		post("git-upload-pack"), get("git-receive-pack"), post("git-receive-pack")}
}

type gitMode struct {
	name       string
	cfg        func(*Config)
	unattended bool
}

// gitModes are the four ways an unchecked request is decided: attended OSS
// (auto: a GET's miss is alerted), managed, chain.failure_mode closed, and
// an unattended actor (each refuses every unchecked request).
var gitModes = []gitMode{
	{name: "attended"},
	{name: "managed", cfg: func(c *Config) { c.Managed = true }},
	{name: "closed", cfg: func(c *Config) { c.Chain.FailureMode = FailureClosed }},
	{name: "unattended", unattended: true},
}

// slowLeaderHarness is a leader that answers chain checks (with v) and
// registration lookups after delay. send, when set, is chain.send_budget.
func slowLeaderHarness(t *testing.T, m gitMode, delay, send time.Duration, v ChainVerdict) *harness {
	t.Helper()
	h := newHarness(t, func(c *Config, o *Options) {
		o.ChainChecker = fakeChecker{delay: delay, v: v}
		if send > 0 {
			c.Chain.SendBudget, c.Ask.Hold = send, MessageBudget-send
		}
		if m.cfg != nil {
			m.cfg(c)
		}
	})
	h.uids.delay, h.uids.unattended = delay, m.unattended
	return h
}

func uncheckedFinding(v Verdict) bool {
	return slices.ContainsFunc(v.Findings, func(f string) bool { return strings.HasPrefix(f, "chain_unchecked") })
}

// The P1 of the 6a93ec78ba review: at 20 ms, the GET of info/refs was
// refused on a managed or closed install and for an unattended actor, and
// on an attended actor's cached registration the 20 ms refresh refused it
// as registration_unconfirmed, so git failed on a slow but healthy leader.
func TestGitOnASlowHealthyLeaderGAP0601(t *testing.T) {
	leaders := []struct{ delay, send time.Duration }{
		{100 * time.Millisecond, 0},
		{150 * time.Millisecond, 0},
		{380 * time.Millisecond, 500 * time.Millisecond},
	}
	for _, m := range gitModes {
		for _, l := range leaders {
			t.Run(fmt.Sprintf("%s/leader-%s", m.name, l.delay), func(t *testing.T) {
				t.Parallel()
				h := slowLeaderHarness(t, m, l.delay, l.send, ChainVerdict{})
				for i, r := range gitRequests("eng-web") {
					start := time.Now()
					v := h.eng.DecideHeaders(context.Background(), r)
					if !v.Allow {
						t.Fatalf("request %d, %s %s, refused on a healthy leader answering in %s: %+v", i, r.Method, r.Path, l.delay, v)
					}
					// Only the clone's first GET, attended on a registration
					// resolved for it, may miss its 20 ms (alerted).
					if uncheckedFinding(v) && (i > 0 || m.name != "attended") {
						t.Fatalf("request %d, %s %s, unchecked on a leader answering in %s: %+v", i, r.Method, r.Path, l.delay, v)
					}
					if d := time.Since(start); d > MessageBudget {
						t.Fatalf("request %d took %s, over the message budget", i, d)
					}
				}
			})
		}
	}
}

// A slow leader's hit is still answered, and refuses every git request as
// chain_egress (the laptop verdict), in every mode.
func TestGitHitOnASlowLeaderRefusedGAP0601(t *testing.T) {
	for _, m := range gitModes {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			h := slowLeaderHarness(t, m, 150*time.Millisecond, 0, ChainVerdict{Deny: true, Rule: "secret_read_then_egress"})
			for i, r := range gitRequests("eng-web")[1:] {
				if v := h.eng.DecideHeaders(context.Background(), r); v.Allow || v.Category != CategoryChainEgress {
					t.Fatalf("request %d, %s %s: want chain_egress: %+v", i+1, r.Method, r.Path, v)
				}
			}
		})
	}
}

// Control: with the leader down, or not answering within the budget, every
// git POST is still refused, retryable, in every mode, and a GET is refused
// where the policy refuses unchecked egress.
func TestGitWithTheLeaderDownOrHungStillRefusedGAP0601(t *testing.T) {
	ctx := context.Background()
	for _, m := range gitModes {
		t.Run(m.name+"/down", func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, func(c *Config, o *Options) {
				o.ChainChecker = fakeChecker{err: errors.New("leader down")}
				if m.cfg != nil {
					m.cfg(c)
				}
			})
			h.uids.unattended = m.unattended
			clock := time.Now()
			h.eng.uids.now = func() time.Time { return clock }
			h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")) // caches the registration
			leaderDown(h)
			clock = clock.Add(5 * time.Minute)
			for i, r := range gitRequests("eng-web") {
				start := time.Now()
				v := h.eng.DecideHeaders(ctx, r)
				if d := time.Since(start); d > 150*time.Millisecond {
					t.Fatalf("request %d, leader down: took %s, want an answer at once", i, d)
				}
				wantGitRefused(t, m, i, r, v)
			}
		})
		t.Run(m.name+"/hung", func(t *testing.T) {
			t.Parallel()
			h := slowLeaderHarness(t, m, 0, 0, ChainVerdict{})
			if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow {
				t.Fatalf("leader up: %+v", v)
			}
			// The leader stops answering: checks and lookups hang.
			h.eng.checker = fakeChecker{delay: 3 * time.Second}
			h.uids.mu.Lock()
			h.uids.delay = 3 * time.Second
			h.uids.mu.Unlock()
			for i, r := range gitRequests("eng-web") {
				start := time.Now()
				v := h.eng.DecideHeaders(ctx, r)
				if d := time.Since(start); d > MessageBudget {
					t.Fatalf("request %d, leader hung: took %s, over the message budget", i, d)
				}
				if r.Method == "POST" {
					wantGitRefused(t, m, i, r, v)
				} else if m.name != "attended" && v.Allow {
					t.Fatalf("request %d, %s %s, leader hung: allowed where unchecked egress is refused: %+v", i, r.Method, r.Path, v)
				}
			}
		})
	}
}

func wantGitRefused(t *testing.T, m gitMode, i int, r *Request, v Verdict) {
	t.Helper()
	if r.Method == "GET" && m.name == "attended" {
		if !v.Allow || !v.Alert {
			t.Fatalf("request %d, attended GET, leader down: want allowed with an alert: %+v", i, v)
		}
		return
	}
	if v.Allow || v.Category != CategoryChainUnchecked || !v.Retryable {
		t.Fatalf("request %d, %s %s, leader down: want refused chain_unchecked, retryable: %+v", i, r.Method, r.Path, v)
	}
}

// Only an attended GET or HEAD on a registration resolved for it, whose
// miss is allowed with an alert, keeps check_budget (20 ms).
func TestAttendedFreshGetKeepsCheckBudgetGAP0601(t *testing.T) {
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = fakeChecker{delay: 200 * time.Millisecond} })
	start := time.Now()
	v := h.eng.DecideHeaders(context.Background(), req("eng-web", "GET", "example.com", "/"))
	if !v.Allow || !v.Alert || !slices.Contains(v.Findings, "chain_unchecked:"+uncheckedTimeout) {
		t.Fatalf("attended GET, slow leader: want allowed with an alert: %+v", v)
	}
	if d := time.Since(start); d > 150*time.Millisecond {
		t.Fatalf("attended GET took %s, budget 20ms", d)
	}
}

func TestSendBudgetIsBoundedGAP0601(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = fakeChecker{delay: 2 * time.Second} })
	start := time.Now()
	v := h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com"))
	wantSendRefused(t, "leader slower than send_budget", v, uncheckedTimeout)
	if d := time.Since(start); d < 200*time.Millisecond || d > 900*time.Millisecond {
		t.Fatalf("send check took %s, want about send_budget 250ms", d)
	}
	// The text holds for a slow leader and for one that can't be reached
	// (its client retries until the deadline), and names no config key.
	if !strings.Contains(v.Reason, "slow, overloaded or can't be reached") || strings.Contains(v.Reason, "send_budget") {
		t.Fatalf("timeout reason: %q", v.Reason)
	}
	// A longer check_budget wins over a shorter send_budget.
	h = newHarness(t, func(c *Config, o *Options) {
		o.ChainChecker = fakeChecker{delay: 300 * time.Millisecond}
		c.Chain.CheckBudget, c.Chain.SendBudget, c.Ask.Hold = 450*time.Millisecond, 100*time.Millisecond, time.Second
	})
	if v := h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")); !v.Allow {
		t.Fatalf("check_budget 450ms over send_budget 100ms, 300ms leader: %+v", v)
	}
	if h.eng.cfg.Chain.SendBudget != 450*time.Millisecond || h.eng.uids.confirmBudget != 450*time.Millisecond {
		t.Fatalf("send %s confirm %s, want check_budget 450ms", h.eng.cfg.Chain.SendBudget, h.eng.uids.confirmBudget)
	}
}

// The leader down keeps the refusal, without waiting for send_budget.
func TestSendBudgetLeaderDownStillRefusedGAP0601(t *testing.T) {
	ctx := context.Background()
	h, clock := outageHarness(t, false)
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow {
		t.Fatalf("lookup up: %+v", v)
	}
	leaderDown(h)
	*clock = clock.Add(5 * time.Minute)
	start := time.Now()
	wantSendRefused(t, "leader down", h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")), uncheckedLookup)
	if d := time.Since(start); d > 150*time.Millisecond {
		t.Fatalf("leader down: refusal took %s, want it at once", d)
	}
}

func TestSendBudgetConfigGAP0601(t *testing.T) {
	cfg, err := ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chain.SendBudget != 250*time.Millisecond || cfg.Chain.CheckBudget != 20*time.Millisecond {
		t.Fatalf("defaults: check %s send %s", cfg.Chain.CheckBudget, cfg.Chain.SendBudget)
	}
	if _, err := ParseConfig([]byte(testConfig + "\nchain:\n  send_budget: 600ms\n")); err == nil {
		t.Fatal("send_budget 600ms accepted, want at most 500ms")
	}
	if _, err := ParseConfig([]byte(testConfig + "\nchain:\n  send_budget: 400ms\n")); err == nil {
		t.Fatal("send_budget 400ms with ask.hold 1500ms accepted, want at most the 1.8s message budget together")
	}
}
