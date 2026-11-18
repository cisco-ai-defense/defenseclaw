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
	"slices"
	"strings"
	"testing"
	"time"
)

// GAP-0601: while the leader is down, an attended actor that read a secret
// could POST it to an allowed host (chain_unchecked:registration_unavailable,
// allowed with an alert), where a laptop, whose chain check needs no
// cluster, refuses it. A request that can carry data out is now refused in
// every mode while its chain check is missing; GET and HEAD keep the alert.

func postBody(atespace, host string) *Request {
	r := req(atespace, "POST", host, "/collect", "content-type", "application/octet-stream")
	r.EndOfStream, r.ContentLength = false, 42
	return r
}

func wantSendRefused(t *testing.T, name string, v Verdict, why string) {
	t.Helper()
	if v.Allow || v.Category != CategoryChainUnchecked || v.Rule != why || !v.Retryable ||
		!strings.Contains(v.Reason, "carry data out") || len(v.Reason) > 320 {
		t.Fatalf("%s: want refused chain_unchecked/%s, retryable: %+v", name, why, v)
	}
}

func TestAttendedSendRefusedWhileTheLeaderIsDownGAP0601(t *testing.T) {
	ctx := context.Background()
	h, clock := outageHarness(t, false)
	// Lookup up, chain down: the registration is cached.
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow {
		t.Fatalf("lookup up, chain down: attended GET refused: %+v", v)
	}
	leaderDown(h)
	*clock = clock.Add(5 * time.Minute)

	v := h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com"))
	wantSendRefused(t, "leader down, POST with a body", v, uncheckedLookup)
	if !strings.Contains(v.Reason, "leader") {
		t.Fatalf("reason does not name the outage: %q", v.Reason)
	}

	for name, r := range map[string]*Request{
		"PUT, no body":           req("eng-web", "PUT", "example.com", "/x"),
		"DELETE, no body":        req("eng-web", "DELETE", "example.com", "/x"),
		"PATCH, no body":         req("eng-web", "PATCH", "example.com", "/x"),
		"GET with a body":        func() *Request { r := req("eng-web", "GET", "example.com", "/"); r.EndOfStream = false; return r }(),
		"GET overridden to POST": req("eng-web", "GET", "example.com", "/", "x-http-method-override", "POST"),
		"GET ?_method=PUT":       req("eng-web", "GET", "example.com", "/x?_method=put"),
		"lower-case post":        req("eng-web", "post", "example.com", "/x"),
	} {
		wantSendRefused(t, name, h.eng.DecideHeaders(ctx, r), uncheckedLookup)
	}

	// Control: GET and HEAD keep the documented alert.
	for _, m := range []string{"GET", "HEAD"} {
		v := h.eng.DecideHeaders(ctx, req("eng-web", m, "example.com", "/"))
		if !v.Allow || !v.Alert || !slices.Contains(v.Findings, "chain_unchecked:"+uncheckedLookup) {
			t.Fatalf("leader down, %s: want allowed with an alert: %+v", m, v)
		}
	}
}

// A chain check that errs or times out with the registration lookup up
// (a leader that answers lookups from cache, a slow leader) is the same
// missing check: a send is refused, in every mode, explicit open included.
func TestSendRefusedOnEveryUncheckedReasonGAP0601(t *testing.T) {
	ctx := context.Background()
	const budget = 200 * time.Millisecond
	checkers := map[string]ChainChecker{
		uncheckedError:    fakeChecker{err: errors.New("leader down")},
		uncheckedTimeout:  fakeChecker{delay: 2 * budget},
		uncheckedInternal: panicChecker{},
	}
	for why, chk := range checkers {
		for _, mode := range []string{"", FailureOpen} {
			t.Run(why+"/"+mode, func(t *testing.T) {
				h := newHarness(t, func(c *Config, o *Options) {
					o.ChainChecker = chk
					c.Chain.CheckBudget = budget
					if mode != "" {
						c.Chain.FailureMode = mode
					}
				})
				wantSendRefused(t, "POST", h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")), why)
				if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow || !v.Alert {
					t.Fatalf("GET: want allowed with an alert: %+v", v)
				}
			})
		}
	}
}

// Leader up: a hit refuses the send as chain_egress (the laptop verdict),
// a clear check allows it, and an unregistered actor (no window) is not
// refused for a send.
func TestSendWithTheLeaderUpGAP0601(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, func(_ *Config, o *Options) {
		o.ChainChecker = fakeChecker{v: ChainVerdict{Deny: true, Rule: "secret_read_then_egress"}}
	})
	if v := h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")); v.Allow || v.Category != CategoryChainEgress {
		t.Fatalf("leader up, chain hit: want chain_egress: %+v", v)
	}
	h = newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = fakeChecker{} })
	if v := h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")); !v.Allow || v.Category == CategoryChainUnchecked {
		t.Fatalf("leader up, chain clear: want allowed: %+v", v)
	}
	h = newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = fakeChecker{} })
	h.uids.uid = ""
	if v := h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")); !v.Allow ||
		!slices.Contains(v.Findings, "chain_unchecked:"+uncheckedUnregistered) {
		t.Fatalf("unregistered actor: want allowed with an alert: %+v", v)
	}
}

// Unattended and closed keep their refusal and its text for every request.
func TestUnattendedAndClosedUnchangedGAP0601(t *testing.T) {
	ctx := context.Background()
	h, _ := outageHarness(t, true)
	for _, r := range []*Request{req("eng-web", "GET", "example.com", "/"), postBody("eng-web", "example.com")} {
		v := h.eng.DecideHeaders(ctx, r)
		if v.Allow || v.Category != CategoryChainUnchecked || !strings.Contains(v.Reason, "refuses unchecked egress") {
			t.Fatalf("unattended %s: %+v", r.Method, v)
		}
	}
	h = newHarness(t, func(c *Config, o *Options) {
		o.ChainChecker = fakeChecker{err: errors.New("leader down")}
		c.Chain.FailureMode = FailureClosed
	})
	for _, r := range []*Request{req("eng-web", "GET", "example.com", "/"), postBody("eng-web", "example.com")} {
		if v := h.eng.DecideHeaders(ctx, r); v.Allow || !strings.Contains(v.Reason, "refuses unchecked egress") {
			t.Fatalf("closed %s: %+v", r.Method, v)
		}
	}
}
