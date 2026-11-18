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

package chainstate

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// GAP-0601 (IB5 TST-2593): the first git clone of a fresh actor, about 75 s
// after a leader restart, got GET info/refs refused chain_unchecked timeout
// at 256 ms on a healthy leader; later clones took about 1 ms. Cause: the
// start grace ran from the leader's first clear egress check with no bound,
// so the first clear check after any restart was answered unavailable (the
// callout's leader client retried it until the 250 ms send budget ran out),
// however long after the restart it came. These tests drive the callout's
// real path: leader.Server with the chain state and another store's method,
// and the callout's leader client (Retry 1 s) under the 250 ms send budget.
// They use only API that rel has, so they run at rel unchanged.

// coldLeaderBudget is the callout's chain.send_budget (default 250 ms).
const coldLeaderBudget = 250 * time.Millisecond

// coldLeader is a restarted leader with the production start grace; its
// term starts now.
func coldLeader(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), now: time.Date(2026, 11, 18, 11, 11, 58, 0, time.UTC)}
	svc, err := New(Options{Dir: h.dir, Now: h.clock, StartGrace: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ls := &leader.Server{IsLeader: func() bool { return true }}
	svc.Register(ls)
	// A read of another store on the same leader: the callout's
	// registration lookup before its chain check.
	ls.HandleRead(leader.MethodRegistrationGet, func(context.Context, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	})
	h.svc, h.srv = svc, httptest.NewServer(ls)
	h.client = &Client{Leader: &leader.Client{BaseURL: h.srv.URL, HTTP: h.srv.Client(), Retry: time.Second}}
	t.Cleanup(func() { h.srv.Close(); _ = svc.Close() })
	return h
}

// otherCall is one call of another store the leader serves.
func (h *harness) otherCall() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.client.Leader.Call(ctx, leader.MethodRegistrationGet, "", struct{}{}, nil); err != nil {
		h.t.Fatalf("registration read: %v", err)
	}
}

// calloutCheck is one callout chain check under the send budget, with its
// wall-clock latency.
func (h *harness) calloutCheck(in EgressRequest) (EgressVerdict, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), coldLeaderBudget)
	defer cancel()
	start := time.Now()
	v, err := h.client.CheckEgress(ctx, in)
	return v, time.Since(start), err
}

var freshGit = Actor{Atespace: "dc-eng", UID: "caa20383-acf7-4766-954d-b2f9871ed97e"}

// cloneAnswered checks a fresh actor's HTTPS clone (its registration
// lookup, GET info/refs, then POST git-upload-pack): answered clear, at once.
func (h *harness) cloneAnswered(when string) {
	h.t.Helper()
	h.otherCall()
	for _, m := range []string{"GET", "POST"} {
		v, took, err := h.calloutCheck(EgressRequest{Actor: freshGit, Name: "p2b-git1", Host: "github.com", Method: m})
		if err != nil || v.Deny || v.Stale {
			h.t.Fatalf("%s: fresh actor %s github.com: %+v %v after %s, want a clear answer (IB5: chain_unchecked timeout at 256 ms)",
				when, m, v, err, took)
		}
		if took > coldLeaderBudget/2 {
			h.t.Fatalf("%s: fresh actor %s answered after %s, want well inside the %s send budget", when, m, took, coldLeaderBudget)
		}
	}
}

// The first clear check comes 75 s after the leader started.
func TestFirstCloneLongAfterLeaderStartGAP0601(t *testing.T) {
	h := coldLeader(t)
	h.advance(75 * time.Second)
	h.cloneAnswered("75 s after the leader started")
}

// The IB5 sequence: after the restart the leader's only chain traffic is a
// hit (the S2 send refused chain_egress at 11:12:28), then a fresh actor's
// clone 41 s later (11:13:09).
func TestFirstCloneAfterAHitGAP0601(t *testing.T) {
	h := coldLeader(t)
	h.advance(30 * time.Second)
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.advance(time.Second)
	if v, _, err := h.calloutCheck(EgressRequest{Actor: actorA, Name: "p2b-ldr", Host: "github.com", Method: "POST"}); err != nil || !v.Deny {
		t.Fatalf("S2 send after the secret read: %+v %v, want chain_egress", v, err)
	}
	h.advance(41 * time.Second)
	h.cloneAnswered("41 s after a hit")
}

// The S2 property stays: a clear send soon after the leader is back is
// refused (unchecked), a hit is answered at once, and a clear send is
// answered once the grace is over.
func TestSendSoonAfterTheLeaderIsBackStillRefusedGAP0601(t *testing.T) {
	h := coldLeader(t)
	h.otherCall()
	h.advance(6 * time.Second)
	post := EgressRequest{Actor: actorB, Name: "b", Host: "github.com", Method: "POST"}
	if v, took, err := h.calloutCheck(post); err == nil {
		t.Fatalf("clear send 6 s after the leader is back: %+v after %s, want unchecked (refused by the callout)", v, took)
	}
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.advance(time.Second)
	if v, _, err := h.calloutCheck(EgressRequest{Actor: actorA, Name: "a", Host: "github.com", Method: "POST"}); err != nil || !v.Deny {
		t.Fatalf("hit within the grace: %+v %v", v, err)
	}
	h.advance(15 * time.Second)
	if v, _, err := h.calloutCheck(post); err != nil || v.Deny {
		t.Fatalf("clear send 22 s after the leader is back: %+v %v", v, err)
	}
}
