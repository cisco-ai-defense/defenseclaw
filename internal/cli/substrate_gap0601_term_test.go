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

package cli

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// GAP-0601 (IB5 TST-2593): becoming the leader starts a new chain start
// grace term, then reports ready; the grace then runs from the term's first
// call, not from a clear check long after it.
func TestLeaderStartedStartsAGraceTermGAP0601(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 11, 18, 11, 11, 58, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	// The leader options without the registrations (no store here).
	svc, err := chainstate.New(chainstate.Options{Dir: t.TempDir(), Now: clock, StartGrace: leaderChainStartGrace})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	post := chainstate.EgressRequest{Actor: chainstate.Actor{Atespace: "dc-eng", UID: "caa20383-acf7-4766-954d-b2f9871ed97e"},
		Name: "p2b-git1", Host: "github.com", Method: "POST"}
	// An earlier term served a call long ago: a clear check is answered.
	svc.LeaderCall()
	advance(time.Minute)
	if v, err := svc.Egress(context.Background(), post); err != nil || v.Deny {
		t.Fatalf("a minute into the term: %+v %v", v, err)
	}
	var ready atomic.Bool
	substrateLeaderStarted(io.Discard, "leader-0", svc, &ready)
	if !ready.Load() {
		t.Fatal("not ready after becoming the leader")
	}
	svc.LeaderCall()
	advance(6 * time.Second)
	var we *leader.WireError
	if _, err := svc.Egress(context.Background(), post); !errors.As(err, &we) || we.Code != leader.CodeUnavailable {
		t.Fatalf("6 s into the new term: want unavailable (the start grace), got %v", err)
	}
	advance(leaderChainStartGrace)
	if v, err := svc.Egress(context.Background(), post); err != nil || v.Deny {
		t.Fatalf("past the grace of the new term: %+v %v", v, err)
	}
	// No chain state (it failed to open): still ready.
	var ready2 atomic.Bool
	substrateLeaderStarted(io.Discard, "leader-0", nil, &ready2)
	if !ready2.Load() {
		t.Fatal("not ready without chain state")
	}
}
