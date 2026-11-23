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

package asks

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRV4F1OneDecisionWins: while one always decision on an ask is in
// flight (its registration hook is running; a once approval runs no hook,
// GAP-0484), a second decision is refused as already answered, and the
// expiry does not overtake it: the answer the caller gets is the answer the
// store keeps.
func TestRV4F1OneDecisionWins(t *testing.T) {
	ctx := context.Background()
	var clock atomic.Int64
	clock.Store(time.Unix(1_800_000_000, 0).UnixNano())
	s := NewMemory()
	s.Now = func() time.Time { return time.Unix(0, clock.Load()) }
	entered, release := make(chan struct{}, 1), make(chan struct{})
	s.OnApprove = func(context.Context, Ask) error { entered <- struct{}{}; <-release; return nil }

	for _, tc := range []string{"deny meanwhile", "expiry meanwhile"} {
		a, err := s.OpenAsk(ctx, Ask{Atespace: "eng-web", Actor: "alice-1", UID: "u-" + tc, OwnerID: "alice",
			Host: "pypi.example.org", TimeoutSeconds: 60})
		if err != nil {
			t.Fatal(err)
		}
		type res struct {
			a   Ask
			err error
		}
		done := make(chan res, 1)
		go func() {
			got, err := s.Resolve(ctx, ResolveRequest{ID: a.ID, Decision: "approve", Always: true, CallerID: "alice"})
			done <- res{got, err}
		}()
		<-entered
		var other error
		if tc == "deny meanwhile" {
			_, other = s.Resolve(ctx, ResolveRequest{ID: a.ID, Decision: "deny", CallerID: "root", Admin: true})
		} else {
			clock.Add(int64(2 * time.Minute))
			_, _ = s.List(ctx, ListRequest{OwnerID: "alice"})
		}
		close(release)
		r := <-done
		release = make(chan struct{})
		stored, _ := s.List(ctx, ListRequest{OwnerID: "alice"})
		var kept string
		for _, x := range stored {
			if x.ID == a.ID {
				kept = x.State
			}
		}
		if tc == "deny meanwhile" && !IsDecided(other) {
			t.Errorf("%s: the second decision succeeded too (%v)", tc, other)
		}
		if r.err != nil || r.a.State != StateApproved || kept != StateApproved {
			t.Errorf("%s: approve returned %q (%v), the store keeps %q", tc, r.a.State, r.err, kept)
		}
	}
}

// TestRV4F1ParallelBindingDecisions: many approve/deny pairs on binding asks
// at once; exactly one of each pair succeeds and the store keeps its answer.
func TestRV4F1ParallelBindingDecisions(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	for i := range 200 {
		a, err := s.OpenAsk(ctx, Ask{Kind: KindSecretBinding, OwnerID: "alice", Host: "git.lab.example", Tool: "gl",
			Rule: BindingRule(fmt.Sprintf("b-%d", i))})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		got := make([]Ask, 2)
		errs := make([]error, 2)
		for j, d := range []string{"approve", "deny"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got[j], errs[j] = s.Resolve(ctx, ResolveRequest{ID: a.ID, Decision: d, CallerID: "root", Admin: true})
			}()
		}
		wg.Wait()
		if (errs[0] == nil) == (errs[1] == nil) {
			t.Fatalf("ask %d: approve %v, deny %v: want exactly one success", i, errs[0], errs[1])
		}
		win := got[0]
		if errs[0] != nil {
			win = got[1]
		}
		list, _ := s.List(ctx, ListRequest{OwnerID: "alice"})
		for _, x := range list {
			if x.ID == a.ID && x.State != win.State {
				t.Fatalf("ask %d: the winner said %s, the store keeps %s", i, win.State, x.State)
			}
		}
	}
}
