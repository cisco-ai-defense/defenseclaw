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
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// calloutBudget is the callout's default chain check budget.
const calloutBudget = 20 * time.Millisecond

// TestEgressCheckNeedsNoStoreGAP0179 is the root cause of GAP-0179: a new
// actor's first egress (a clone before any hook) opened and created its
// store inside the check, which overran the callout budget. The check now
// answers from memory under a budget-sized deadline and creates no store
// file; the worker records the step afterwards.
func TestEgressCheckNeedsNoStoreGAP0179(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	// The worker records nothing here, so the only store would be the
	// check's own.
	h.svc.egress.stop()
	h.svc.startEgressWorkerWith(func(context.Context, EgressRequest) error { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), calloutBudget)
	defer cancel()
	v, err := h.svc.Egress(ctx, EgressRequest{Actor: actorA, Host: "github.com", Method: "GET"})
	if err != nil || v.Deny {
		t.Fatalf("first egress of a new actor: %+v %v", v, err)
	}
	if _, err := os.Stat(h.svc.dbPath(actorA)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the check opened a store (%v)", err)
	}
	// After a secret read, the memo denies at once, with no store read.
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.advance(time.Second)
	v, err = h.svc.Egress(ctx, EgressRequest{Actor: actorA, Host: "example.com", Method: "POST"})
	if err != nil || !v.Deny || v.Rule != guardrail.ToolChainSecretReadThenEgress {
		t.Fatalf("after a secret read: %+v %v", v, err)
	}
	// Past the chain's time window, clear again.
	h.advance(31 * time.Minute)
	if v, _ := h.svc.Egress(ctx, EgressRequest{Actor: actorA, Host: "example.com", Method: "POST"}); v.Deny {
		t.Fatalf("past the window: %+v", v)
	}
}

// TestEgressMemoFollowsTheStore: the memo is saved with the actor's state,
// so a new leader on the same volume (a failover) answers the first check
// from it, and a revert barrier, which clears the memo, is saved too.
func TestEgressMemoFollowsTheStore(t *testing.T) {
	dir := t.TempDir()
	req := EgressRequest{Actor: actorA, Host: "example.com", Method: "POST"}
	h := newHarness(t, dir, Options{})
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.advance(time.Second)
	if v, err := h.client.CheckEgress(context.Background(), req); err != nil || !v.Deny {
		t.Fatalf("leader 1: %+v %v", v, err)
	}
	h.svc.egress.stop() // the queued step is written
	h.svc.startEgressWorker()

	h2 := newHarness(t, dir, Options{})
	if v, err := h2.svc.Egress(context.Background(), req); err != nil || !v.Deny {
		t.Fatalf("new leader, first check: %+v %v", v, err)
	}
	h2.life(LifecycleEvent{Actor: actorA, Event: LifecycleReverted})
	if v, err := h2.svc.Egress(context.Background(), req); err != nil || v.Deny {
		t.Fatalf("after a revert: %+v %v", v, err)
	}
	h3 := newHarness(t, dir, Options{})
	if v, err := h3.svc.Egress(context.Background(), req); err != nil || v.Deny {
		t.Fatalf("leader 3 after the revert: %+v %v", v, err)
	}
}

// TestEgressMemoWarmsAStoreFromAnOlderLeader: a state file with no saved
// memo (written by an older leader) answers errWarming, so the callout's
// chain failure mode decides, until the worker has read the store; then
// the store's own detection.
func TestEgressMemoWarmsAStoreFromAnOlderLeader(t *testing.T) {
	dir := t.TempDir()
	req := EgressRequest{Actor: actorA, Host: "example.com", Method: "POST"}
	h := newHarness(t, dir, Options{})
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.advance(time.Second)
	path := h.svc.statePath(actorA)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil || st["egress"] == nil {
		t.Fatalf("state file has no saved memo: %s %v", raw, err)
	}
	delete(st, "egress")
	if raw, err = json.Marshal(st); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	h2 := newHarness(t, dir, Options{})
	_, err = h2.svc.Egress(context.Background(), req)
	var we *leader.WireError
	if !errors.As(err, &we) || we.Code != leader.CodeUnavailable {
		t.Fatalf("cold memo: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		v, err := h2.svc.Egress(context.Background(), req)
		if err == nil {
			if !v.Deny {
				t.Fatalf("warmed memo lost the store's detection: %+v", v)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("memo never warmed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestEgressCheckSkipsAPurgeOnTheVolumeGAP0179: a delete's file removal
// runs outside the service mutex, so another actor's check does not wait
// for it, and the purged actor answers unavailable until its files are
// gone.
func TestEgressCheckSkipsAPurgeOnTheVolumeGAP0179(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", projection(t, reverseShell, 1))
	h.life(LifecycleEvent{Actor: actorA, Event: LifecycleDeleted})
	if _, err := os.Stat(h.svc.dbPath(actorA)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("store of a deleted actor: %v", err)
	}
	h.svc.mu.Lock()
	n := len(h.svc.purging) + len(h.svc.purges)
	h.svc.mu.Unlock()
	if n != 0 {
		t.Fatalf("purge left %d entries", n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), calloutBudget)
	defer cancel()
	if _, err := h.svc.Egress(ctx, EgressRequest{Actor: actorB, Host: "example.com", Method: "GET"}); err != nil {
		t.Fatal(err)
	}
}

// TestEgressCheckLoadSlowDiskGAP0179 is the load test: 50 checks a second
// for 4 s across five actors, through the real leader transport, with the
// worker's store writes slowed to 200 ms each. p99 of the check stays
// within the callout's 20 ms budget, and nothing blocks behind the writes.
func TestEgressCheckLoadSlowDiskGAP0179(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	h := newHarness(t, t.TempDir(), Options{})
	// A slow disk: every store write the worker makes takes 200 ms more.
	const writeDelay = 200 * time.Millisecond
	h.svc.egress.stop()
	h.svc.startEgressWorkerWith(func(ctx context.Context, in EgressRequest) error {
		time.Sleep(writeDelay)
		return h.svc.recordEgress(ctx, in)
	})
	actors := make([]Actor, 5)
	for i := range actors {
		actors[i] = Actor{Atespace: "eng-web", UID: fmt.Sprintf("2e8d6260-7d31-4e56-b416-%012d", i+1)}
		// Some actors have windows (a hook), so the worker really writes.
		if i%2 == 0 {
			h.hook(actors[i], "s1", projection(t, reverseShell, 1))
		}
	}
	const rate, seconds = 50, 4
	var mu sync.Mutex
	var lat []time.Duration
	var wg sync.WaitGroup
	tick := time.NewTicker(time.Second / rate)
	defer tick.Stop()
	for n := 0; n < rate*seconds; n++ {
		<-tick.C
		wg.Add(1)
		go func(a Actor) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			start := time.Now()
			_, err := h.client.CheckEgress(ctx, EgressRequest{Actor: a, Host: "registry.npmjs.org", Method: "GET"})
			d := time.Since(start)
			if err != nil {
				t.Errorf("check: %v", err)
			}
			mu.Lock()
			lat = append(lat, d)
			mu.Unlock()
		}(actors[n%len(actors)])
	}
	wg.Wait()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p50, p99 := lat[len(lat)/2], lat[len(lat)*99/100]
	t.Logf("%d checks at %d/s, worker writes %s each: p50 %s, p99 %s, max %s, dropped %d",
		len(lat), rate, writeDelay, p50, p99, lat[len(lat)-1], h.svc.EgressDropped())
	if p99 > calloutBudget {
		t.Fatalf("p99 %s over the callout budget %s", p99, calloutBudget)
	}
}
