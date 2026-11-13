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
// memo, or a memo of the older step1/hit format (ed4fc62536), is cold: the
// new leader answers errWarming, so the callout's chain failure mode
// decides, until its worker has read the store back (it starts doing so
// at start, before any egress); then the store's own detection. It never
// allows meanwhile.
func TestEgressMemoWarmsAStoreFromAnOlderLeader(t *testing.T) {
	for _, older := range []any{nil, map[string]any{"step1": map[string]any{}}} {
		t.Run(fmt.Sprint(older), func(t *testing.T) { testEgressMemoWarms(t, older) })
	}
}

func testEgressMemoWarms(t *testing.T, older any) {
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
	if older == nil {
		delete(st, "egress")
	} else {
		st["egress"] = older
	}
	if raw, err = json.Marshal(st); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	h2 := newHarness(t, dir, Options{})
	v, err := h2.svc.Egress(context.Background(), req)
	var we *leader.WireError
	if err == nil && !v.Deny || err != nil && (!errors.As(err, &we) || we.Code != leader.CodeUnavailable) {
		t.Fatalf("cold memo: %+v %v", v, err)
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

// GAP-0179: the egress check never waits on the disk. The worker's store
// write blocks (a disk that does not answer) until the test lets it go.
// With the worker stuck in it, checks over the transport and more checks
// than the worker queue holds all return, answered from the memo: a secret
// read still refuses, other actors are allowed. The signal is the blocked
// write itself (entered, release), not a latency percentile on a shared
// host; the 10 s guard only stops a hang.
func TestEgressCheckNeverWaitsOnABlockedDiskGAP0179(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	secret, other := actorA, actorB
	h.hook(secret, "s1", secretRead(t))
	h.hook(other, "s1", projection(t, reverseShell, 1))
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock) // before the harness closes the service, which drains the worker
	h.svc.egress.stop()
	h.svc.startEgressWorkerWith(func(ctx context.Context, in EgressRequest) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return h.svc.recordEgress(ctx, in)
	})
	const guard = 10 * time.Second
	check := func(a Actor, transport bool) EgressVerdict {
		t.Helper()
		type res struct {
			v   EgressVerdict
			err error
		}
		ch := make(chan res, 1)
		go func() {
			in := EgressRequest{Actor: a, Host: "registry.npmjs.org", Method: "GET"}
			if transport {
				v, err := h.client.CheckEgress(context.Background(), in)
				ch <- res{v, err}
				return
			}
			v, err := h.svc.Egress(context.Background(), in)
			ch <- res{v, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("check of %s: %v", a.UID, r.err)
			}
			return r.v
		case <-time.After(guard):
			t.Fatal("an egress check waited on the blocked disk")
		}
		return EgressVerdict{}
	}
	// An allowed check hands its step to the worker, which blocks in the write.
	if v := check(other, true); v.Deny {
		t.Fatalf("other actor: %+v", v)
	}
	select {
	case <-entered:
	case <-time.After(guard):
		t.Fatal("the worker never reached the store write")
	}
	// The disk is blocked now. Checks still answer, from the memo.
	for range 20 {
		if v := check(secret, true); !v.Deny {
			t.Fatalf("secret read, disk blocked: %+v, want deny", v)
		}
		if v := check(other, true); v.Deny {
			t.Fatalf("other actor, disk blocked: %+v", v)
		}
	}
	// More checks than the worker queue holds: the full queue drops the
	// step (counted) and the check still answers.
	for range egressQueueSize + 16 {
		check(other, false)
	}
	if h.svc.EgressDropped() == 0 {
		t.Fatal("the full queue dropped nothing: a check would have waited for room")
	}
	unblock()
}
