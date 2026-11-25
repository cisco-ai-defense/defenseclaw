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

//go:build !windows

package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/activity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// concurrentLists runs n lists at once and returns the slowest.
func concurrentLists(t *testing.T, f *substrateFixture, n int, path string) time.Duration {
	t.Helper()
	var mu sync.Mutex
	var slowest time.Duration
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			rec := f.do(t, f.admin, http.MethodGet, path, "p-alice", "")
			d := time.Since(t0)
			if rec.Code != http.StatusOK {
				t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
			}
			mu.Lock()
			if d > slowest {
				slowest = d
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return slowest
}

// GAP-1018: with the leader unreachable (refused), concurrent lists and a
// status answer at once, as before the activity feed, with the activity
// unknown. serve wires the feed and the asks to the same leader client.
func TestListAndStatusLeaderDownDoNotWait(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close() // refused from now on
	toLeader := &leader.Client{BaseURL: "http://" + addr, HTTP: &http.Client{Timeout: 5 * time.Second}}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.ActivityFeed = &activity.Reader{Leader: toLeader}
		c.Asks = &asks.Client{Leader: toLeader}
	})
	const bound = 500 * time.Millisecond // readerWait (250 ms) and room for a slow box
	for round := 0; round < 2; round++ {
		if d := concurrentLists(t, f, 6, "/api/v1/substrate/actors"); d > bound {
			t.Fatalf("round %d: the slowest of 6 concurrent lists took %v with the leader down (want under %v)", round, d, bound)
		}
	}
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
	if a := activityOf(t, rec.Body.Bytes(), "alice-1"); a != nil {
		t.Fatalf("activity = %v with the leader down, want none (unknown)", a)
	}
	t0 := time.Now()
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/alice-1", "p-alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	if d := time.Since(t0); d > bound {
		t.Fatalf("status took %v with the leader down", d)
	}
}

// hungAsks is an ask store whose List does not answer (a leader that takes
// connections and never replies); it gives up after 3 s so that an old
// build fails instead of hanging.
type hungAsks struct {
	asksDirect
	lists atomic.Int32
}

func (h *hungAsks) List(ctx context.Context, _ asks.ListRequest) ([]asks.Ask, error) {
	h.lists.Add(1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(3 * time.Second):
		return nil, context.DeadlineExceeded
	}
}

// GAP-1018: the pending-asks read of list is bounded too, and a failure is
// remembered, so the next lists do not call the leader again.
func TestListAsksReadIsBoundedAndRemembered(t *testing.T) {
	now := time.Now()
	h := &hungAsks{asksDirect: asksDirect{asks.NewMemory()}}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.ActivityFeed = &fakeActivityFeed{snap: activity.Snapshot{Last: map[string]time.Time{subUID1: now}}}
		c.Asks = h
	})
	t0 := time.Now()
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
	if d := time.Since(t0); d > substrateActivityAsksWait+500*time.Millisecond {
		t.Fatalf("list took %v on a hung asks read (want about %v)", d, substrateActivityAsksWait)
	}
	if a := activityOf(t, rec.Body.Bytes(), "alice-1"); a != nil {
		t.Fatalf("activity = %v without the pending asks, want none (unknown, never idle)", a)
	}
	if d := concurrentLists(t, f, 6, "/api/v1/substrate/actors"); d > 100*time.Millisecond {
		t.Fatalf("lists after a failed asks read took up to %v (the failure is not remembered)", d)
	}
	if n := h.lists.Load(); n != 1 {
		t.Fatalf("asks reads = %d, want 1 within the backoff", n)
	}
}

// cancelAsks is an ask store whose first List blocks until ctx ends or
// release closes (a slow leader read); later lists answer at once.
type cancelAsks struct {
	asksDirect
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (c *cancelAsks) List(ctx context.Context, in asks.ListRequest) ([]asks.Ask, error) {
	if c.calls.Add(1) == 1 {
		close(c.entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.release:
			return nil, nil
		}
	}
	return c.asksDirect.List(ctx, in)
}

// GAP-1043: the pending-asks failure memory is gateway-wide, so one
// caller's cancellation (a Ctrl-C of its list) must not set it; the next
// person's list still shows activity.
func TestListCallerCancelDoesNotBlankOthers(t *testing.T) {
	now := time.Now()
	c := &cancelAsks{asksDirect: asksDirect{asks.NewMemory()}, entered: make(chan struct{}), release: make(chan struct{})}
	f := newSubstrateFixture(t, func(cfg *SubstrateConfig) {
		cfg.ActivityFeed = &fakeActivityFeed{snap: activity.Snapshot{Last: map[string]time.Time{subUID1: now}}}
		cfg.Asks = c
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/substrate/actors", nil).WithContext(ctx)
	req.RemoteAddr = "10.0.0.7:43210"
	req.Header.Set("X-DefenseClaw-Client", "actor-hook/1.0")
	req.Header.Set("Authorization", "Bearer p-alice")
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.admin.ServeHTTP(httptest.NewRecorder(), req)
	}()
	select {
	case <-c.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the asks read did not start")
	}
	cancel() // caller A gives up mid-read
	close(c.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("caller A's list did not end")
	}
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if a := activityOf(t, rec.Body.Bytes(), "alice-1"); a == nil {
		t.Fatal("caller B's list shows no activity after caller A cancelled: A's cancel marked the asks read down for everyone")
	}
}
