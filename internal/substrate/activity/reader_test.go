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

package activity

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// fakeClock is a settable clock for the Reader.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// concurrent runs n Snapshot calls at once and returns the slowest.
func concurrent(t *testing.T, r *Reader, n int) (slowest time.Duration, errs int) {
	t.Helper()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			_, err := r.Snapshot(context.Background())
			d := time.Since(t0)
			mu.Lock()
			if d > slowest {
				slowest = d
			}
			if err != nil {
				errs++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return slowest, errs
}

// GAP-1018: with the leader refusing connections, concurrent readers do not
// queue behind one retrying call, and the failure is remembered.
func TestReaderLeaderRefusedDoesNotQueue(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close() // refused from now on
	r := &Reader{Leader: &leader.Client{BaseURL: "http://" + addr, HTTP: &http.Client{Timeout: 5 * time.Second}}}
	slowest, errs := concurrent(t, r, 6)
	if errs != 6 {
		t.Fatalf("errors = %d, want 6 (no leader, no snapshot)", errs)
	}
	if slowest > readerWait+time.Second {
		t.Fatalf("slowest Snapshot took %v with the leader down (queued or retried)", slowest)
	}
	// The failure is remembered: the next callers answer at once.
	slowest, errs = concurrent(t, r, 6)
	if errs != 6 || slowest > 50*time.Millisecond {
		t.Fatalf("after a failed read: errors %d, slowest %v (the failure is not cached)", errs, slowest)
	}
}

// GAP-1018: a leader that does not answer (a blackhole) makes callers wait
// at most readerWait each, at the same time, never one after the other.
func TestReaderHungLeaderIsBoundedAndConcurrent(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	r := &Reader{fetch: func(ctx context.Context) (Snapshot, error) {
		calls.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return Snapshot{}, ctx.Err()
	}}
	t0 := time.Now()
	_, errs := concurrent(t, r, 6)
	if all := time.Since(t0); errs != 6 || all > 3*readerWait {
		t.Fatalf("6 callers on a hung leader: errors %d, %v in all (want about %v, not 6x)", errs, all, readerWait)
	}
	// A caller that gave up marked the leader slow: the next ones do not wait.
	slowest, errs := concurrent(t, r, 6)
	if errs != 6 || slowest > 50*time.Millisecond {
		t.Fatalf("after a timed-out wait: errors %d, slowest %v", errs, slowest)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("leader reads = %d, want 1 (one read in flight, none started while it runs)", n)
	}
}

// A snapshot past its TTL is answered at once while a newer one is read;
// past two flushes more it is unknown, never an old idle.
func TestReaderStaleWhileReading(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	gate := make(chan struct{}, 1)
	var calls atomic.Int32
	r := &Reader{Now: clk.now, fetch: func(ctx context.Context) (Snapshot, error) {
		n := calls.Add(1)
		if n == 1 {
			return Snapshot{Last: map[string]time.Time{"u1": clk.now()}}, nil
		}
		select {
		case <-gate:
			return Snapshot{Last: map[string]time.Time{"u2": clk.now()}}, nil
		case <-ctx.Done():
			return Snapshot{}, ctx.Err()
		}
	}}
	snap, err := r.Snapshot(context.Background())
	if err != nil || snap.Last["u1"].IsZero() {
		t.Fatalf("first read: %v %v", snap, err)
	}
	clk.add(DefaultSnapshotTTL + time.Second) // stale, still usable
	t0 := time.Now()
	snap, err = r.Snapshot(context.Background())
	if err != nil || snap.Last["u1"].IsZero() || time.Since(t0) > 50*time.Millisecond {
		t.Fatalf("stale read: %v %v in %v (want the old snapshot at once)", snap, err, time.Since(t0))
	}
	gate <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for {
		snap, _ = r.Snapshot(context.Background())
		if !snap.Last["u2"].IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the background read never replaced the snapshot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("leader reads = %d, want 2", n)
	}
}

// After readerFailTTL the Reader tries again, and a good answer is used.
func TestReaderRecoversAfterFailTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	var up atomic.Bool
	var calls atomic.Int32
	r := &Reader{Now: clk.now, fetch: func(context.Context) (Snapshot, error) {
		calls.Add(1)
		if !up.Load() {
			return Snapshot{}, errors.New("down")
		}
		return Snapshot{Last: map[string]time.Time{"u1": clk.now()}}, nil
	}}
	if _, err := r.Snapshot(context.Background()); err == nil {
		t.Fatal("a down leader gave a snapshot")
	}
	up.Store(true)
	if _, err := r.Snapshot(context.Background()); err == nil {
		t.Fatal("a remembered failure was retried at once")
	}
	clk.add(readerFailTTL)
	_, _ = r.Snapshot(context.Background()) // starts the read; does not wait (the last one failed)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if snap, err := r.Snapshot(context.Background()); err == nil && !snap.Last["u1"].IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the Reader did not recover")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("leader reads = %d, want 2 (one per fail TTL)", n)
	}
}
