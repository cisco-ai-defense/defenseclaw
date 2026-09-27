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

package triage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

type fakeApplier struct {
	mu      sync.Mutex
	bulk    [][]string
	single  []string
	err     error
	skipped uint32
	version uint32
}

func (f *fakeApplier) ApproveDraftChunks(_ context.Context, sandbox string, approvals []openshell.DraftChunkApproval) (*openshell.ApproveAllResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	ids := make([]string, len(approvals))
	for i, a := range approvals {
		ids[i] = sandbox + "/" + a.ChunkID
	}
	f.bulk = append(f.bulk, ids)
	f.version++
	return &openshell.ApproveAllResult{PolicyVersion: f.version, ChunksApproved: uint32(len(approvals)) - f.skipped, ChunksSkipped: f.skipped}, nil
}

func (f *fakeApplier) ApproveDraftChunk(_ context.Context, sandbox, chunkID, _ string) (*openshell.ApproveResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.single = append(f.single, sandbox+"/"+chunkID)
	f.version++
	return &openshell.ApproveResult{PolicyVersion: f.version}, nil
}

func (f *fakeApplier) calls() ([][]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.bulk...), append([]string(nil), f.single...)
}

type collector struct {
	mu      sync.Mutex
	results []Result
	ch      chan struct{}
}

func newCollector() *collector { return &collector{ch: make(chan struct{}, 64)} }

func (c *collector) add(rs []Result) {
	c.mu.Lock()
	c.results = append(c.results, rs...)
	c.mu.Unlock()
	c.ch <- struct{}{}
}

func (c *collector) wait(t *testing.T, n int) []Result {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		c.mu.Lock()
		if len(c.results) >= n {
			out := append([]Result(nil), c.results...)
			c.mu.Unlock()
			return out
		}
		c.mu.Unlock()
		select {
		case <-c.ch:
		case <-deadline:
			t.Fatalf("timed out waiting for %d results", n)
		}
	}
}

func runBatcher(t *testing.T, opts BatcherOptions) *Batcher {
	t.Helper()
	b := NewBatcher(opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = b.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return b
}

func TestBatcherDebouncesIntoOneRevision(t *testing.T) {
	apply := &fakeApplier{}
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 40 * time.Millisecond, OnResult: col.add})
	for _, id := range []string{"a", "b", "c"} {
		b.Enqueue(Item{Sandbox: "box", ChunkID: id, ReviewToken: "rt-" + id})
		time.Sleep(5 * time.Millisecond)
	}
	b.Enqueue(Item{Sandbox: "box", ChunkID: "a"}) // duplicate
	b.Enqueue(Item{Sandbox: "other", ChunkID: "z"})
	results := col.wait(t, 4)
	bulk, single := apply.calls()
	if len(single) != 0 {
		t.Fatalf("single approvals = %v", single)
	}
	byBox := map[string]int{}
	for _, call := range bulk {
		byBox[call[0][:3]] += 1
		if call[0][:3] == "box" && len(call) != 3 {
			t.Fatalf("box batch = %v, want the three chunks in one revision", call)
		}
	}
	if byBox["box"] != 1 || byBox["oth"] != 1 {
		t.Fatalf("bulk calls = %v", bulk)
	}
	for _, r := range results {
		if r.Err != nil || r.PolicyVersion == 0 {
			t.Fatalf("result = %+v", r)
		}
	}
	if b.Pending("box") != 0 {
		t.Fatal("queue not drained")
	}
}

func TestBatcherWaitsForQuiescence(t *testing.T) {
	apply := &fakeApplier{}
	col := newCollector()
	inflight := sandboxauth.NewInFlight(nil)
	end := inflight.Begin("sb_1")
	b := runBatcher(t, BatcherOptions{Apply: apply, Quiesce: inflight, Debounce: 10 * time.Millisecond, Idle: 20 * time.Millisecond, OnResult: col.add})
	b.Enqueue(Item{Sandbox: "box", BindingID: "sb_1", ChunkID: "a"})
	time.Sleep(100 * time.Millisecond)
	if bulk, _ := apply.calls(); len(bulk) != 0 {
		t.Fatalf("applied while a hook request was open: %v", bulk)
	}
	ended := time.Now()
	end()
	results := col.wait(t, 1)
	if results[0].Forced || results[0].Err != nil {
		t.Fatalf("result = %+v", results[0])
	}
	if waited := time.Since(ended); waited < 20*time.Millisecond {
		t.Fatalf("applied %v after the last request, before the idle interval", waited)
	}
}

func TestBatcherForcesAfterMaxWait(t *testing.T) {
	apply := &fakeApplier{}
	col := newCollector()
	inflight := sandboxauth.NewInFlight(nil)
	_ = inflight.Begin("sb_1") // never ends
	b := runBatcher(t, BatcherOptions{Apply: apply, Quiesce: inflight, Debounce: 5 * time.Millisecond,
		MaxWait: 30 * time.Millisecond, OnResult: col.add})
	b.Enqueue(Item{Sandbox: "box", BindingID: "sb_1", ChunkID: "a"})
	results := col.wait(t, 1)
	if !results[0].Forced {
		t.Fatalf("result = %+v, want forced", results[0])
	}
}

func TestBatcherSingleAndFailures(t *testing.T) {
	apply := &fakeApplier{}
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 5 * time.Millisecond, OnResult: col.add})
	b.Enqueue(Item{Sandbox: "box", ChunkID: "flagged", Single: true})
	b.Enqueue(Item{Sandbox: "box", ChunkID: "plain"})
	col.wait(t, 2)
	bulk, single := apply.calls()
	if len(single) != 1 || single[0] != "box/flagged" || len(bulk) != 1 || bulk[0][0] != "box/plain" {
		t.Fatalf("bulk %v single %v", bulk, single)
	}

	apply.mu.Lock()
	apply.err = errors.New("gateway down")
	apply.mu.Unlock()
	b.Enqueue(Item{Sandbox: "box", ChunkID: "later"})
	results := col.wait(t, 3)
	if results[2].Err == nil {
		t.Fatalf("failed batch reported %+v", results[2])
	}
}

func TestBatcherSkippedChunks(t *testing.T) {
	apply := &fakeApplier{skipped: 1}
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 5 * time.Millisecond, OnResult: col.add})
	b.Enqueue(Item{Sandbox: "box", ChunkID: "a"})
	b.Enqueue(Item{Sandbox: "box", ChunkID: "b"})
	results := col.wait(t, 2)
	if results[0].Skipped || !results[1].Skipped {
		t.Fatalf("results = %+v", results)
	}
}

func TestBatcherForget(t *testing.T) {
	apply := &fakeApplier{}
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: time.Hour})
	b.Enqueue(Item{Sandbox: "box", ChunkID: "a"})
	if b.Pending("box") != 1 {
		t.Fatal("not queued")
	}
	if dropped := b.Forget("box"); len(dropped) != 1 {
		t.Fatalf("forget = %v", dropped)
	}
	if b.Pending("box") != 0 {
		t.Fatal("still queued")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

func TestBatcherRunTwice(t *testing.T) {
	b := runBatcher(t, BatcherOptions{Apply: &fakeApplier{}})
	time.Sleep(10 * time.Millisecond)
	if err := b.Run(context.Background()); err == nil {
		t.Fatal("second Run accepted")
	}
}
