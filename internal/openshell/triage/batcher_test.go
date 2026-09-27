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
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// fakeApplier is a draft inbox with OpenShell 0.1.1's review-token
// semantics (measured on the host): a token approves a chunk only while the
// sandbox policy is unchanged since the token was read; the single call
// answers Conflict for a stale token, the bulk call skips the chunk without
// an error.
type fakeApplier struct {
	mu      sync.Mutex
	version uint32
	chunks  map[string]*openshell.PolicyChunk // by sandbox/id
	order   []string
	bulk    [][]string
	single  []string
	err     error
	// race lands another policy change after each of the next race inbox
	// reads, so the tokens just read are stale.
	race int
	// edit changes a chunk's proposed content after the next inbox read.
	edit string
}

func newFakeApplier() *fakeApplier {
	return &fakeApplier{version: 1, chunks: map[string]*openshell.PolicyChunk{}}
}

// add drafts a pending chunk and returns its content digest.
func (f *fakeApplier) add(sandbox, id string, notes string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &openshell.PolicyChunk{ID: id, Status: "pending", RuleName: "allow_" + id + "_443", SecurityNotes: notes,
		ProposedRule: &openshell.NetworkPolicyRule{Name: "allow_" + id + "_443",
			Endpoints: []v1.PolicyNetworkEndpoint{{Host: id + ".example.org", Port: 443}}}}
	f.chunks[sandbox+"/"+id] = c
	f.order = append(f.order, sandbox+"/"+id)
	return ContentDigest(*c)
}

func (f *fakeApplier) token(c *openshell.PolicyChunk) string {
	return fmt.Sprintf("%s@v%d", c.ID, f.version)
}

func (f *fakeApplier) status(sandbox, id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.chunks[sandbox+"/"+id]; c != nil {
		return c.Status
	}
	return ""
}

func (f *fakeApplier) GetDraft(_ context.Context, sandbox, status string) (*openshell.DraftPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := &openshell.DraftPolicy{}
	for _, k := range f.order {
		c := f.chunks[k]
		if !strings.HasPrefix(k, sandbox+"/") || (status != "" && c.Status != status) {
			continue
		}
		cp := *c
		cp.ReviewToken = f.token(c)
		out.Chunks = append(out.Chunks, cp)
	}
	if f.race > 0 {
		f.race--
		f.version++
	}
	if f.edit != "" {
		if c := f.chunks[sandbox+"/"+f.edit]; c != nil {
			c.ProposedRule.Endpoints[0].Ports = []uint32{443, 22}
		}
		f.edit = ""
	}
	return out, nil
}

func (f *fakeApplier) ApproveDraftChunks(_ context.Context, sandbox string, approvals []openshell.DraftChunkApproval) (*openshell.ApproveAllResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	ids := make([]string, len(approvals))
	res := &openshell.ApproveAllResult{}
	var picked []*openshell.PolicyChunk
	for i, a := range approvals {
		ids[i] = sandbox + "/" + a.ChunkID
		c := f.chunks[sandbox+"/"+a.ChunkID]
		if c == nil || c.Status != "pending" {
			return nil, &types.StatusError{Code: types.ErrorConflict, Message: "chunk is not pending"}
		}
		if a.ReviewToken != f.token(c) || c.SecurityNotes != "" {
			res.ChunksSkipped++
			continue
		}
		picked = append(picked, c)
	}
	f.bulk = append(f.bulk, ids)
	if len(picked) == 0 {
		return res, nil
	}
	for _, c := range picked {
		c.Status = "approved"
	}
	f.version++
	res.PolicyVersion, res.ChunksApproved = f.version, uint32(len(picked))
	return res, nil
}

func (f *fakeApplier) ApproveDraftChunk(_ context.Context, sandbox, chunkID, token string) (*openshell.ApproveResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.single = append(f.single, sandbox+"/"+chunkID)
	c := f.chunks[sandbox+"/"+chunkID]
	if c == nil {
		return nil, &types.StatusError{Code: types.ErrorNotFound, Message: "no chunk"}
	}
	if c.Status != "pending" || token != f.token(c) {
		return nil, &types.StatusError{Code: types.ErrorConflict, Message: "review token does not match the fetched proposal"}
	}
	c.Status = "approved"
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

// item queues chunk id of sandbox in the applier and returns its Item.
func item(f *fakeApplier, sandbox, id string) Item {
	return Item{Sandbox: sandbox, ChunkID: id, Digest: f.add(sandbox, id, "")}
}

func TestBatcherDebouncesIntoOneRevision(t *testing.T) {
	apply := newFakeApplier()
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 40 * time.Millisecond, OnResult: col.add})
	for _, id := range []string{"a", "b", "c"} {
		b.Enqueue(item(apply, "box", id))
		time.Sleep(5 * time.Millisecond)
	}
	b.Enqueue(Item{Sandbox: "box", ChunkID: "a"}) // duplicate
	b.Enqueue(item(apply, "other", "z"))
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
		if r.Err != nil || r.PolicyVersion == 0 || r.Skipped || r.Stale || r.Changed || r.Gone {
			t.Fatalf("result = %+v", r)
		}
	}
	if b.Pending("box") != 0 {
		t.Fatal("queue not drained")
	}
}

// TestBatcherUsesLiveReviewTokens pins that an approval decided while other
// approvals landed still applies: the batch reads the tokens again right
// before it approves instead of using the ones read at triage time.
func TestBatcherUsesLiveReviewTokens(t *testing.T) {
	apply := newFakeApplier()
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 5 * time.Millisecond, OnResult: col.add})
	it := item(apply, "box", "a")
	apply.mu.Lock()
	apply.version += 5 // other approvals landed since the chunk was triaged
	apply.mu.Unlock()
	b.Enqueue(it)
	results := col.wait(t, 1)
	if r := results[0]; r.Err != nil || r.Skipped || r.Stale || r.PolicyVersion == 0 {
		t.Fatalf("result = %+v", r)
	}
	if apply.status("box", "a") != "approved" {
		t.Fatal("chunk not approved")
	}
}

// TestBatcherAttributesBulkResultsByStatus pins that a bulk approval whose
// tokens went stale under a concurrent policy change is retried with fresh
// tokens, and that results are read from the inbox, not guessed from the
// skip count.
func TestBatcherAttributesBulkResultsByStatus(t *testing.T) {
	apply := newFakeApplier()
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 5 * time.Millisecond, OnResult: col.add})
	apply.mu.Lock()
	apply.race = 1 // the first read's tokens are stale by the time they are used
	apply.mu.Unlock()
	b.Enqueue(item(apply, "box", "a"))
	b.Enqueue(item(apply, "box", "b"))
	results := col.wait(t, 2)
	for _, r := range results {
		if r.Err != nil || r.Skipped || r.Stale || r.Gone || r.Changed {
			t.Fatalf("result = %+v", r)
		}
	}
	if apply.status("box", "a") != "approved" || apply.status("box", "b") != "approved" {
		t.Fatal("chunks not approved after the retry")
	}
	if bulk, _ := apply.calls(); len(bulk) != 2 {
		t.Fatalf("bulk calls = %v, want the stale attempt and the retry", bulk)
	}
}

func TestBatcherGivesUpOnStaleTokens(t *testing.T) {
	apply := newFakeApplier()
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 5 * time.Millisecond, OnResult: col.add})
	apply.mu.Lock()
	apply.race = 100
	apply.mu.Unlock()
	b.Enqueue(item(apply, "box", "a"))
	results := col.wait(t, 1)
	if !results[0].Stale || results[0].Err != nil {
		t.Fatalf("result = %+v, want stale", results[0])
	}
	if bulk, _ := apply.calls(); len(bulk) != maxApplyAttempts {
		t.Fatalf("attempts = %d", len(bulk))
	}
	if apply.status("box", "a") != "pending" {
		t.Fatal("stale chunk approved")
	}
}

func TestBatcherSkipsChangedAndGoneChunks(t *testing.T) {
	apply := newFakeApplier()
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 5 * time.Millisecond, OnResult: col.add})
	changed := item(apply, "box", "a")
	gone := item(apply, "box", "b")
	apply.mu.Lock()
	apply.chunks["box/a"].ProposedRule.Endpoints[0].Ports = []uint32{443, 22}
	apply.chunks["box/b"].Status = "rejected"
	apply.mu.Unlock()
	b.Enqueue(changed)
	b.Enqueue(gone)
	b.Enqueue(Item{Sandbox: "box", ChunkID: "missing"})
	results := col.wait(t, 3)
	byID := map[string]Result{}
	for _, r := range results {
		byID[r.Item.ChunkID] = r
	}
	if !byID["a"].Changed || !byID["b"].Gone || !byID["missing"].Gone {
		t.Fatalf("results = %+v", results)
	}
	if apply.status("box", "a") != "pending" {
		t.Fatal("changed chunk approved")
	}
	if bulk, single := apply.calls(); len(bulk)+len(single) != 0 {
		t.Fatalf("approved anything: %v %v", bulk, single)
	}
}

func TestBatcherWaitsForQuiescence(t *testing.T) {
	apply := newFakeApplier()
	col := newCollector()
	inflight := sandboxauth.NewInFlight(nil)
	end := inflight.Begin("sb_1")
	b := runBatcher(t, BatcherOptions{Apply: apply, Quiesce: inflight, Debounce: 10 * time.Millisecond, Idle: 20 * time.Millisecond, OnResult: col.add})
	it := item(apply, "box", "a")
	it.BindingID = "sb_1"
	b.Enqueue(it)
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
	apply := newFakeApplier()
	col := newCollector()
	inflight := sandboxauth.NewInFlight(nil)
	_ = inflight.Begin("sb_1") // never ends
	b := runBatcher(t, BatcherOptions{Apply: apply, Quiesce: inflight, Debounce: 5 * time.Millisecond,
		MaxWait: 30 * time.Millisecond, OnResult: col.add})
	it := item(apply, "box", "a")
	it.BindingID = "sb_1"
	b.Enqueue(it)
	results := col.wait(t, 1)
	if !results[0].Forced {
		t.Fatalf("result = %+v, want forced", results[0])
	}
}

// TestBatcherFlaggedChunksGoSingle pins that an approved security-flagged
// chunk goes through the single call with a token read after the bulk
// approval landed (which made the first read stale).
func TestBatcherFlaggedChunksGoSingle(t *testing.T) {
	apply := newFakeApplier()
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 5 * time.Millisecond, OnResult: col.add})
	b.Enqueue(Item{Sandbox: "box", ChunkID: "flagged", Digest: apply.add("box", "flagged", "downloads executables")})
	b.Enqueue(item(apply, "box", "plain"))
	results := col.wait(t, 2)
	for _, r := range results {
		if r.Err != nil || r.Stale || r.Skipped {
			t.Fatalf("result = %+v", r)
		}
	}
	bulk, single := apply.calls()
	if len(single) != 1 || single[0] != "box/flagged" || len(bulk) != 1 || bulk[0][0] != "box/plain" {
		t.Fatalf("bulk %v single %v", bulk, single)
	}
	if apply.status("box", "flagged") != "approved" {
		t.Fatal("flagged chunk not approved")
	}
}

func TestBatcherFailures(t *testing.T) {
	apply := newFakeApplier()
	col := newCollector()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: 5 * time.Millisecond, OnResult: col.add})
	it := item(apply, "box", "later")
	apply.mu.Lock()
	apply.err = errors.New("gateway down")
	apply.mu.Unlock()
	b.Enqueue(it)
	results := col.wait(t, 1)
	if results[0].Err == nil {
		t.Fatalf("failed batch reported %+v", results[0])
	}
}

func TestBatcherForget(t *testing.T) {
	apply := newFakeApplier()
	b := runBatcher(t, BatcherOptions{Apply: apply, Debounce: time.Hour})
	b.Enqueue(item(apply, "box", "a"))
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
	b := runBatcher(t, BatcherOptions{Apply: newFakeApplier()})
	time.Sleep(10 * time.Millisecond)
	if err := b.Run(context.Background()); err == nil {
		t.Fatal("second Run accepted")
	}
}
