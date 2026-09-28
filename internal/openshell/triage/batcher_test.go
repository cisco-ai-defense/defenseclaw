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

// change runs fn on the inbox under its lock.
func (f *fakeApplier) change(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
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

// byID indexes results by chunk id.
func byID(results []Result) map[string]Result {
	out := map[string]Result{}
	for _, r := range results {
		out[r.Item.ChunkID] = r
	}
	return out
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

// startBatcher runs a batcher over a new fake inbox that reports to a new
// collector, with a 5ms debounce unless edit changes the options.
func startBatcher(t *testing.T, edit func(*BatcherOptions)) (*fakeApplier, *collector, *Batcher) {
	t.Helper()
	apply, col := newFakeApplier(), newCollector()
	opts := BatcherOptions{Apply: apply, Debounce: 5 * time.Millisecond, OnResult: col.add}
	if edit != nil {
		edit(&opts)
	}
	return apply, col, runBatcher(t, opts)
}

// item queues chunk id of sandbox in the applier and returns its Item,
// attributed to binding when one is given.
func item(f *fakeApplier, sandbox, id string, binding ...string) Item {
	it := Item{Sandbox: sandbox, ChunkID: id, Digest: f.add(sandbox, id, "")}
	if len(binding) > 0 {
		it.BindingID = binding[0]
	}
	return it
}

// applied fails unless r is a clean approval that produced a policy
// revision.
func applied(t *testing.T, r Result) {
	t.Helper()
	if r.Err != nil || r.PolicyVersion == 0 || r.Skipped || r.Stale || r.Changed || r.Gone || r.Refused != nil {
		t.Fatalf("result = %+v, want an applied approval", r)
	}
}

func TestBatcherDebouncesIntoOneRevision(t *testing.T) {
	apply, col, b := startBatcher(t, func(o *BatcherOptions) { o.Debounce = 40 * time.Millisecond })
	for _, id := range []string{"a", "b", "c"} {
		b.Enqueue(item(apply, "box", id))
		time.Sleep(5 * time.Millisecond)
	}
	b.Enqueue(Item{Sandbox: "box", ChunkID: "a"}) // duplicate
	b.Enqueue(item(apply, "other", "z"))
	for _, r := range col.wait(t, 4) {
		applied(t, r)
	}
	bulk, single := apply.calls()
	byBox := map[string]int{}
	for _, call := range bulk {
		byBox[call[0][:3]]++
		if call[0][:3] == "box" && len(call) != 3 {
			t.Fatalf("box batch = %v, want the three chunks in one revision", call)
		}
	}
	if len(single) != 0 || byBox["box"] != 1 || byBox["oth"] != 1 || b.Pending("box") != 0 {
		t.Fatalf("bulk calls = %v, single %v, %d still queued", bulk, single, b.Pending("box"))
	}
}

// Approvals apply with the review tokens read right before the batch
// approves, not the ones read at triage time: other approvals may have
// landed in between. A bulk approval whose tokens went stale under a
// concurrent policy change is retried with fresh tokens, its results read
// from the inbox rather than guessed from the skip count, and given up as
// stale after maxApplyAttempts.
func TestBatcherReviewTokens(t *testing.T) {
	for _, tc := range []struct {
		name          string
		bump, race    int
		ids           []string
		stale         bool
		bulkAttempts  int
		approvedAfter string
	}{
		{"tokens changed since triage", 5, 0, []string{"a"}, false, 1, "approved"},
		{"stale once", 0, 1, []string{"a", "b"}, false, 2, "approved"},
		{"always stale", 0, 100, []string{"a"}, true, maxApplyAttempts, "pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apply, col, b := startBatcher(t, nil)
			var items []Item
			for _, id := range tc.ids {
				items = append(items, item(apply, "box", id))
			}
			apply.change(func() { apply.version += uint32(tc.bump); apply.race = tc.race })
			for _, it := range items {
				b.Enqueue(it)
			}
			for _, r := range col.wait(t, len(tc.ids)) {
				if tc.stale {
					if !r.Stale || r.Err != nil {
						t.Fatalf("result = %+v, want stale", r)
					}
				} else {
					applied(t, r)
				}
			}
			for _, id := range tc.ids {
				if got := apply.status("box", id); got != tc.approvedAfter {
					t.Fatalf("chunk %s is %s, want %s", id, got, tc.approvedAfter)
				}
			}
			if bulk, _ := apply.calls(); len(bulk) != tc.bulkAttempts {
				t.Fatalf("bulk calls = %v, want %d attempts", bulk, tc.bulkAttempts)
			}
		})
	}
}

func TestBatcherSkipsChangedAndGoneChunks(t *testing.T) {
	apply, col, b := startBatcher(t, nil)
	changed, gone := item(apply, "box", "a"), item(apply, "box", "b")
	apply.change(func() {
		apply.chunks["box/a"].ProposedRule.Endpoints[0].Ports = []uint32{443, 22}
		apply.chunks["box/b"].Status = "rejected"
	})
	b.Enqueue(changed)
	b.Enqueue(gone)
	b.Enqueue(Item{Sandbox: "box", ChunkID: "missing"})
	if r := byID(col.wait(t, 3)); !r["a"].Changed || !r["b"].Gone || !r["missing"].Gone {
		t.Fatalf("results = %+v", r)
	}
	if bulk, single := apply.calls(); len(bulk)+len(single) != 0 || apply.status("box", "a") != "pending" {
		t.Fatalf("approved anything: %v %v", bulk, single)
	}
}

// A batch waits for the binding's hook requests to end and the idle
// interval to pass, and is forced after MaxWait when they never end.
func TestBatcherWaitsForQuiescence(t *testing.T) {
	inflight := sandboxauth.NewInFlight(nil)
	end := inflight.Begin("sb_1")
	apply, col, b := startBatcher(t, func(o *BatcherOptions) {
		o.Quiesce, o.Debounce, o.Idle = inflight, 10*time.Millisecond, 20*time.Millisecond
	})
	b.Enqueue(item(apply, "box", "a", "sb_1"))
	time.Sleep(100 * time.Millisecond)
	if bulk, _ := apply.calls(); len(bulk) != 0 {
		t.Fatalf("applied while a hook request was open: %v", bulk)
	}
	ended := time.Now()
	end()
	if r := col.wait(t, 1)[0]; r.Forced || r.Err != nil {
		t.Fatalf("result = %+v", r)
	}
	if waited := time.Since(ended); waited < 20*time.Millisecond {
		t.Fatalf("applied %v after the last request, before the idle interval", waited)
	}

	_ = inflight.Begin("sb_1") // never ends
	forcedApply, forced, fb := startBatcher(t, func(o *BatcherOptions) { o.Quiesce, o.MaxWait = inflight, 30*time.Millisecond })
	fb.Enqueue(item(forcedApply, "box", "a", "sb_1"))
	if r := forced.wait(t, 1)[0]; !r.Forced {
		t.Fatalf("result = %+v, want forced", r)
	}
}

// fakeTunnels is a binding's egress proxy traffic: while busy, every read
// sees more bytes moved.
type fakeTunnels struct {
	mu    sync.Mutex
	open  int
	moved int64
	busy  bool
}

func (f *fakeTunnels) BindingActivity(bindingID string) (int, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if bindingID != "sb_1" {
		return 0, 0
	}
	if f.busy {
		f.moved += 1 << 10
	}
	return f.open, f.moved
}

func (f *fakeTunnels) set(open int, busy bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open, f.busy = open, busy
}

// TestBatcherWaitsForIdleTunnels pins that a batch also waits for the
// binding's egress tunnels to go quiet, since the policy reload closes them
// too: a transfer that keeps moving bytes holds the batch, a tunnel left
// open but idle does not, and a transfer that never ends gets the batch
// after MaxWait. The hooks must be quiet at the same time.
func TestBatcherWaitsForIdleTunnels(t *testing.T) {
	inflight := sandboxauth.NewInFlight(nil)
	tunnels := &fakeTunnels{}
	tunnels.set(1, true)
	apply, col, b := startBatcher(t, func(o *BatcherOptions) { o.Quiesce, o.Tunnels, o.Idle = inflight, tunnels, 20*time.Millisecond })
	b.Enqueue(item(apply, "box", "a", "sb_1"))
	time.Sleep(120 * time.Millisecond)
	if bulk, _ := apply.calls(); len(bulk) != 0 {
		t.Fatalf("applied while a tunnel was moving data: %v", bulk)
	}
	// The transfer ends; its tunnel stays open, idle.
	tunnels.set(1, false)
	if r := col.wait(t, 1)[0]; r.Forced || r.Err != nil || r.PolicyVersion == 0 {
		t.Fatalf("result = %+v", r)
	}

	// A transfer that never ends gets the batch after MaxWait.
	busy := &fakeTunnels{}
	busy.set(2, true)
	forcedApply, forced, fb := startBatcher(t, func(o *BatcherOptions) {
		o.Quiesce, o.Tunnels, o.Idle, o.MaxWait = inflight, busy, 10*time.Millisecond, 60*time.Millisecond
	})
	fb.Enqueue(item(forcedApply, "box", "b", "sb_1"))
	if got := forced.wait(t, 1); !got[0].Forced {
		t.Fatalf("result = %+v, want forced", got[0])
	}
	// Another binding's tunnels never hold a batch.
	fb.Enqueue(item(forcedApply, "box", "c", "sb_2"))
	if got := forced.wait(t, 2); got[1].Forced || got[1].Err != nil {
		t.Fatalf("result = %+v", got[1])
	}
}

// TestBatcherFlaggedChunksGoSingle pins that an approved security-flagged
// chunk goes through the single call with a token read after the bulk
// approval landed (which made the first read stale).
func TestBatcherFlaggedChunksGoSingle(t *testing.T) {
	apply, col, b := startBatcher(t, nil)
	b.Enqueue(Item{Sandbox: "box", ChunkID: "flagged", Digest: apply.add("box", "flagged", "downloads executables")})
	b.Enqueue(item(apply, "box", "plain"))
	for _, r := range col.wait(t, 2) {
		if r.Err != nil || r.Stale || r.Skipped {
			t.Fatalf("result = %+v", r)
		}
	}
	bulk, single := apply.calls()
	if len(single) != 1 || single[0] != "box/flagged" || len(bulk) != 1 || bulk[0][0] != "box/plain" || apply.status("box", "flagged") != "approved" {
		t.Fatalf("bulk %v single %v; the flagged chunk must be approved on its own", bulk, single)
	}
}

// A failing inbox is reported; Forget drops a sandbox's queue, Drain
// returns once nothing is queued, and a batcher runs once.
func TestBatcherLifecycle(t *testing.T) {
	apply, col, b := startBatcher(t, nil)
	it := item(apply, "box", "later")
	apply.change(func() { apply.err = errors.New("gateway down") })
	b.Enqueue(it)
	if r := col.wait(t, 1)[0]; r.Err == nil {
		t.Fatalf("failed batch reported %+v", r)
	}
	defaults := runBatcher(t, BatcherOptions{Apply: newFakeApplier()})
	time.Sleep(10 * time.Millisecond)
	if err := defaults.Run(context.Background()); err == nil {
		t.Fatal("second Run accepted")
	}

	held := newFakeApplier()
	hb := runBatcher(t, BatcherOptions{Apply: held, Debounce: time.Hour})
	hb.Enqueue(item(held, "box", "a"))
	if hb.Pending("box") != 1 {
		t.Fatal("not queued")
	}
	if dropped := hb.Forget("box"); len(dropped) != 1 || hb.Pending("box") != 0 {
		t.Fatalf("forget = %v, %d still queued", dropped, hb.Pending("box"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := hb.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

// TestBatcherRechecksBeforeApplying pins the apply-time re-check: an
// approval Recheck refuses is left unapproved and reported as Refused, the
// rest of the batch still lands, and Recheck sees the chunk as it is when
// the batch is applied.
func TestBatcherRechecksBeforeApplying(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	apply, col, b := startBatcher(t, func(o *BatcherOptions) {
		o.Recheck = func(_ context.Context, it Item, c openshell.PolicyChunk) error {
			mu.Lock()
			seen = append(seen, c.ProposedRule.Endpoints[0].Host)
			mu.Unlock()
			if it.ChunkID == "rebind" {
				return errors.New("rebind.example.org resolves to an address of this machine")
			}
			return nil
		}
	})
	b.Enqueue(item(apply, "box", "ok"))
	b.Enqueue(item(apply, "box", "rebind"))
	results := byID(col.wait(t, 2))
	applied(t, results["ok"])
	if r := results["rebind"]; r.Refused == nil || !strings.Contains(r.Refused.Error(), "this machine") || r.Err != nil || r.PolicyVersion != 0 {
		t.Fatalf("rebind result = %+v", r)
	}
	if apply.status("box", "ok") != "approved" || apply.status("box", "rebind") != "pending" {
		t.Fatalf("statuses = %s, %s", apply.status("box", "ok"), apply.status("box", "rebind"))
	}
	if bulk, _ := apply.calls(); len(bulk) != 1 || len(bulk[0]) != 1 || bulk[0][0] != "box/ok" {
		t.Fatalf("bulk calls = %v, want only the rechecked approval", bulk)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("recheck saw %v, want both chunks", seen)
	}
}

// TestBatcherOneChunkPerRule pins that chunks naming the same rule land in
// separate revisions: approving merges a chunk into the rule of its name,
// so the second is checked again (Recheck) once the first one's rule
// exists, where a merge into another destination's rule is refused.
func TestBatcherOneChunkPerRule(t *testing.T) {
	var mu sync.Mutex
	var rechecked []string
	apply, col, b := startBatcher(t, func(o *BatcherOptions) {
		o.Debounce = 20 * time.Millisecond
		o.Recheck = func(_ context.Context, it Item, _ openshell.PolicyChunk) error {
			mu.Lock()
			rechecked = append(rechecked, it.ChunkID)
			mu.Unlock()
			return nil
		}
	})
	first, second := item(apply, "box", "first"), item(apply, "box", "second")
	apply.change(func() {
		for _, id := range []string{"first", "second"} {
			c := apply.chunks["box/"+id]
			c.RuleName, c.ProposedRule.Name = "allow_shared_443", "allow_shared_443"
		}
	})
	first.Digest, second.Digest = "", ""
	b.Enqueue(first)
	b.Enqueue(second)
	b.Enqueue(item(apply, "box", "other"))
	for _, r := range col.wait(t, 3) {
		applied(t, r)
	}
	bulk, _ := apply.calls()
	if len(bulk) != 2 || len(bulk[0]) != 2 || bulk[0][0] != "box/first" || bulk[0][1] != "box/other" ||
		len(bulk[1]) != 1 || bulk[1][0] != "box/second" {
		t.Fatalf("bulk calls = %v, want the second chunk of rule allow_shared_443 in a revision of its own", bulk)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(rechecked) != 3 || rechecked[2] != "second" {
		t.Fatalf("rechecked %v, want the second chunk checked again in its own batch", rechecked)
	}
}
