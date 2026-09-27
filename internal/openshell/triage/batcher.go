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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Applier applies approved draft chunks to a sandbox policy.
// openshell.Client satisfies it.
type Applier interface {
	// ApproveDraftChunks approves several reviewed chunks in one policy
	// revision; security-flagged chunks are skipped.
	ApproveDraftChunks(ctx context.Context, sandbox string, approvals []openshell.DraftChunkApproval) (*openshell.ApproveAllResult, error)
	// ApproveDraftChunk approves one chunk, security-flagged ones included.
	ApproveDraftChunk(ctx context.Context, sandbox, chunkID, reviewToken string) (*openshell.ApproveResult, error)
}

// Quiescer waits until a sandbox binding has no ingress request open and
// none for idle. *sandboxauth.InFlight satisfies it.
type Quiescer interface {
	WaitQuiescent(ctx context.Context, bindingID string, idle time.Duration) error
}

// Item is one approval waiting to be applied.
type Item struct {
	Sandbox     string
	BindingID   string
	ChunkID     string
	ReviewToken string
	// Single applies the chunk on its own (ApproveDraftChunk): the bulk
	// call skips security-flagged chunks, so an operator approval of a
	// flagged chunk must go through the single call.
	Single bool
	// Tag is carried through to the Result.
	Tag any
}

// Result is the outcome of one applied Item.
type Result struct {
	Item Item
	// Err is set when the approval failed; Skipped when OpenShell left the
	// chunk out of a bulk approval.
	Err     error
	Skipped bool
	// PolicyVersion is the sandbox policy revision the approval landed in.
	PolicyVersion uint32
	PolicyHash    string
	// Forced reports a batch applied after MaxWait without quiescence.
	Forced bool
}

// BatcherOptions configure a Batcher.
type BatcherOptions struct {
	Apply Applier
	// Quiesce is consulted before each batch; nil applies at once.
	Quiesce Quiescer
	// Debounce collects approvals until none arrived for this long
	// (openshell.approvals.debounce_ms; default 3s).
	Debounce time.Duration
	// MaxDelay caps how long debouncing may postpone a batch (default 30s).
	MaxDelay time.Duration
	// Idle is the hook-quiet interval required before applying (default
	// 2s).
	Idle time.Duration
	// MaxWait bounds the wait for quiescence; a sandbox busy that long gets
	// its batch anyway (default 2m).
	MaxWait time.Duration
	// OnResult receives every batch's results. It runs on the batcher
	// goroutine and must not block for long.
	OnResult func([]Result)
}

// Batcher debounces approvals per sandbox and applies each sandbox's batch
// in one policy revision at a hook-quiescent moment.
type Batcher struct {
	opts BatcherOptions

	mu      sync.Mutex
	queues  map[string]*queue
	ready   chan string
	running bool
	// idle is broadcast whenever a flush completes, so Drain can wait for
	// the batcher to go idle; busy counts running flushes.
	idle *sync.Cond
	busy int
}

type queue struct {
	items    []Item
	first    time.Time
	timer    *time.Timer
	flushing bool
}

// NewBatcher returns a Batcher. Run must be running for batches to apply.
func NewBatcher(opts BatcherOptions) *Batcher {
	if opts.Debounce <= 0 {
		opts.Debounce = 3 * time.Second
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = 30 * time.Second
	}
	if opts.MaxDelay < opts.Debounce {
		opts.MaxDelay = opts.Debounce
	}
	if opts.Idle <= 0 {
		opts.Idle = 2 * time.Second
	}
	if opts.MaxWait <= 0 {
		opts.MaxWait = 2 * time.Minute
	}
	b := &Batcher{opts: opts, queues: map[string]*queue{}, ready: make(chan string, 256)}
	b.idle = sync.NewCond(&b.mu)
	return b
}

// Enqueue adds an approval. A chunk already queued is not added twice.
func (b *Batcher) Enqueue(item Item) {
	b.mu.Lock()
	defer b.mu.Unlock()
	q := b.queues[item.Sandbox]
	if q == nil {
		q = &queue{first: time.Now()}
		b.queues[item.Sandbox] = q
	}
	for _, have := range q.items {
		if have.ChunkID == item.ChunkID {
			return
		}
	}
	if len(q.items) == 0 {
		q.first = time.Now()
	}
	q.items = append(q.items, item)
	b.scheduleLocked(item.Sandbox, q)
}

// scheduleLocked (re)arms the sandbox's debounce timer, never past
// first+MaxDelay.
func (b *Batcher) scheduleLocked(sandbox string, q *queue) {
	if q.flushing {
		return
	}
	delay := b.opts.Debounce
	if left := time.Until(q.first.Add(b.opts.MaxDelay)); left < delay {
		delay = max(left, 0)
	}
	if q.timer != nil {
		q.timer.Stop()
	}
	q.timer = time.AfterFunc(delay, func() { b.signal(sandbox) })
}

func (b *Batcher) signal(sandbox string) {
	select {
	case b.ready <- sandbox:
	default:
		// The channel only overflows with hundreds of sandboxes flushing at
		// once; retry shortly instead of losing the batch.
		time.AfterFunc(100*time.Millisecond, func() { b.signal(sandbox) })
	}
}

// Pending reports how many approvals are queued for sandbox.
func (b *Batcher) Pending(sandbox string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if q := b.queues[sandbox]; q != nil {
		return len(q.items)
	}
	return 0
}

// Forget drops a sandbox's queued approvals (the sandbox was deleted).
func (b *Batcher) Forget(sandbox string) []Item {
	b.mu.Lock()
	defer b.mu.Unlock()
	q := b.queues[sandbox]
	if q == nil {
		return nil
	}
	if q.timer != nil {
		q.timer.Stop()
	}
	delete(b.queues, sandbox)
	return q.items
}

// Run applies batches until ctx ends.
func (b *Batcher) Run(ctx context.Context) error {
	b.mu.Lock()
	if b.running {
		b.mu.Unlock()
		return errors.New("triage: batcher is already running")
	}
	b.running = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.running = false
		b.mu.Unlock()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sandbox := <-b.ready:
			items, ok := b.take(sandbox)
			if !ok {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				b.flush(ctx, sandbox, items)
			}()
		}
	}
}

// take claims a sandbox's queue for one flush; a flush already running for
// the sandbox picks the new items up when it finishes.
func (b *Batcher) take(sandbox string) ([]Item, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	q := b.queues[sandbox]
	if q == nil || q.flushing || len(q.items) == 0 {
		return nil, false
	}
	items := q.items
	q.items = nil
	q.flushing = true
	b.busy++
	return items, true
}

func (b *Batcher) flush(ctx context.Context, sandbox string, items []Item) {
	results := b.apply(ctx, sandbox, items)
	if b.opts.OnResult != nil && len(results) > 0 {
		b.opts.OnResult(results)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.busy--
	if q := b.queues[sandbox]; q != nil {
		q.flushing = false
		if len(q.items) == 0 {
			delete(b.queues, sandbox)
		} else {
			q.first = time.Now()
			b.scheduleLocked(sandbox, q)
		}
	}
	b.idle.Broadcast()
}

// Drain waits until no flush is running and no batch is queued, or ctx
// ends. It does not flush early.
func (b *Batcher) Drain(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		b.mu.Lock()
		for b.busy > 0 || len(b.queues) > 0 {
			if ctx.Err() != nil {
				break
			}
			b.idle.Wait()
		}
		b.mu.Unlock()
		close(done)
	}()
	stop := context.AfterFunc(ctx, func() {
		b.mu.Lock()
		b.idle.Broadcast()
		b.mu.Unlock()
	})
	defer stop()
	<-done
	return ctx.Err()
}

func (b *Batcher) apply(ctx context.Context, sandbox string, items []Item) []Result {
	forced := false
	if q := b.opts.Quiesce; q != nil && items[0].BindingID != "" {
		wctx, cancel := context.WithTimeout(ctx, b.opts.MaxWait)
		err := q.WaitQuiescent(wctx, items[0].BindingID, b.opts.Idle)
		cancel()
		if ctx.Err() != nil {
			return failAll(items, ctx.Err())
		}
		forced = err != nil
	}
	var bulk []Item
	var results []Result
	for _, it := range items {
		if !it.Single {
			bulk = append(bulk, it)
			continue
		}
		res, err := b.opts.Apply.ApproveDraftChunk(ctx, sandbox, it.ChunkID, it.ReviewToken)
		r := Result{Item: it, Err: err, Forced: forced}
		if res != nil {
			r.PolicyVersion, r.PolicyHash = res.PolicyVersion, res.PolicyHash
		}
		results = append(results, r)
	}
	if len(bulk) == 0 {
		return results
	}
	approvals := make([]openshell.DraftChunkApproval, len(bulk))
	for i, it := range bulk {
		approvals[i] = openshell.DraftChunkApproval{ChunkID: it.ChunkID, ReviewToken: it.ReviewToken}
	}
	res, err := b.opts.Apply.ApproveDraftChunks(ctx, sandbox, approvals)
	if err != nil {
		return append(results, failAll(bulk, err)...)
	}
	skipped := 0
	if res != nil {
		skipped = int(res.ChunksSkipped)
	}
	for i, it := range bulk {
		r := Result{Item: it, Forced: forced}
		if res != nil {
			r.PolicyVersion, r.PolicyHash = res.PolicyVersion, res.PolicyHash
		}
		// The bulk answer counts skipped chunks without naming them; they
		// are the security-flagged ones, which triage never sends in bulk,
		// so a skip here marks the tail conservatively.
		if skipped > 0 && i >= len(bulk)-skipped {
			r.Skipped = true
		}
		results = append(results, r)
	}
	return results
}

func failAll(items []Item, err error) []Result {
	out := make([]Result, len(items))
	for i, it := range items {
		out[i] = Result{Item: it, Err: err}
	}
	return out
}
