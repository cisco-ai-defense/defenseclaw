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
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Applier reads a sandbox's draft inbox and applies approved chunks to its
// policy. openshell.Client satisfies it.
//
// OpenShell binds a chunk's review token to the live policy: once any other
// change lands, the token a chunk was reviewed with no longer approves it
// (the single call answers FAILED_PRECONDITION, the bulk call counts the
// chunk as skipped without an error). The batcher therefore reads fresh
// tokens right before it applies and reads the inbox again afterwards to
// learn which chunks landed.
type Applier interface {
	// GetDraft returns the sandbox's draft chunks ("" status: all of them).
	GetDraft(ctx context.Context, sandbox, status string) (*openshell.DraftPolicy, error)
	// ApproveDraftChunks approves several reviewed chunks in one policy
	// revision; security-flagged chunks and chunks with stale tokens are
	// skipped.
	ApproveDraftChunks(ctx context.Context, sandbox string, approvals []openshell.DraftChunkApproval) (*openshell.ApproveAllResult, error)
	// ApproveDraftChunk approves one chunk, security-flagged ones included.
	ApproveDraftChunk(ctx context.Context, sandbox, chunkID, reviewToken string) (*openshell.ApproveResult, error)
}

// Quiescer waits until a sandbox binding has no ingress request open and
// none for idle. *sandboxauth.InFlight satisfies it.
type Quiescer interface {
	WaitQuiescent(ctx context.Context, bindingID string, idle time.Duration) error
}

// TunnelActivity reports a sandbox binding's traffic through the DefenseClaw
// egress proxy: its open tunnels and forwarded requests, and the bytes they
// moved so far. *egress.Proxy satisfies it.
type TunnelActivity interface {
	BindingActivity(bindingID string) (open int, moved int64)
}

// Item is one approval waiting to be applied.
type Item struct {
	Sandbox   string
	BindingID string
	ChunkID   string
	// Digest is ContentDigest of the chunk as it was decided. A chunk whose
	// content differs when the batch is applied is not approved (Result
	// Changed); empty skips the check.
	Digest string
	// Tag is carried through to the Result.
	Tag any

	// attempts counts applications that lost a race with another policy
	// change.
	attempts int
}

// Result is the outcome of one Item. At most one of Err, Refused, Skipped,
// Changed, Stale and Gone is set; none means the chunk is approved.
type Result struct {
	Item Item
	// Err is set when the approval failed.
	Err error
	// Refused is set when BatcherOptions.Recheck refused the approval right
	// before it was applied; the chunk was not approved and is still
	// pending.
	Refused error
	// Skipped reports a security-flagged chunk OpenShell left out of a bulk
	// approval.
	Skipped bool
	// Changed reports a chunk whose proposed content changed after it was
	// decided; it was not approved and must be triaged again.
	Changed bool
	// Stale reports a chunk OpenShell kept refusing because its policy
	// changed under every attempt; it was not approved.
	Stale bool
	// Gone reports a chunk that is no longer pending (rejected or removed).
	Gone bool
	// PolicyVersion is the sandbox policy revision the approval landed in
	// (0 when another client approved the chunk first).
	PolicyVersion uint32
	PolicyHash    string
	// Forced reports a batch applied after MaxWait without quiescence.
	Forced bool
}

// maxApplyAttempts bounds how often an approval whose review token went
// stale is retried with a fresh one.
const maxApplyAttempts = 3

// BatcherOptions configure a Batcher.
type BatcherOptions struct {
	Apply Applier
	// Quiesce is consulted before each batch; nil applies at once.
	Quiesce Quiescer
	// Tunnels, when set, is consulted before each batch too: the policy
	// reload closes the sandbox's connections through the egress proxy as
	// well (a package download, a clone), so a batch also waits until none
	// of the binding's tunnels moved a byte for Idle, or none is open,
	// within the same MaxWait. The harness's model streams run over its
	// provider's direct rule, which DefenseClaw does not see: a reload
	// during one still interrupts it.
	Tunnels TunnelActivity
	// Debounce collects approvals until none arrived for this long
	// (openshell.approvals.debounce_ms; default 3s).
	Debounce time.Duration
	// MaxDelay caps how long debouncing may postpone a batch (default 30s).
	MaxDelay time.Duration
	// Idle is the hook-quiet (and tunnel-quiet) interval required before
	// applying (default 2s).
	Idle time.Duration
	// MaxWait bounds the wait for quiescence; a sandbox busy that long gets
	// its batch anyway (default 2m).
	MaxWait time.Duration
	// Recheck, when set, judges every approval again right before it is
	// applied, against the chunk as it is then: a destination name may
	// resolve elsewhere, and the policy may have changed, since the approval
	// was decided. An error leaves the chunk unapproved (Result.Refused).
	Recheck func(ctx context.Context, item Item, chunk openshell.PolicyChunk) error
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
// The chunk's review token is read when the batch is applied.
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
			q, items, ok := b.take(sandbox)
			if !ok {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				b.flush(ctx, sandbox, q, items)
			}()
		}
	}
}

// take claims a sandbox's queue for one flush; a flush already running for
// the sandbox picks the new items up when it finishes.
func (b *Batcher) take(sandbox string) (*queue, []Item, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	q := b.queues[sandbox]
	if q == nil || q.flushing || len(q.items) == 0 {
		return nil, nil, false
	}
	items := q.items
	q.items = nil
	q.flushing = true
	b.busy++
	return q, items, true
}

func (b *Batcher) flush(ctx context.Context, sandbox string, q *queue, items []Item) {
	results, retry := b.apply(ctx, sandbox, items)
	if b.opts.OnResult != nil && len(results) > 0 {
		b.opts.OnResult(results)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.busy--
	// A flushing queue stays in the map until the flush ends, unless Forget
	// dropped the sandbox; its retries go with it.
	if b.queues[sandbox] == q {
		q.flushing = false
		for _, it := range retry {
			if !slices.ContainsFunc(q.items, func(have Item) bool { return have.ChunkID == it.ChunkID }) {
				q.items = append(q.items, it)
			}
		}
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

// apply approves one sandbox's batch at a quiet moment. It returns the
// finished results and the items to retry in a later batch.
func (b *Batcher) apply(ctx context.Context, sandbox string, items []Item) ([]Result, []Item) {
	forced := false
	if items[0].BindingID != "" && (b.opts.Quiesce != nil || b.opts.Tunnels != nil) {
		forced = b.waitQuiet(ctx, items[0].BindingID)
		if ctx.Err() != nil {
			return failAll(items, ctx.Err()), nil
		}
	}
	a := applyRun{b: b, ctx: ctx, sandbox: sandbox, forced: forced}
	draft, err := a.draft()
	if err != nil {
		return failAll(items, err), nil
	}
	// Security-flagged chunks need the single call (the bulk call skips
	// them); everything else lands in one revision. Of chunks naming the
	// same rule only the first is applied: approving merges a chunk into
	// the rule of its name, and a chunk judged before that rule existed
	// must be judged again against it (FromChunk refuses a merge into
	// another destination's rule), so the others wait for the next batch.
	var bulk, single []Item
	rules := map[string]bool{}
	for _, it := range items {
		c, done := a.check(draft, it)
		rule := chunkRuleName(c)
		switch {
		case done:
		case rule != "" && rules[rule]:
			a.retry = append(a.retry, it)
		case a.refused(it, c):
		case c.SecurityNotes != "":
			single, rules[rule] = append(single, it), true
		default:
			bulk, rules[rule] = append(bulk, it), true
		}
	}
	if len(bulk) > 0 {
		a.bulk(draft, bulk)
	}
	for i, it := range single {
		// Every approval that lands changes the policy and so every other
		// chunk's review token: read a fresh one before each single call.
		if len(bulk) > 0 || i > 0 {
			if draft, err = a.draft(); err != nil {
				a.fail(it, err)
				continue
			}
			if _, done := a.check(draft, it); done {
				continue
			}
		}
		a.single(draft, it)
	}
	return a.results, a.retry
}

// waitQuiet waits until binding's hooks are quiet (Quiesce) and its egress
// tunnels idle (Tunnels) at the same time, and reports whether MaxWait (or
// ctx) ended the wait first.
func (b *Batcher) waitQuiet(ctx context.Context, binding string) (forced bool) {
	wctx, cancel := context.WithTimeout(ctx, b.opts.MaxWait)
	defer cancel()
	for {
		if q := b.opts.Quiesce; q != nil {
			if err := q.WaitQuiescent(wctx, binding, b.opts.Idle); err != nil {
				return true
			}
		}
		if b.tunnelsIdle(wctx, binding) {
			// A hook request may have arrived while the tunnels were
			// watched; InFlight tells without waiting.
			q, ok := b.opts.Quiesce.(interface {
				Quiescent(bindingID string, idle time.Duration) bool
			})
			if !ok || q.Quiescent(binding, b.opts.Idle) {
				return false
			}
		}
		if wctx.Err() != nil {
			return true
		}
	}
}

// tunnelsIdle reports that none of binding's egress tunnels moved a byte
// for Idle, or none is open.
func (b *Batcher) tunnelsIdle(ctx context.Context, binding string) bool {
	t := b.opts.Tunnels
	if t == nil {
		return true
	}
	open, before := t.BindingActivity(binding)
	if open == 0 {
		return true
	}
	timer := time.NewTimer(b.opts.Idle)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
	}
	now, after := t.BindingActivity(binding)
	return now == 0 || (now == open && after == before)
}

// applyRun collects one batch's outcomes.
type applyRun struct {
	b       *Batcher
	ctx     context.Context
	sandbox string
	forced  bool
	results []Result
	retry   []Item
}

func (a *applyRun) draft() (map[string]openshell.PolicyChunk, error) {
	d, err := a.b.opts.Apply.GetDraft(a.ctx, a.sandbox, "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]openshell.PolicyChunk, len(d.Chunks))
	for _, c := range d.Chunks {
		out[c.ID] = c
	}
	return out, nil
}

func (a *applyRun) result(r Result) {
	r.Forced = a.forced
	a.results = append(a.results, r)
}

func (a *applyRun) fail(it Item, err error) { a.result(Result{Item: it, Err: err}) }

// refused runs BatcherOptions.Recheck on an item about to be applied and
// settles it as Refused when the check fails.
func (a *applyRun) refused(it Item, c openshell.PolicyChunk) bool {
	if a.b.opts.Recheck == nil {
		return false
	}
	if err := a.b.opts.Recheck(a.ctx, it, c); err != nil {
		a.result(Result{Item: it, Refused: err})
		return true
	}
	return false
}

// again retries an item whose review token went stale, up to
// maxApplyAttempts.
func (a *applyRun) again(it Item) {
	it.attempts++
	if it.attempts >= maxApplyAttempts {
		a.result(Result{Item: it, Stale: true})
		return
	}
	a.retry = append(a.retry, it)
}

// check settles an item that cannot be approved as decided: the chunk is
// gone, already decided, or its content changed. It returns the live chunk
// and whether the item is settled.
func (a *applyRun) check(draft map[string]openshell.PolicyChunk, it Item) (openshell.PolicyChunk, bool) {
	c, ok := draft[it.ChunkID]
	switch {
	case !ok:
		a.result(Result{Item: it, Gone: true})
	case c.Status == "approved":
		// Approved by another client in the meantime.
		a.result(Result{Item: it})
	case c.Status != "" && c.Status != "pending":
		a.result(Result{Item: it, Gone: true})
	case it.Digest != "" && ContentDigest(c) != it.Digest:
		a.result(Result{Item: it, Changed: true})
	default:
		return c, false
	}
	return c, true
}

func (a *applyRun) bulk(draft map[string]openshell.PolicyChunk, items []Item) {
	approvals := make([]openshell.DraftChunkApproval, len(items))
	for i, it := range items {
		approvals[i] = openshell.DraftChunkApproval{ChunkID: it.ChunkID, ReviewToken: draft[it.ChunkID].ReviewToken}
	}
	res, err := a.b.opts.Apply.ApproveDraftChunks(a.ctx, a.sandbox, approvals)
	if err != nil {
		for _, it := range items {
			a.fail(it, err)
		}
		return
	}
	if res == nil {
		res = &openshell.ApproveAllResult{}
	}
	// The bulk answer counts skipped chunks without naming them: read the
	// inbox again to learn which ones landed.
	after, err := a.draft()
	if err != nil {
		if res.ChunksSkipped == 0 && int(res.ChunksApproved) == len(items) {
			for _, it := range items {
				a.result(Result{Item: it, PolicyVersion: res.PolicyVersion, PolicyHash: res.PolicyHash})
			}
			return
		}
		for _, it := range items {
			a.again(it)
		}
		return
	}
	for _, it := range items {
		c, ok := after[it.ChunkID]
		switch {
		case ok && c.Status == "approved":
			a.result(Result{Item: it, PolicyVersion: res.PolicyVersion, PolicyHash: res.PolicyHash})
		case ok && (c.Status == "" || c.Status == "pending"):
			if c.SecurityNotes != "" {
				a.result(Result{Item: it, Skipped: true})
				continue
			}
			// Still pending without a flag: the token went stale under a
			// concurrent policy change.
			a.again(it)
		default:
			a.result(Result{Item: it, Gone: true})
		}
	}
}

func (a *applyRun) single(draft map[string]openshell.PolicyChunk, it Item) {
	res, err := a.b.opts.Apply.ApproveDraftChunk(a.ctx, a.sandbox, it.ChunkID, draft[it.ChunkID].ReviewToken)
	switch {
	case openshell.IsConflict(err):
		// A stale token, or a chunk decided meanwhile: the retry reads
		// the inbox again and tells them apart.
		a.again(it)
	case err != nil:
		a.fail(it, err)
	default:
		r := Result{Item: it}
		if res != nil {
			r.PolicyVersion, r.PolicyHash = res.PolicyVersion, res.PolicyHash
		}
		a.result(r)
	}
}

// chunkRuleName is the network_policies key approving c merges into
// (FromChunk's RuleName).
func chunkRuleName(c openshell.PolicyChunk) string {
	if c.RuleName == "" && c.ProposedRule != nil {
		return c.ProposedRule.Name
	}
	return c.RuleName
}

func failAll(items []Item, err error) []Result {
	out := make([]Result, len(items))
	for i, it := range items {
		out[i] = Result{Item: it, Err: err}
	}
	return out
}
