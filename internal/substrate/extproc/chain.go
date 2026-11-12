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

package extproc

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// chainSendTimeout bounds one ObserveEgress call on the worker.
const chainSendTimeout = 2 * time.Second

// chainQueue hands observed_egress steps to a ChainSink on one background
// worker. push never blocks: a full queue drops the step and counts it.
type chainQueue struct {
	sink    ChainSink
	ch      chan ChainStep
	dropped atomic.Uint64
	mu      sync.RWMutex
	closed  bool
	done    chan struct{}
}

func newChainQueue(sink ChainSink, size int) *chainQueue {
	if sink == nil {
		return nil
	}
	q := &chainQueue{sink: sink, ch: make(chan ChainStep, size), done: make(chan struct{})}
	go q.run()
	return q
}

func (q *chainQueue) push(s ChainStep) {
	if q == nil {
		return
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return
	}
	select {
	case q.ch <- s:
	default:
		q.dropped.Add(1)
	}
}

func (q *chainQueue) run() {
	defer close(q.done)
	for s := range q.ch {
		func() {
			defer func() { _ = recover() }()
			ctx, cancel := context.WithTimeout(context.Background(), chainSendTimeout)
			defer cancel()
			_ = q.sink.ObserveEgress(ctx, s)
		}()
	}
}

func (q *chainQueue) close() {
	if q == nil {
		return
	}
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.ch)
	}
	q.mu.Unlock()
	<-q.done
}

func (q *chainQueue) droppedCount() uint64 {
	if q == nil {
		return 0
	}
	return q.dropped.Load()
}

// checkChain runs the synchronous egress-chain check under the budget. A
// miss, an error, a panic or the deadline is no hit: the hook-side step
// stands.
func (e *Engine) checkChain(ctx context.Context, step ChainStep) (ChainVerdict, bool) {
	if e.checker == nil {
		return ChainVerdict{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, e.cfg.Chain.CheckBudget)
	defer cancel()
	type result struct {
		v   ChainVerdict
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: context.Canceled}
			}
		}()
		v, err := e.checker.CheckEgress(ctx, step)
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err == nil && r.v.Deny
	case <-ctx.Done():
		return ChainVerdict{}, false
	}
}
