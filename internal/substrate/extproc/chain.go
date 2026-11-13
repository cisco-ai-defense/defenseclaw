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
	"errors"
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

// chainPerActorInflight caps one actor's concurrent chain checks, so an
// actor flooding its own window can't take the leader's time from others
// (GAP-0090). A check over the cap waits for a slot within its budget, so
// a normal burst of parallel requests (a package install) is checked, not
// refused; only a sustained flood is unchecked.
const chainPerActorInflight = 8

// Chain check outcomes.
const (
	chainClear = iota
	chainHit
	chainUnchecked
)

// Why a chain check could not answer.
const (
	uncheckedError    = "error"
	uncheckedTimeout  = "timeout"
	uncheckedBusy     = "actor_busy"
	uncheckedInternal = "internal_error"
	// uncheckedUnregistered is an actor with no registration (no UID), so
	// no chain window can be named for it (GAP-0090).
	uncheckedUnregistered = "unregistered"
)

// chainLimiter bounds in-flight checks per actor: one semaphore per actor,
// dropped when its last check returns.
type chainLimiter struct {
	mu sync.Mutex
	m  map[string]*actorSlots
}

type actorSlots struct {
	ch    chan struct{}
	users int
}

// acquire takes a slot for key, waiting until ctx ends.
func (l *chainLimiter) acquire(ctx context.Context, key string) bool {
	l.mu.Lock()
	if l.m == nil {
		l.m = map[string]*actorSlots{}
	}
	s := l.m[key]
	if s == nil {
		s = &actorSlots{ch: make(chan struct{}, chainPerActorInflight)}
		l.m[key] = s
	}
	s.users++
	l.mu.Unlock()
	select {
	case s.ch <- struct{}{}:
		return true
	default:
	}
	select {
	case s.ch <- struct{}{}:
		return true
	case <-ctx.Done():
		l.done(key, s)
		return false
	}
}

// release returns key's slot.
func (l *chainLimiter) release(key string) {
	l.mu.Lock()
	s := l.m[key]
	l.mu.Unlock()
	if s == nil {
		return
	}
	<-s.ch
	l.done(key, s)
}

func (l *chainLimiter) done(key string, s *actorSlots) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s.users--; s.users <= 0 && l.m[key] == s {
		delete(l.m, key)
	}
}

// checkChain runs the synchronous egress-chain check under the budget. A
// miss is clear. An actor with no registration, an error, a panic, the
// deadline or the actor's in-flight cap is unchecked, with the reason: the
// caller applies the chain failure mode, because on the hook path an
// egress chain only alerts and the callout is where it blocks (GAP-0090).
func (e *Engine) checkChain(ctx context.Context, step ChainStep) (ChainVerdict, int, string) {
	if e.checker == nil {
		return ChainVerdict{}, chainClear, ""
	}
	if step.Actor.UID == "" {
		return ChainVerdict{}, chainUnchecked, uncheckedUnregistered
	}
	key := step.Actor.Atespace + "/" + step.Actor.Name
	// The budget covers the wait for a slot and the check. The slot is
	// released when the check returns, not at the deadline, so a slow
	// leader keeps counting against the actor that sent it.
	ctx, cancel := context.WithTimeout(ctx, e.cfg.Chain.CheckBudget)
	if !e.chainLimit.acquire(ctx, key) {
		cancel()
		return ChainVerdict{}, chainUnchecked, uncheckedBusy
	}
	type result struct {
		v        ChainVerdict
		err      error
		panicked bool
		timedOut bool
	}
	ch := make(chan result, 1)
	go func() {
		defer e.chainLimit.release(key)
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				ch <- result{panicked: true}
			}
		}()
		v, err := e.checker.CheckEgress(ctx, step)
		ch <- result{v: v, err: err, timedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)}
	}()
	select {
	case r := <-ch:
		switch {
		case r.panicked:
			return ChainVerdict{}, chainUnchecked, uncheckedInternal
		case r.err != nil && r.timedOut:
			return ChainVerdict{}, chainUnchecked, uncheckedTimeout
		case r.err != nil:
			return ChainVerdict{}, chainUnchecked, uncheckedError
		case r.v.Deny:
			return r.v, chainHit, ""
		}
		return r.v, chainClear, ""
	case <-ctx.Done():
		return ChainVerdict{}, chainUnchecked, uncheckedTimeout
	}
}

// chainFailClosed reports whether an unchecked chain step refuses: always
// with chain.failure_mode closed, never with open (refused at load on a
// managed install), and with auto (the default) on a managed install (D8)
// or for an unattended actor, since nobody watches its alerts.
func (e *Engine) chainFailClosed(pol *Policy) bool {
	switch e.cfg.Chain.FailureMode {
	case FailureClosed:
		return true
	case FailureOpen:
		return false
	}
	return e.cfg.Managed || pol.Unattended
}
