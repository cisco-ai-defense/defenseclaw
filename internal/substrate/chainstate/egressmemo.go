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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// The callout's egress chain check answers from memory (GAP-0179). It runs
// under the callout's budget (20 ms by default) on every request to an
// allowed host, and a store write on the leader's volume (opening a new
// actor's store, the connector instance row, the observe transaction)
// does not fit it: on a chart install every request of a new actor timed
// out and was refused as unchecked. So the leader keeps, per actor, the
// egress-relevant part of its actor window in memory, fed by the hook
// observations it already handles, and answers from it. The exact record
// of the egress step (the window event) is written afterwards by one
// background worker, batched, off the RPC. The memo is saved in the
// actor's state file whenever a chain starts or ends, before the store
// write, so a new leader answers from it at once.

// egressMemo is an actor's egress state in memory. Times are the actor's
// running time (suspension does not count), in nanoseconds.
type egressMemo struct {
	mu sync.Mutex
	// warm: the memo covers everything in the actor's store. A store from
	// a leader that saved no memo is not covered until the worker has
	// evaluated one egress step on it.
	warm bool
	// step1 is the last first step of each egress chain, and how many
	// actor events came after it.
	step1 map[string]memoStep
	// hit is the last detection of an egress chain the store reported.
	hit map[string]int64
}

type memoStep struct {
	At     int64  `json:"at"`
	Events uint64 `json:"events,omitempty"`
}

// egressSnapshot is the memo as the state file keeps it.
type egressSnapshot struct {
	Step1 map[string]memoStep `json:"step1,omitempty"`
	Hit   map[string]int64    `json:"hit,omitempty"`
}

// errWarming answers a chain check for an actor whose stored windows the
// memo does not cover yet (a store from an older leader): the callout's
// chain failure mode decides, and the worker warms the memo.
var errWarming = &leader.WireError{Code: leader.CodeUnavailable, Message: "the actor's chain state is loading"}

// egressChainDefs are the definitions of egressChains.
var egressChainDefs = func() []guardrail.ToolChainDefinition {
	var out []guardrail.ToolChainDefinition
	for _, id := range egressChains {
		if d, ok := guardrail.ToolChainDefinitionByID(id); ok {
			out = append(out, d)
		}
	}
	return out
}()

// startsEgressChain reports whether mask holds the first step of an
// egress chain.
func startsEgressChain(mask uint64) bool {
	for _, d := range egressChainDefs {
		if d.Step1Bit != 0 && mask&d.Step1Bit != 0 {
			return true
		}
	}
	return false
}

func (m *egressMemo) init() {
	if m.step1 == nil {
		m.step1, m.hit = map[string]memoStep{}, map[string]int64{}
	}
}

// noteStep1 records the first steps in mask, before the store sees them:
// a store write that fails afterwards leaves the memo stricter, never
// laxer.
func (m *egressMemo) noteStep1(at int64, mask uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	for _, d := range egressChainDefs {
		if d.Step1Bit != 0 && mask&d.Step1Bit != 0 {
			m.step1[d.ID] = memoStep{At: at}
		}
	}
}

// noteObserved feeds one stored actor-window observation into the memo:
// any event other than a first step counts against the chain's event
// window, and a detection is kept. It reports whether a detection is new.
func (m *egressMemo) noteObserved(at int64, mask uint64, detected []string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	fresh := false
	for _, d := range egressChainDefs {
		if d.Step1Bit != 0 && mask&d.Step1Bit != 0 {
			if _, ok := m.step1[d.ID]; !ok {
				m.step1[d.ID] = memoStep{At: at}
			}
		} else if s, ok := m.step1[d.ID]; ok {
			s.Events++
			m.step1[d.ID] = s
		}
		if slices.Contains(detected, d.ID) {
			if _, ok := m.hit[d.ID]; !ok {
				fresh = true
			}
			m.hit[d.ID] = at
		}
	}
	return fresh
}

// reset forgets the windows (a terminal reset, or a revert barrier for the
// chains that keep one).
func (m *egressMemo) reset(barrierOnly bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range egressChainDefs {
		if !barrierOnly || d.ArtifactMutationBarrier {
			delete(m.step1, d.ID)
			delete(m.hit, d.ID)
		}
	}
}

// warmUp marks the memo as covering the store; it reports whether it did
// not before.
func (m *egressMemo) warmUp() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cold := !m.warm
	m.warm = true
	return cold
}

// merge adds a fork parent's windows to the child's memo (GAP-0091): a
// chain the child lacks, or whose parent step is later, comes from the
// parent. The child is warm only if both are.
func (m *egressMemo) merge(p *egressMemo) {
	p.mu.Lock()
	warm := p.warm
	step1, hit := map[string]memoStep{}, map[string]int64{}
	for k, v := range p.step1 {
		step1[k] = v
	}
	for k, v := range p.hit {
		hit[k] = v
	}
	p.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	m.warm = m.warm && warm
	for k, v := range step1 {
		if c, ok := m.step1[k]; !ok || v.At > c.At {
			m.step1[k] = v
		}
	}
	for k, v := range hit {
		if v > m.hit[k] {
			m.hit[k] = v
		}
	}
}

// snapshot is the memo for the state file.
func (m *egressMemo) snapshot() *egressSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := &egressSnapshot{}
	if len(m.step1) > 0 {
		out.Step1 = map[string]memoStep{}
		for k, v := range m.step1 {
			out.Step1[k] = v
		}
	}
	if len(m.hit) > 0 {
		out.Hit = map[string]int64{}
		for k, v := range m.hit {
			out.Hit[k] = v
		}
	}
	return out
}

// restore loads a saved memo: it covers the store (warm).
func (m *egressMemo) restore(snap *egressSnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.step1, m.hit = map[string]memoStep{}, map[string]int64{}
	for k, v := range snap.Step1 {
		m.step1[k] = v
	}
	for k, v := range snap.Hit {
		m.hit[k] = v
	}
	m.warm = true
}

// verdict is the chain check's answer at running time now; ok is false
// while the memo is not warm. A chain is live while its first step is
// inside the chain's windows; a detection the store reported counts only
// for a chain whose first step the memo does not know (a store from an
// older leader).
func (m *egressMemo) verdict(now int64, action string) (EgressVerdict, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.warm {
		return EgressVerdict{}, false
	}
	var v EgressVerdict
	for _, d := range egressChainDefs {
		live := false
		if s, ok := m.step1[d.ID]; ok {
			live = now-s.At <= int64(d.TimeWindow) && s.Events < d.EventWindow
		} else if t, ok := m.hit[d.ID]; ok {
			live = now-t <= int64(d.TimeWindow)
		}
		if !live {
			continue
		}
		v.Detected = append(v.Detected, d.ID)
		if egressDenyChains[d.ID] && v.Rule == "" {
			v.Rule = d.ID
			v.Reason = "Earlier in this actor's work it read a secret; DefenseClaw blocks sending data off the cluster after that."
			v.Deny = action == EgressBlock
		}
	}
	return v, true
}

// egressRecord is one egress step for the worker.
type egressRecord struct {
	actor Actor
	in    EgressRequest
}

// egressQueueSize bounds the steps waiting for the worker; a full queue
// drops the step (counted, warned once per drop run) and never blocks
// the check.
const egressQueueSize = 4096

// egressBatch is how many queued steps the worker takes at once; steps of
// one actor in a batch are recorded as one.
const egressBatch = 64

// egressWorker writes the exact egress steps off the RPC.
type egressWorker struct {
	ch      chan egressRecord
	done    chan struct{}
	dropped atomic.Uint64
	mu      sync.RWMutex
	closed  bool
}

func (s *Service) startEgressWorker() { s.startEgressWorkerWith(s.recordEgress) }

// startEgressWorkerWith runs the worker with record (tests slow it down).
func (s *Service) startEgressWorkerWith(record func(context.Context, EgressRequest) error) {
	w := &egressWorker{ch: make(chan egressRecord, egressQueueSize), done: make(chan struct{})}
	s.egress = w
	go func() {
		defer close(w.done)
		var reported uint64
		for first := range w.ch {
			batch := []egressRecord{first}
		drain:
			for len(batch) < egressBatch {
				select {
				case r, ok := <-w.ch:
					if !ok {
						break drain
					}
					batch = append(batch, r)
				default:
					break drain
				}
			}
			seen := map[string]bool{}
			for _, r := range batch {
				if seen[r.actor.key()] {
					continue
				}
				seen[r.actor.key()] = true
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := record(ctx, r.in); err != nil {
					s.warnf("record egress step for %s/%s: %v", r.actor.Atespace, r.actor.UID, err)
				}
				cancel()
			}
			if d := w.dropped.Load(); d != reported {
				s.warnf("egress worker queue full: %d egress steps not recorded in the actor windows (the checks were answered)", d-reported)
				reported = d
			}
		}
	}()
}

func (w *egressWorker) push(r egressRecord) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return
	}
	select {
	case w.ch <- r:
	default:
		w.dropped.Add(1)
	}
}

// stop drains the queue and waits for the worker.
func (w *egressWorker) stop() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
	w.mu.Unlock()
	<-w.done
}

// EgressDropped is how many egress steps a full queue dropped.
func (s *Service) EgressDropped() uint64 {
	if s.egress == nil {
		return 0
	}
	return s.egress.dropped.Load()
}
