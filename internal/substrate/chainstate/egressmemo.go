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
	"bytes"
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// The callout's egress chain check answers from memory (GAP-0179). It runs
// under the callout's budget (20 ms by default) on every request to an
// allowed host, and a store write on the leader's volume (opening a new
// actor's store, the connector instance row, the observe transaction)
// does not fit it. So the leader keeps, per actor, a copy of the store's
// own state of the actor window (audit ScopeState: the window events, the
// next sequence and the prepared actions that start an egress chain) and
// matches an egress step against it with the store's matcher
// (guardrail.MatchToolChains). The copy is not a second model of the
// window: syncMemo reads it back from the store after every write to the
// actor window, whatever the path (a hook's prepare, resolve, observe,
// discard or reset; a fork copy; a revert barrier; the worker's egress
// record), so replays, resets, barriers and promoted pending steps count
// exactly as in the store. A prepared step counts from PreToolUse, before
// its PostToolUse promotes it, because the command may send the data
// while it runs. The exact record of an allowed egress step is written
// afterwards by one background worker, batched, off the RPC. The copy is
// saved in the actor's state file, so a new leader answers from it at
// once.

// egressMemo is an actor's egress state in memory. Times are the actor's
// running time (suspension does not count).
type egressMemo struct {
	mu sync.Mutex
	// warm: the memo is the store's state. A store from a leader that
	// saved no memo, or a read back that failed, leaves it cold until the
	// worker has synced it: the check answers unavailable meanwhile.
	warm bool
	// synced: the memo came from the store (or its saved copy); a fork
	// link made before the child's store leaves it alone.
	synced bool
	w      memoWindow
	// enc is w encoded, for the state file and to tell a change.
	enc []byte
}

// memoWindow is the actor window as the store has it.
type memoWindow struct {
	Ruleset string
	Next    uint64
	Events  []guardrail.ToolChainWindowEvent
	Pending []audit.ToolChainPendingStep
}

// egressSnapshotVersion is the saved memo's format. A state file with
// another version (or none) is from an older leader: its memo is cold.
const egressSnapshotVersion = 2

// egressSnapshot is the memo as the state file keeps it.
type egressSnapshot struct {
	V      int    `json:"v"`
	Window []byte `json:"window,omitempty"`
}

// errWarming answers a chain check for an actor whose stored window the
// memo does not hold yet: the callout's chain failure mode decides, and
// the worker syncs the memo.
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

// egressStep1Mask holds the first steps of the egress chains: the prepared
// actions the memo keeps.
var egressStep1Mask = func() uint64 {
	var m uint64
	for _, d := range egressChainDefs {
		m |= d.Step1Bit
	}
	return m
}()

// egressStep is the projection of an egress step: the second step of every
// egress chain.
var egressStep = func() guardrail.ToolChainProjection {
	var m uint64
	for _, id := range egressChains {
		if bit, ok := guardrail.ToolChainStepMask(id, 2); ok {
			m |= bit
		}
	}
	return guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete, DetectionStepMask: m}
}()

// startsEgressChain reports whether mask holds the first step of an
// egress chain.
func startsEgressChain(mask uint64) bool { return mask&egressStep1Mask != 0 }

func encodeWindow(w memoWindow) []byte {
	raw, err := encodeGob(w)
	if err != nil {
		return nil
	}
	return raw
}

// set makes w the memo (read back from the store); it reports whether the
// memo changed.
func (m *egressMemo) set(w memoWindow) bool {
	enc := encodeWindow(w)
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := !m.warm || !m.synced || !bytes.Equal(enc, m.enc)
	m.w, m.enc, m.warm, m.synced = w, enc, true, true
	return changed
}

// notePending adds a step the store is about to record, before it does:
// a leader that stops between the store write and the read back restarts
// from a saved memo that is stricter, never laxer. The next sync replaces
// it with the store's own state.
func (m *egressMemo) notePending(at time.Time, p guardrail.ToolChainProjection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.w
	w.Pending = append(slices.Clone(w.Pending), audit.ToolChainPendingStep{
		PreparedAt: at, ExpiresAt: at.Add(guardrail.ToolChainMaxHorizon), Projection: p})
	m.w, m.enc = w, encodeWindow(w)
}

// invalidate makes the memo cold: a read back failed, so it may miss a step.
func (m *egressMemo) invalidate() {
	m.mu.Lock()
	m.warm = false
	m.mu.Unlock()
}

// linkFrom gives a new forked actor's memo its parent's window before the
// child has a store (GAP-0091): its first egress is checked against what
// the parent did. A memo already synced from the child's store, which
// holds the copied windows, is kept.
func (m *egressMemo) linkFrom(p *egressMemo) {
	p.mu.Lock()
	w, warm := p.w, p.warm
	p.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.synced {
		return
	}
	m.w, m.enc, m.warm = w, encodeWindow(w), m.warm && warm
}

// snapshot is the memo for the state file.
func (m *egressMemo) snapshot() *egressSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &egressSnapshot{V: egressSnapshotVersion, Window: slices.Clone(m.enc)}
}

// restore loads a saved memo; false for a memo of another format.
func (m *egressMemo) restore(snap *egressSnapshot) bool {
	if snap == nil || snap.V != egressSnapshotVersion {
		return false
	}
	var w memoWindow
	if len(snap.Window) > 0 {
		if err := decodeGob(snap.Window, &w); err != nil {
			return false
		}
	}
	m.set(w)
	return true
}

// verdict is the chain check's answer at running time now; ok is false
// while the memo is cold or the window can't be matched.
func (m *egressMemo) verdict(now time.Time, action string) (EgressVerdict, bool) {
	m.mu.Lock()
	w, warm := m.w, m.warm
	m.mu.Unlock()
	if !warm {
		return EgressVerdict{}, false
	}
	detected, fileUnknown, ok := detectEgress(w, now)
	if !ok {
		return EgressVerdict{}, false
	}
	var v EgressVerdict
	for _, d := range egressChainDefs {
		if detected&d.ResultBit == 0 {
			continue
		}
		v.Detected = append(v.Detected, d.ID)
		if !egressDenyChains[d.ID] {
			continue
		}
		// A chain that joined only through the file-unknown marker only
		// alerts; a resolved one refuses while the action is block. The
		// verdict names a refusing chain before an alerting one.
		refuse := action == EgressBlock && RefusesEgressJoin(d.ID, fileUnknown)
		if v.Rule == "" || refuse && !v.Deny {
			v.Rule = d.ID
			v.Reason = "Earlier in this actor's work it read a secret; DefenseClaw blocks sending data off the cluster after that."
			if !refuse {
				v.Reason = "Earlier in this actor's work it read a secret; DefenseClaw alerts on sending data off the cluster after that."
			}
			v.Deny = refuse
		}
	}
	return v, true
}

// detectEgress matches an egress step at now against the window, as the
// store's Observe of that step would, and against each prepared first
// step on its own, as if it had just resolved. fileUnknown holds the
// detected chains that no match resolved: every match that detects them
// joined only through the file-unknown marker.
func detectEgress(w memoWindow, now time.Time) (detected, fileUnknown uint32, ok bool) {
	next := max(w.Next, 1)
	final := guardrail.ToolChainWindowEvent{SemanticEventID: "substrate.egress", Sequence: next, ReceivedAt: now, Projection: egressStep}
	var resolved uint32
	if len(w.Events) > 0 {
		m, err := guardrail.MatchToolChains(w.Events, final)
		if err != nil {
			return 0, 0, false
		}
		detected |= m.DetectedMask
		resolved |= m.DetectedMask &^ m.FileUnknownJoinMask
	}
	for _, p := range w.Pending {
		if !now.Before(p.ExpiresAt) {
			continue
		}
		prior := []guardrail.ToolChainWindowEvent{{SemanticEventID: "substrate.pending", Sequence: 1, ReceivedAt: p.PreparedAt, Projection: p.Projection}}
		m, err := guardrail.MatchToolChains(prior, guardrail.ToolChainWindowEvent{
			SemanticEventID: final.SemanticEventID, Sequence: 2, ReceivedAt: now, Projection: egressStep})
		if err != nil {
			return 0, 0, false
		}
		detected |= m.DetectedMask
		resolved |= m.DetectedMask &^ m.FileUnknownJoinMask
	}
	return detected, detected &^ resolved, true
}

// egressRecord is one job for the worker: an egress step to record, or
// (sync) a memo to read back from the store.
type egressRecord struct {
	actor Actor
	in    EgressRequest
	sync  bool
}

func (r egressRecord) key() string {
	if r.sync {
		return "sync/" + r.actor.key()
	}
	return "egress/" + r.actor.key()
}

// egressQueueSize bounds the jobs waiting for the worker; a full queue
// drops the job (counted, warned once per drop run) and never blocks the
// check.
const egressQueueSize = 4096

// egressBatch is how many queued jobs the worker takes at once; the same
// job of one actor in a batch runs once.
const egressBatch = 64

// egressWorker writes the exact egress steps off the RPC.
type egressWorker struct {
	ch      chan egressRecord
	done    chan struct{}
	dropped atomic.Uint64
	mu      sync.RWMutex
	closed  bool
}

// startEgressWorker runs the worker.
func (s *Service) startEgressWorker() {
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
				if seen[r.key()] {
					continue
				}
				seen[r.key()] = true
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				var err error
				if r.sync {
					err = s.warmMemo(ctx, r.actor)
				} else {
					err = s.recordEgress(ctx, r.in)
				}
				if err != nil {
					s.warnf("chain worker for %s/%s: %v", r.actor.Atespace, r.actor.UID, err)
				}
				cancel()
			}
			if d := w.dropped.Load(); d != reported {
				s.warnf("egress worker queue full: %d jobs dropped (the checks were answered)", d-reported)
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

// EgressDropped is how many worker jobs a full queue dropped.
func (s *Service) EgressDropped() uint64 {
	if s.egress == nil {
		return 0
	}
	return s.egress.dropped.Load()
}
