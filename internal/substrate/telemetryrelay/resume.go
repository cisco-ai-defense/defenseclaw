// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

// The first hook call of an actor after a resume (GAP-0486). No component
// sees a resume when it happens; the controller sees the actor suspended at
// a pass (time S) and the leader adds that lifecycle record here. An actor
// seen suspended at S runs a hook call only after it resumed, so the first
// hook call any gateway replica serves for it that started after S is its
// first after the resume.
//
// Lifecycle records are a queue, so only one replica gets each record, and
// the actor's next call may land on any replica. So the leader decides:
//
//   - It keeps the suspended-since-S set and hands it to every replica in
//     each MethodResumeSync answer (a broadcast, like the gauges, not a
//     queue). A replica claims only for an actor in its copy of the set
//     (one leader call, MethodResumeClaim); every other hook call costs a
//     map lookup and nothing on the network.
//   - Each sync also reports the newest hook call start of every actor the
//     replica served since its last sync. A call served after S that did
//     not claim (its replica did not have S yet) drops the entry: the mark
//     is missed, never put on a later call.
//   - A claim wins only once every live replica has acknowledged the entry,
//     that is synced again after applying an answer that carried it. By
//     then every call any replica served after S either claimed or was
//     reported. A claim before that, or one after a reported call, drops
//     the entry unmarked.
//
//   - The leader must know every replica that serves hooks. A replica syncs
//     once before it serves (Taker.Join), and a leader that just started
//     marks nothing for ResumeReplicaTTL (Store.ResumeWarmup): its replica
//     set fills only as each replica syncs with it.
//
// Known limits that give a missed mark: a quick resume before every replica
// acknowledged; a leader change (the set is in the leader's memory, and the
// new leader warms up); a suspend and resume the controller saw inside one
// pass (same time).
//
// Known limits that can mark a later call instead of the first:
//   - Concurrent first calls, on two replicas or two on one replica that
//     reach Hook out of start order: the claim that reaches the leader first
//     wins, and it may be the later-starting call's.
//   - A replica the leader does not know: one that could not reach the leader
//     when it started (until its first sync), a 1.0.10 replica in a mixed
//     rollout (it never syncs), or one that served hooks while it could not
//     reach the leader for over ResumeReplicaTTL.

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Leader methods of the first-hook-after-resume mark (GAP-0486). They are
// new methods, not new fields of MethodTake: the leader decodes a take
// strictly, so a newer replica's fields would fail every take on an older
// leader in a rolling upgrade. An older leader answers these with an error,
// and the replica then marks nothing.
const (
	MethodResumeSync  = "TelemetryResumeSync"
	MethodResumeClaim = "TelemetryResumeClaim"
)

const (
	// MaxResumeActors bounds the suspended set, the leader's newest hook
	// call starts and a replica's report, in actors.
	MaxResumeActors = 4096
	// ResumeReplicaTTL is how long a replica that stopped syncing still
	// counts as live: a claim waits for its acknowledgement.
	ResumeReplicaTTL = 2 * time.Minute
	// maxResumeReplicas bounds the replicas the leader tracks.
	maxResumeReplicas = 64
	// resumeEvictBatch is how many of the oldest newest-call starts go at
	// once when the leader's map is full: one sort per batch instead of a
	// scan of the whole map under the leader lock for every new actor.
	resumeEvictBatch = MaxResumeActors / 8
)

// ResumeSyncRequest is a replica's sync: who it is, the sequence number of
// this sync and of the newest answer it applied, and the newest start (Unix
// ns) of each actor's hook calls it served since its last sync. Overflow is
// set when it served more actors than it could keep.
type ResumeSyncRequest struct {
	Replica  string           `json:"replica"`
	Seq      uint64           `json:"seq"`
	Applied  uint64           `json:"applied,omitempty"`
	Hooks    map[string]int64 `json:"hooks,omitempty"`
	Overflow bool             `json:"overflow,omitempty"`
}

// ResumeSyncResponse is the suspended set: actor UID -> S (Unix ns).
type ResumeSyncResponse struct {
	Suspended map[string]int64 `json:"suspended,omitempty"`
}

// ResumeClaimRequest claims the mark for a hook call that started at Start
// (Unix ns).
type ResumeClaimRequest struct {
	Replica string `json:"replica"`
	UID     string `json:"uid"`
	Start   int64  `json:"start"`
}

// ResumeClaimResponse says whether the call is the first after the resume.
type ResumeClaimResponse struct {
	First bool `json:"first,omitempty"`
}

type resumeEntry struct {
	at int64
	// delivered is the sequence number of each replica's first sync whose
	// answer carried the entry; acked the replicas that synced again after
	// applying such an answer.
	delivered map[string]uint64
	acked     map[string]bool
}

// resumeLeader is the leader's side, in the Store.
type resumeLeader struct {
	mu       sync.Mutex
	entries  map[string]*resumeEntry
	hookSeen map[string]int64
	replicas map[string]time.Time
	// started is the leader's first resume call: the warm-up starts there.
	started time.Time
	// now replaces the clock (tests).
	now func() time.Time
}

// startLocked notes the leader's first resume call.
func (l *resumeLeader) startLocked(now time.Time) {
	if l.started.IsZero() {
		l.started = now
	}
}

func (l *resumeLeader) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// lifecycle notes a lifecycle record the leader queues.
func (l *resumeLeader) lifecycle(r Record) {
	if r.UID == "" || r.At.IsZero() {
		return
	}
	at := r.At.UnixNano()
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.startLocked(now)
	switch r.Lifecycle {
	case chainstate.LifecycleSuspended:
		if seen, ok := l.hookSeen[r.UID]; ok && seen > at {
			// Its first call after the resume was served already, unmarked.
			delete(l.entries, r.UID)
			return
		}
		if e, ok := l.entries[r.UID]; ok && e.at >= at {
			return
		}
		l.boundEntriesLocked(r.UID)
		l.entries[r.UID] = &resumeEntry{at: at}
	case chainstate.LifecycleResumed:
		// Seen suspended and running again inside one pass: the first call
		// may have run before that pass, so nothing is marked.
		if e, ok := l.entries[r.UID]; ok && at <= e.at {
			delete(l.entries, r.UID)
		}
	case chainstate.LifecycleDeleted:
		delete(l.entries, r.UID)
		delete(l.hookSeen, r.UID)
	}
}

// noteHookLocked records a served hook call: an entry it started after is
// gone (that call was the first one).
func (l *resumeLeader) noteHookLocked(uid string, start int64) {
	if uid == "" {
		return
	}
	if e, ok := l.entries[uid]; ok && start > e.at {
		delete(l.entries, uid)
	}
	if prev, ok := l.hookSeen[uid]; ok && prev >= start {
		return
	}
	if l.hookSeen == nil {
		l.hookSeen = map[string]int64{}
	}
	if _, ok := l.hookSeen[uid]; !ok && len(l.hookSeen) >= MaxResumeActors {
		evictOldest(l.hookSeen, resumeEvictBatch)
	}
	l.hookSeen[uid] = start
}

// evictOldest deletes the n entries of m with the oldest values.
func evictOldest(m map[string]int64, n int) {
	if n <= 0 || len(m) == 0 {
		return
	}
	at := make([]int64, 0, len(m))
	for _, v := range m {
		at = append(at, v)
	}
	slices.Sort(at)
	cut := at[min(n, len(at))-1]
	for k, v := range m {
		if n == 0 {
			return
		}
		if v <= cut {
			delete(m, k)
			n--
		}
	}
}

func (l *resumeLeader) boundEntriesLocked(uid string) {
	if l.entries == nil {
		l.entries = map[string]*resumeEntry{}
	}
	if _, ok := l.entries[uid]; ok || len(l.entries) < MaxResumeActors {
		return
	}
	var oldest string
	var oldestAt int64
	for k, e := range l.entries {
		if oldest == "" || e.at < oldestAt {
			oldest, oldestAt = k, e.at
		}
	}
	delete(l.entries, oldest)
}

func (l *resumeLeader) liveReplicasLocked(now time.Time) {
	for id, at := range l.replicas {
		if now.Sub(at) > ResumeReplicaTTL {
			delete(l.replicas, id)
		}
	}
}

// ResumeSync implements MethodResumeSync.
func (s *Store) ResumeSync(_ context.Context, in ResumeSyncRequest) (ResumeSyncResponse, error) {
	l := &s.resumes
	if in.Replica == "" || in.Seq == 0 {
		return ResumeSyncResponse{}, &leader.WireError{Code: leader.CodeBadRequest, Message: "a resume sync names its replica and sequence"}
	}
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.startLocked(now)
	l.liveReplicasLocked(now)
	if l.replicas == nil {
		l.replicas = map[string]time.Time{}
	}
	if _, ok := l.replicas[in.Replica]; !ok && len(l.replicas) >= maxResumeReplicas {
		var oldest string
		var oldestAt time.Time
		for id, at := range l.replicas {
			if oldest == "" || at.Before(oldestAt) {
				oldest, oldestAt = id, at
			}
		}
		delete(l.replicas, oldest)
	}
	l.replicas[in.Replica] = now
	if in.Overflow {
		// The replica could not keep every call it served: any entry's
		// first call may be among them.
		clear(l.entries)
	}
	n := 0
	for uid, start := range in.Hooks {
		if n++; n > MaxResumeActors {
			clear(l.entries)
			break
		}
		l.noteHookLocked(uid, start)
	}
	out := ResumeSyncResponse{}
	if len(l.entries) > 0 {
		out.Suspended = make(map[string]int64, len(l.entries))
	}
	for uid, e := range l.entries {
		if d, ok := e.delivered[in.Replica]; !ok {
			if e.delivered == nil {
				e.delivered = map[string]uint64{}
			}
			e.delivered[in.Replica] = in.Seq
		} else if in.Applied >= d {
			if e.acked == nil {
				e.acked = map[string]bool{}
			}
			e.acked[in.Replica] = true
		}
		out.Suspended[uid] = e.at
	}
	return out, nil
}

// ResumeClaim implements MethodResumeClaim: the call is the first after the
// resume only when it started after S, no call after S was reported, every
// live replica acknowledged the entry, and the leader is past its warm-up.
// Any claim for a call after S ends the entry.
func (s *Store) ResumeClaim(_ context.Context, in ResumeClaimRequest) (ResumeClaimResponse, error) {
	l := &s.resumes
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.startLocked(now)
	e, ok := l.entries[in.UID]
	if !ok || in.Start <= e.at {
		return ResumeClaimResponse{}, nil
	}
	l.liveReplicasLocked(now)
	_, first := l.replicas[in.Replica]
	for id := range l.replicas {
		if !e.acked[id] {
			first = false
		}
	}
	if seen, ok := l.hookSeen[in.UID]; ok && seen > e.at {
		first = false
	}
	if now.Sub(l.started) < s.resumeWarmup() {
		// A replica that has not synced with this leader yet may have
		// served the first call.
		first = false
	}
	delete(l.entries, in.UID)
	l.noteHookLocked(in.UID, in.Start)
	return ResumeClaimResponse{First: first}, nil
}

// Resumes is a gateway replica's side: its copy of the suspended set and
// its report of the hook calls it served. The zero value is ready.
type Resumes struct {
	once    sync.Once
	replica string

	mu       sync.Mutex
	seq      uint64
	applied  uint64
	hooks    map[string]int64
	overflow bool
	maybe    map[string]int64
	// claimed is the S each actor was claimed for here, so a sync answer
	// that left before the claim does not start a second claim.
	claimed map[string]int64
}

func (r *Resumes) id() string {
	r.once.Do(func() { r.replica = leader.NewRequestID() })
	return r.replica
}

// Hook notes a hook call for uid that started at start and says whether to
// claim the mark for it. It is on every hook call: a map lookup and update.
func (r *Resumes) Hook(uid string, start time.Time) bool {
	if uid == "" {
		return false
	}
	ns := start.UnixNano()
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.hooks[uid]; !ok || ns > prev {
		switch {
		case !ok && len(r.hooks) >= MaxResumeActors:
			r.overflow = true
		default:
			if r.hooks == nil {
				r.hooks = map[string]int64{}
			}
			r.hooks[uid] = ns
		}
	}
	at, ok := r.maybe[uid]
	if !ok || ns <= at {
		return false
	}
	if c, ok := r.claimed[uid]; ok && c == at {
		return false
	}
	delete(r.maybe, uid)
	if r.claimed == nil {
		r.claimed = map[string]int64{}
	}
	r.claimed[uid] = at
	return true
}

// Sync reports the calls served since the last sync and applies the
// leader's suspended set. A failed sync keeps its report for the next one.
func (r *Resumes) Sync(ctx context.Context, c *leader.Client) error {
	id := r.id()
	r.mu.Lock()
	r.seq++
	in := ResumeSyncRequest{Replica: id, Seq: r.seq, Applied: r.applied, Hooks: r.hooks, Overflow: r.overflow}
	r.hooks, r.overflow = nil, false
	r.mu.Unlock()
	var out ResumeSyncResponse
	err := c.Call(ctx, MethodResumeSync, leader.NewRequestID(), in, &out)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.overflow = r.overflow || in.Overflow
		for uid, ns := range in.Hooks {
			if prev, ok := r.hooks[uid]; ok && prev >= ns {
				continue
			} else if !ok && len(r.hooks) >= MaxResumeActors {
				r.overflow = true
				continue
			}
			if r.hooks == nil {
				r.hooks = map[string]int64{}
			}
			r.hooks[uid] = ns
		}
		return err
	}
	r.applied = in.Seq
	maybe := make(map[string]int64, len(out.Suspended))
	for uid, at := range out.Suspended {
		if len(maybe) >= MaxResumeActors {
			break
		}
		if c, ok := r.claimed[uid]; ok && c == at {
			continue
		}
		maybe[uid] = at
	}
	for uid, at := range r.claimed {
		if out.Suspended[uid] != at {
			delete(r.claimed, uid)
		}
	}
	r.maybe = maybe
	return nil
}

// Claim asks the leader whether the hook call for uid that started at
// start is the first after the resume. An error is a no.
func (r *Resumes) Claim(ctx context.Context, c *leader.Client, uid string, start time.Time) bool {
	var out ResumeClaimResponse
	if err := c.Call(ctx, MethodResumeClaim, leader.NewRequestID(), ResumeClaimRequest{Replica: r.id(), UID: uid, Start: start.UnixNano()}, &out); err != nil {
		return false
	}
	return out.First
}

// resumeWarmup is Store.ResumeWarmup with its default.
func (s *Store) resumeWarmup() time.Duration {
	switch {
	case s.ResumeWarmup < 0:
		return 0
	case s.ResumeWarmup == 0:
		return ResumeReplicaTTL
	}
	return s.ResumeWarmup
}
