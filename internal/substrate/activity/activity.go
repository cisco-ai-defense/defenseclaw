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

// Package activity is the last-activity feed of the controller's idle
// suspend (PLAN 5.3 "Idle"): when each actor last made a hook call, a model
// call or relay traffic, and whether it has an ask waiting.
//
// Every gateway replica records what its actor listener serves (Recorder,
// gateway receive time only, E15) and sends the newest time per actor and
// kind to the leader every few seconds (MethodActivityObserve). The leader
// keeps the newest of all replicas (Store). The controller reads one
// snapshot per idle pass (Source, MethodActivitySnapshot). A lost batch
// only makes an actor look idle a few seconds early; the controller also
// needs a low CPU sample, or without a CPU feed no open attachment, before
// it suspends.
//
// KindTaskEnd is not activity: it is when an actor's --task run ended (the
// relay's report), kept apart (Snapshot.Ended) so that the controller can
// free a finished task's worker (GAP-0274).
//
// KindAttach is not activity either: a gateway reports it about every
// minute while it proxies a terminal attachment (WebSocket or long-poll),
// kept apart (Snapshot.Attached) so that a controller without a CPU feed
// never suspends an attached actor (GAP-0534).
package activity

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Kinds of activity.
const (
	KindHook   = "hook"
	KindModel  = "model"
	KindRelay  = "relay"
	KindEgress = "egress"
	// KindTaskEnd is the end of a --task run, not activity.
	KindTaskEnd = "task_end"
	// KindAttach is an open terminal attachment, not activity.
	KindAttach = "attach"
)

const (
	// DefaultFlushInterval is how often a replica sends its batch.
	DefaultFlushInterval = 5 * time.Second
	// DefaultSnapshotTTL is how long the controller reuses a snapshot.
	DefaultSnapshotTTL = 10 * time.Second
	// maxActors bounds every map here; past it the oldest entries go.
	maxActors = 100000
	// retention is how long the leader keeps an actor it heard nothing of.
	retention = 24 * time.Hour
	// replicaSilentAfter is three missed replica heartbeats.
	replicaSilentAfter = 3 * DefaultFlushInterval
	// replicaForget is how long a silent replica's last attachment report
	// stays unknown (open); past it the replica counts as gone.
	replicaForget = time.Hour
	// attachLiveAtSilence: an attachment report this close to the replica's
	// last heartbeat was still being re-sent (every minute) when it fell
	// silent.
	attachLiveAtSilence = 2 * time.Minute
	// maxReplicas bounds the heartbeat map.
	maxReplicas = 1024
	// kindHeartbeat and replicaUIDPrefix make a replica's heartbeat entry; an
	// actor UID never holds a slash.
	kindHeartbeat    = "heartbeat"
	replicaUIDPrefix = "replica/"
)

// Entry is one actor's last activity.
type Entry struct {
	Atespace string               `json:"atespace"`
	UID      string               `json:"uid"`
	Last     map[string]time.Time `json:"last"`
}

// Batch is a replica's report.
type Batch struct {
	Entries []Entry `json:"entries"`
}

// Snapshot is the leader's answer: last activity by actor UID, the UIDs
// with an ask waiting, when each actor's --task run last ended and when a
// terminal attachment of it was last seen open.
type Snapshot struct {
	Last     map[string]time.Time `json:"last"`
	Pending  []string             `json:"pending,omitempty"`
	Ended    map[string]time.Time `json:"ended,omitempty"`
	Attached map[string]time.Time `json:"attached,omitempty"`
}

// ---- gateway replica ----

// Recorder collects activity on one replica and sends it to the leader.
// ObserveActivity never blocks on the network.
type Recorder struct {
	Leader   *leader.Client
	Interval time.Duration
	// Replica names this replica (its pod name). Set, every flush carries a
	// heartbeat entry, an empty batch too, so the leader can tell a replica
	// that stopped reporting from one with nothing to report
	// (substrate-1:GAP-0578 e). Empty sends no heartbeat (the old wire).
	Replica string

	mu    sync.Mutex
	dirty map[string]*Entry // by UID
}

// ObserveActivity records one call (gateway.SubstrateActivitySink).
func (r *Recorder) ObserveActivity(kind, atespace, uid string, at time.Time) {
	if uid == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dirty == nil {
		r.dirty = map[string]*Entry{}
	}
	e, ok := r.dirty[uid]
	if !ok {
		if len(r.dirty) >= maxActors {
			return // the next flush empties the map
		}
		e = &Entry{Atespace: atespace, UID: uid, Last: map[string]time.Time{}}
		r.dirty[uid] = e
	}
	if at.After(e.Last[kind]) {
		e.Last[kind] = at
	}
}

// Flush sends what was recorded since the last flush, and the replica's
// heartbeat when Replica is set. A failed send keeps the entries for the
// next one.
func (r *Recorder) Flush(ctx context.Context) error {
	r.mu.Lock()
	batch := Batch{Entries: make([]Entry, 0, len(r.dirty)+1)}
	for _, e := range r.dirty {
		batch.Entries = append(batch.Entries, *e)
	}
	r.dirty = nil
	r.mu.Unlock()
	if r.Replica != "" {
		// An entry, not a new Batch field: a leader of the previous release
		// refuses unknown fields, and takes this as one more actor it never
		// asks about.
		batch.Entries = append(batch.Entries, Entry{UID: replicaUIDPrefix + r.Replica,
			Last: map[string]time.Time{kindHeartbeat: time.Now()}})
	}
	if len(batch.Entries) == 0 {
		return nil
	}
	err := r.Leader.Call(ctx, leader.MethodActivityObserve, leader.NewRequestID(), batch, nil)
	if err != nil {
		for _, e := range batch.Entries {
			if strings.HasPrefix(e.UID, replicaUIDPrefix) {
				continue
			}
			for k, t := range e.Last {
				r.ObserveActivity(k, e.Atespace, e.UID, t)
			}
		}
	}
	return err
}

// Run flushes every Interval until ctx ends.
func (r *Recorder) Run(ctx context.Context) {
	iv := r.Interval
	if iv <= 0 {
		iv = DefaultFlushInterval
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = r.Flush(fctx)
			cancel()
			return
		case <-t.C:
			_ = r.Flush(ctx)
		}
	}
}

// ---- leader ----

// Store is the leader's view: the newest activity of every replica.
type Store struct {
	// Pending reports the UIDs with an ask waiting (the ask store); nil is
	// none.
	Pending func() []string
	Now     func() time.Time

	mu       sync.Mutex
	last     map[string]time.Time
	ended    map[string]time.Time // KindTaskEnd
	attached map[string]time.Time // KindAttach
	seen     map[string]time.Time // when the leader last heard of the UID
	// attachVia is the replica that sent each UID's newest attachment
	// report, and replicas when the leader last heard each replica's
	// heartbeat (substrate-1:GAP-0578 e).
	attachVia map[string]string
	replicas  map[string]time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Observe merges a batch. A time in the future of the leader's clock is
// capped at now: replicas share a clock source, and an actor cannot push
// its idle time forward through a replica. A batch's heartbeat entry names
// the replica that sent it; it is not an actor.
func (s *Store) Observe(_ context.Context, b Batch) (struct{}, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		s.last, s.ended, s.seen = map[string]time.Time{}, map[string]time.Time{}, map[string]time.Time{}
		s.attached, s.attachVia, s.replicas = map[string]time.Time{}, map[string]string{}, map[string]time.Time{}
	}
	replica := ""
	for _, e := range b.Entries {
		if name, ok := strings.CutPrefix(e.UID, replicaUIDPrefix); ok && name != "" {
			replica = name
			if len(s.replicas) < maxReplicas {
				s.replicas[name] = now
			} else if _, known := s.replicas[name]; known {
				s.replicas[name] = now
			}
		}
	}
	for _, e := range b.Entries {
		if e.UID == "" || strings.HasPrefix(e.UID, replicaUIDPrefix) {
			continue
		}
		for kind, t := range e.Last {
			if t.After(now) {
				t = now
			}
			into := s.last
			switch kind {
			case KindTaskEnd:
				into = s.ended
			case KindAttach:
				into = s.attached
			}
			if t.After(into[e.UID]) {
				into[e.UID] = t
				if kind == KindAttach {
					if replica != "" {
						s.attachVia[e.UID] = replica
					} else {
						delete(s.attachVia, e.UID)
					}
				}
			}
		}
		s.seen[e.UID] = now
	}
	if len(s.last) > maxActors {
		s.prune(now)
	}
	return struct{}{}, nil
}

func (s *Store) prune(now time.Time) {
	for uid, at := range s.seen {
		if now.Sub(at) > retention || len(s.last) > maxActors {
			delete(s.seen, uid)
			delete(s.last, uid)
			delete(s.ended, uid)
			delete(s.attached, uid)
			delete(s.attachVia, uid)
		}
	}
	for name, at := range s.replicas {
		if now.Sub(at) > retention {
			delete(s.replicas, name)
		}
	}
}

// attachedNow is the attachment time the snapshot gives uid, whose newest
// report came at at (substrate-1:GAP-0578 e). A replica re-sends a report
// every minute while it proxies a terminal, and sends its heartbeat every
// flush. When the replica that sent uid's newest report has stopped
// reporting since (no heartbeat for replicaSilentAfter), while the
// attachment was still being reported (at within attachLiveAtSilence of its
// last heartbeat), the leader cannot tell a closed terminal from a replica
// that lost its way to the leader: the attachment is unknown, so it is
// reported as open now, and a controller without a CPU feed keeps the actor.
// After replicaForget of silence (a replica that is gone, as after a
// rollout) the report counts at its own time again.
func (s *Store) attachedNow(uid string, at, now time.Time) time.Time {
	via, ok := s.attachVia[uid]
	if !ok {
		return at
	}
	heard, ok := s.replicas[via]
	if !ok {
		return at
	}
	silent := now.Sub(heard)
	if silent <= replicaSilentAfter || silent > replicaForget || heard.Sub(at) > attachLiveAtSilence {
		return at
	}
	return now
}

// Snapshot answers the controller.
func (s *Store) Snapshot(context.Context, struct{}) (Snapshot, error) {
	s.mu.Lock()
	now := s.now()
	s.prune(now)
	out := Snapshot{Last: make(map[string]time.Time, len(s.last))}
	for uid, t := range s.last {
		out.Last[uid] = t
	}
	if len(s.ended) > 0 {
		out.Ended = make(map[string]time.Time, len(s.ended))
		for uid, t := range s.ended {
			out.Ended[uid] = t
		}
	}
	if len(s.attached) > 0 {
		out.Attached = make(map[string]time.Time, len(s.attached))
		for uid, t := range s.attached {
			out.Attached[uid] = s.attachedNow(uid, t, now)
		}
	}
	s.mu.Unlock()
	if s.Pending != nil {
		out.Pending = s.Pending()
	}
	return out, nil
}

// Serve registers the activity methods on the leader server.
func Serve(srv *leader.Server, s *Store) {
	srv.Handle(leader.MethodActivityObserve, leader.Typed(s.Observe))
	srv.HandleRead(leader.MethodActivitySnapshot, leader.Typed(s.Snapshot))
}

// ---- controller ----

// Source is controller.ActivitySource over the leader.
type Source struct {
	Leader *leader.Client
	TTL    time.Duration
	Now    func() time.Time

	mu      sync.Mutex
	snap    Snapshot
	pending map[string]bool
	at      time.Time
	// got is when snap came from the leader.
	got time.Time
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Source) ttl() time.Duration {
	if s.TTL <= 0 {
		return DefaultSnapshotTTL
	}
	return s.TTL
}

// fresh reports whether the snapshot in hand is recent: no older than two
// replica flushes and the TTL. An older one (the leader unreachable) makes
// every actor's activity, task end and attachment unknown, so the
// controller suspends nothing (GAP-0538).
func (s *Source) fresh() bool {
	return !s.got.IsZero() && s.now().Sub(s.got) <= 2*DefaultFlushInterval+s.ttl()
}

func (s *Source) refresh() {
	ttl := s.ttl()
	now := s.now()
	if !s.at.IsZero() && now.Sub(s.at) < ttl {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var snap Snapshot
	if err := s.Leader.Call(ctx, leader.MethodActivitySnapshot, leader.NewRequestID(), struct{}{}, &snap); err != nil {
		// Keep the last snapshot while it is fresh; retry at the next
		// pass. An actor whose activity is unknown (no fresh snapshot) is
		// not called idle for it.
		s.at = now.Add(-ttl + time.Second)
		return
	}
	s.snap, s.at, s.got = snap, now, now
	s.pending = make(map[string]bool, len(snap.Pending))
	for _, uid := range snap.Pending {
		s.pending[uid] = true
	}
}

// LastActivity implements controller.ActivitySource.
func (s *Source) LastActivity(uid string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if !s.fresh() {
		return time.Time{}, false
	}
	t, ok := s.snap.Last[uid]
	return t, ok
}

// TaskEnded implements controller.TaskEndSource.
func (s *Source) TaskEnded(uid string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if !s.fresh() {
		return time.Time{}, false
	}
	t, ok := s.snap.Ended[uid]
	return t, ok
}

// Attached implements controller.AttachSource.
func (s *Source) Attached(uid string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if !s.fresh() {
		return time.Time{}, false
	}
	t, ok := s.snap.Attached[uid]
	return t, ok
}

// PendingAsk implements controller.ActivitySource.
func (s *Source) PendingAsk(uid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return s.pending[uid]
}
