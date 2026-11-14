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
// only makes an actor look idle a few seconds early; the controller still
// needs a low CPU sample before it suspends.
package activity

import (
	"context"
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

// Snapshot is the leader's answer: last activity by actor UID, and the UIDs
// with an ask waiting.
type Snapshot struct {
	Last    map[string]time.Time `json:"last"`
	Pending []string             `json:"pending,omitempty"`
}

// ---- gateway replica ----

// Recorder collects activity on one replica and sends it to the leader.
// ObserveActivity never blocks on the network.
type Recorder struct {
	Leader   *leader.Client
	Interval time.Duration

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

// Flush sends what was recorded since the last flush. A failed send keeps
// the entries for the next one.
func (r *Recorder) Flush(ctx context.Context) error {
	r.mu.Lock()
	batch := Batch{Entries: make([]Entry, 0, len(r.dirty))}
	for _, e := range r.dirty {
		batch.Entries = append(batch.Entries, *e)
	}
	r.dirty = nil
	r.mu.Unlock()
	if len(batch.Entries) == 0 {
		return nil
	}
	err := r.Leader.Call(ctx, leader.MethodActivityObserve, leader.NewRequestID(), batch, nil)
	if err != nil {
		for _, e := range batch.Entries {
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

	mu   sync.Mutex
	last map[string]time.Time
	seen map[string]time.Time // when the leader last heard of the UID
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Observe merges a batch. A time in the future of the leader's clock is
// capped at now: replicas share a clock source, and an actor cannot push
// its idle time forward through a replica.
func (s *Store) Observe(_ context.Context, b Batch) (struct{}, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		s.last, s.seen = map[string]time.Time{}, map[string]time.Time{}
	}
	for _, e := range b.Entries {
		if e.UID == "" {
			continue
		}
		for _, t := range e.Last {
			if t.After(now) {
				t = now
			}
			if t.After(s.last[e.UID]) {
				s.last[e.UID] = t
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
		}
	}
}

// Snapshot answers the controller.
func (s *Store) Snapshot(context.Context, struct{}) (Snapshot, error) {
	s.mu.Lock()
	s.prune(s.now())
	out := Snapshot{Last: make(map[string]time.Time, len(s.last))}
	for uid, t := range s.last {
		out.Last[uid] = t
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
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Source) refresh() {
	ttl := s.TTL
	if ttl <= 0 {
		ttl = DefaultSnapshotTTL
	}
	now := s.now()
	if !s.at.IsZero() && now.Sub(s.at) < ttl {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var snap Snapshot
	if err := s.Leader.Call(ctx, leader.MethodActivitySnapshot, leader.NewRequestID(), struct{}{}, &snap); err != nil {
		// Keep the last snapshot; retry at the next pass. An actor whose
		// activity is unknown is not called idle for it (LastActivity
		// reports false only when no snapshot ever arrived).
		s.at = now.Add(-ttl + time.Second)
		return
	}
	s.snap, s.at = snap, now
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
	t, ok := s.snap.Last[uid]
	return t, ok
}

// PendingAsk implements controller.ActivitySource.
func (s *Source) PendingAsk(uid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return s.pending[uid]
}
