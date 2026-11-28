// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"sort"
	"sync"
	"time"
)

const (
	// leaderSinkBucketCap bounds the aggregate a replica keeps for its leader.
	leaderSinkBucketCap = 20000
	// leaderSinkKeepHours is how long a bucket stays in memory after its hour
	// ended (a late stream still lands in its own hour). A finished, pushed
	// bucket is then dropped: the leader keeps its last absolute value.
	leaderSinkKeepHours = 6
	// LeaderPushBatch is the most rows one push carries.
	LeaderPushBatch = 2000
)

// RemoteRow is one hourly bucket as a gateway replica reports it to the
// leader: absolute totals since the replica's epoch, never a delta, so a
// retry or a re-send changes nothing. It holds counts, cost and the bounded
// dimension keys (owner, actor, batch, atespace, connector, provider,
// model, route, role, profile, family, cost basis). It never holds prompt
// text, a header or a key.
type RemoteRow struct {
	Hour      int64  `json:"hour"`
	Owner     string `json:"owner"`
	Actor     string `json:"actor,omitempty"`
	Batch     string `json:"batch,omitempty"`
	Atespace  string `json:"atespace,omitempty"`
	Connector string `json:"connector"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Route     string `json:"route"`
	Role      string `json:"role"`
	Profile   string `json:"profile"`
	Family    string `json:"family"`
	Basis     string `json:"basis"`

	Calls         int64    `json:"calls"`
	Errors        int64    `json:"errors,omitempty"`
	UsageCalls    int64    `json:"usage_calls"`
	Input         int64    `json:"input"`
	Output        int64    `json:"output"`
	CacheRead     int64    `json:"cache_read"`
	CacheCreation int64    `json:"cache_creation"`
	Reasoning     int64    `json:"reasoning"`
	CostUSD       *float64 `json:"cost_usd,omitempty"`
	CostCalls     int64    `json:"cost_calls"`
	LatencyMs     float64  `json:"latency_ms"`
}

type leaderKey struct {
	hour                                    int64
	owner, actor, batch, atespace           string
	connector, provider, model, route, role string
	prof, family, basis                     string
}

type leaderEntry struct {
	agg  usageAgg
	ver  uint64 // bumped on every record
	sent uint64 // ver the leader last acknowledged
}

// LeaderSink is the replica side of the cluster usage store: a bounded
// hourly aggregate in memory, pushed to the leader on the sync interval by
// a goroutine of the gateway. Emit does one lock and one map update and
// never touches the network or the disk, so a model call pays nothing for
// it.
type LeaderSink struct {
	mu       sync.Mutex
	epoch    string
	entries  map[leaderKey]*leaderEntry
	dirty    map[leaderKey]struct{} // entries the leader has not acknowledged
	overflow int64
	now      func() time.Time
}

// NewLeaderSink returns a sink that reports under epoch (one gateway
// process).
func NewLeaderSink(epoch string) *LeaderSink {
	return &LeaderSink{epoch: epoch, entries: map[leaderKey]*leaderEntry{}, dirty: map[leaderKey]struct{}{}, now: time.Now}
}

// Epoch names this process to the leader.
func (s *LeaderSink) Epoch() string { return s.epoch }

// Emit implements Sink.
func (s *LeaderSink) Emit(_ context.Context, rec Record) {
	if s == nil {
		return
	}
	f, c := rec.Facts, rec.Cost
	k := leaderKey{
		hour: rec.EndedAt.UTC().Truncate(time.Hour).Unix(), owner: OwnerID(f),
		actor: dimOrEmpty(f.Actor), batch: dimOrEmpty(f.BatchID), atespace: dimOrEmpty(f.Atespace),
		connector: dim(storeConnector(f.Connector)), provider: boundedOther(rec.ProviderKey), model: boundedOther(rec.ModelKey),
		route: dim(f.Route.Decision), role: dim(string(f.CallRole)), prof: dim(f.ProfileName), family: dim(string(f.APIFamily)), basis: dim(c.Basis),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[k]
	if e == nil {
		if len(s.entries) >= leaderSinkBucketCap {
			s.overflow++
			return
		}
		e = &leaderEntry{}
		s.entries[k] = e
	}
	addRecord(&e.agg, rec)
	e.ver++
	s.dirty[k] = struct{}{}
}

// dimOrEmpty is dim for a dimension that is empty off a cluster.
func dimOrEmpty(v string) string {
	if v == "" {
		return ""
	}
	return dim(v)
}

// Overflow is how many records were dropped at the bucket cap.
func (s *LeaderSink) Overflow() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overflow
}

// Pending is the buckets that changed since the leader last acknowledged
// them (at most LeaderPushBatch, oldest hour first), as absolute totals. Ack
// them with Acked after a successful push.
func (s *LeaderSink) Pending() []PendingRow {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []PendingRow
	for k := range s.dirty {
		e := s.entries[k]
		if e == nil || e.sent == e.ver {
			delete(s.dirty, k)
			continue
		}
		out = append(out, PendingRow{RemoteRow: e.row(k), ver: e.ver, key: k})
	}
	sortPending(out)
	if len(out) > LeaderPushBatch {
		out = out[:LeaderPushBatch]
	}
	return out
}

// PendingRow is a row with the version it was read at.
type PendingRow struct {
	RemoteRow
	ver uint64
	key leaderKey
}

// Rows is the wire rows of pending.
func Rows(p []PendingRow) []RemoteRow {
	out := make([]RemoteRow, len(p))
	for i := range p {
		out[i] = p[i].RemoteRow
	}
	return out
}

// Acked marks rows as stored at the leader, and drops buckets of hours
// that are long over and fully stored (the memory stays bounded).
func (s *LeaderSink) Acked(rows []PendingRow) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rows {
		if e := s.entries[r.key]; e != nil && e.sent < r.ver {
			e.sent = r.ver
			if e.sent == e.ver {
				delete(s.dirty, r.key)
			}
		}
	}
	cutoff := s.now().UTC().Add(-leaderSinkKeepHours * time.Hour).Truncate(time.Hour).Unix()
	for k, e := range s.entries {
		if k.hour < cutoff && e.sent == e.ver {
			delete(s.entries, k)
			delete(s.dirty, k)
		}
	}
}

func (e *leaderEntry) row(k leaderKey) RemoteRow {
	a := e.agg
	r := RemoteRow{
		Hour: k.hour, Owner: k.owner, Actor: k.actor, Batch: k.batch, Atespace: k.atespace,
		Connector: k.connector, Provider: k.provider, Model: k.model, Route: k.route, Role: k.role,
		Profile: k.prof, Family: k.family, Basis: k.basis,
		Calls: a.calls, Errors: a.errors, UsageCalls: a.usageCalls, Input: a.input, Output: a.output,
		CacheRead: a.cacheRead, CacheCreation: a.cacheCreate, Reasoning: a.reasoning,
		CostCalls: a.costCalls, LatencyMs: a.latencyMs,
	}
	if a.costCalls > 0 {
		v := a.costSum
		r.CostUSD = &v
	}
	return r
}

func sortPending(p []PendingRow) {
	sort.Slice(p, func(i, j int) bool {
		a, b := p[i].key, p[j].key
		switch {
		case a.hour != b.hour:
			return a.hour < b.hour
		case a.owner != b.owner:
			return a.owner < b.owner
		case a.actor != b.actor:
			return a.actor < b.actor
		case a.model != b.model:
			return a.model < b.model
		}
		return a.connector+a.provider+a.route+a.role+a.prof+a.family+a.basis+a.batch+a.atespace <
			b.connector+b.provider+b.route+b.role+b.prof+b.family+b.basis+b.batch+b.atespace
	})
}
