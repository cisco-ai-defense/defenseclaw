// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package telemetryrelay carries the Substrate records that the controller,
// the callout and the leader see to a gateway replica, the only component
// with the telemetry runtime that exports to the OTLP destinations
// (GAP-0450, GAP-0453). The leader keeps one bounded queue: the controller
// and the callout post to it, the leader adds the actor lifecycle events it
// already receives, and each gateway replica takes a batch every few
// seconds and records it, so every record is exported once. Gauges are kept
// as the newest value and handed to every replica.
//
// The queue is in the leader's memory: records not taken when the leader
// restarts, or past its bound, are lost (counted in Dropped and reported to
// the replica that takes next).
package telemetryrelay

import (
	"context"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Leader methods. Each poster has its own method, which accepts only its
// own kinds of record, so the callout cannot report a count and the
// controller cannot report an egress decision; lifecycle records come only
// from the leader's own lifecycle feed.
const (
	// MethodPostCounts is the controller's report: counts and gauges.
	MethodPostCounts = "TelemetryPostCounts"
	// MethodPostEgress is the callout's report: egress decisions.
	MethodPostEgress = "TelemetryPostEgress"
	// MethodTake is a gateway replica's read: it removes what it returns.
	MethodTake = "TelemetryTake"
)

// Record kinds.
const (
	KindLifecycle = "lifecycle"
	KindEgress    = "egress"
	KindCount     = "count"
	KindGauge     = "gauge"
)

// Metrics a record of kind count or gauge may name.
const (
	MetricIdleSuspends        = "idle_suspends"
	MetricPolicyConflicts     = "policy_conflicts"
	MetricUnattestedTemplates = "unattested_templates"
)

// Record is one fact for the telemetry runtime. It never carries a request
// body, a header value, a token or a secret value.
type Record struct {
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`

	// The actor, for lifecycle and egress records.
	Atespace  string `json:"atespace,omitempty"`
	Actor     string `json:"actor,omitempty"`
	UID       string `json:"uid,omitempty"`
	ParentUID string `json:"parent_uid,omitempty"`
	Profile   string `json:"profile,omitempty"`
	Template  string `json:"template,omitempty"`
	Connector string `json:"connector,omitempty"`
	// Driver is the actor's sandbox class (gvisor or microvm).
	Driver   string `json:"driver,omitempty"`
	BatchID  string `json:"batch_id,omitempty"`
	RunMode  string `json:"run_mode,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	UserName string `json:"user_name,omitempty"`

	// Lifecycle is the chainstate lifecycle event (suspended, resumed,
	// forked, reverted, deleted, crashed).
	Lifecycle string `json:"lifecycle,omitempty"`

	// Egress: the callout's decision (extproc.Event fields).
	Host          string `json:"host,omitempty"`
	Method        string `json:"method,omitempty"`
	Path          string `json:"path,omitempty"`
	Decision      string `json:"decision,omitempty"`
	Category      string `json:"category,omitempty"`
	Source        string `json:"source,omitempty"`
	Rule          string `json:"rule,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Alert         bool   `json:"alert,omitempty"`
	BodyInspected bool   `json:"body_inspected,omitempty"`
	BodyOverCap   bool   `json:"body_over_cap,omitempty"`

	// Metric and Value: a count (Value is the increment) or a gauge (the
	// current value).
	Metric string `json:"metric,omitempty"`
	Value  int64  `json:"value,omitempty"`
}

// PostRequest is a batch of records.
type PostRequest struct {
	Records []Record `json:"records"`
}

// TakeRequest asks for at most Max records.
type TakeRequest struct {
	Max int `json:"max,omitempty"`
}

// TakeResponse is what a replica records: the records it now owns, every
// gauge's newest value, and how many records the queue dropped since the
// last take.
type TakeResponse struct {
	Records []Record         `json:"records,omitempty"`
	Gauges  map[string]int64 `json:"gauges,omitempty"`
	Dropped int64            `json:"dropped,omitempty"`
}

// Bounds.
const (
	DefaultMaxQueue = 50000
	maxPostRecords  = 2000
	DefaultTakeMax  = 2000
	// DefaultInterval is how often posters and takers call the leader.
	DefaultInterval = 3 * time.Second
)

// Store is the leader's queue.
type Store struct {
	// MaxQueue bounds the queue (DefaultMaxQueue when 0): past it the
	// oldest records go.
	MaxQueue int

	mu      sync.Mutex
	q       []Record
	gauges  map[string]int64
	dropped int64
}

func validMetric(kind, m string) bool {
	switch kind {
	case KindCount:
		return m == MetricIdleSuspends || m == MetricPolicyConflicts
	case KindGauge:
		return m == MetricUnattestedTemplates
	}
	return false
}

// Add queues records; a count or gauge naming an unknown metric, and a
// negative value, are dropped.
func (s *Store) Add(recs ...Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	max := s.MaxQueue
	if max <= 0 {
		max = DefaultMaxQueue
	}
	for _, r := range recs {
		switch r.Kind {
		case KindGauge:
			if validMetric(r.Kind, r.Metric) && r.Value >= 0 {
				if s.gauges == nil {
					s.gauges = map[string]int64{}
				}
				s.gauges[r.Metric] = r.Value
			}
			continue
		case KindCount:
			if !validMetric(r.Kind, r.Metric) || r.Value <= 0 {
				continue
			}
		case KindLifecycle, KindEgress:
		default:
			continue
		}
		if len(s.q) >= max {
			s.q = s.q[1:]
			s.dropped++
		}
		s.q = append(s.q, r)
	}
}

// post queues the records of a batch whose kind allow accepts.
func (s *Store) post(in PostRequest, allow func(string) bool) {
	recs := in.Records
	if len(recs) > maxPostRecords {
		recs = recs[:maxPostRecords]
	}
	kept := make([]Record, 0, len(recs))
	for _, r := range recs {
		if allow(r.Kind) {
			kept = append(kept, r)
		}
	}
	s.Add(kept...)
}

// PostCounts implements MethodPostCounts.
func (s *Store) PostCounts(_ context.Context, in PostRequest) (struct{}, error) {
	s.post(in, func(k string) bool { return k == KindCount || k == KindGauge })
	return struct{}{}, nil
}

// PostEgress implements MethodPostEgress.
func (s *Store) PostEgress(_ context.Context, in PostRequest) (struct{}, error) {
	s.post(in, func(k string) bool { return k == KindEgress })
	return struct{}{}, nil
}

// Take implements MethodTake.
func (s *Store) Take(_ context.Context, in TakeRequest) (TakeResponse, error) {
	n := in.Max
	if n <= 0 || n > DefaultTakeMax {
		n = DefaultTakeMax
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > len(s.q) {
		n = len(s.q)
	}
	out := TakeResponse{Records: append([]Record(nil), s.q[:n]...), Dropped: s.dropped}
	s.q = append(s.q[:0:0], s.q[n:]...)
	s.dropped = 0
	if len(s.gauges) > 0 {
		out.Gauges = make(map[string]int64, len(s.gauges))
		for k, v := range s.gauges {
			out.Gauges[k] = v
		}
	}
	return out, nil
}

// Serve registers the methods on the leader server.
func Serve(srv *leader.Server, s *Store) {
	srv.Handle(MethodPostCounts, leader.Typed(s.PostCounts))
	srv.Handle(MethodPostEgress, leader.Typed(s.PostEgress))
	srv.Handle(MethodTake, leader.Typed(s.Take))
}

// Poster batches records for the leader (the controller and the callout).
// Add never blocks on the network; a failed send keeps the batch, within
// the same bound, for the next one.
type Poster struct {
	Leader *leader.Client
	// Method is MethodPostCounts (the controller) or MethodPostEgress (the
	// callout).
	Method   string
	Interval time.Duration

	mu      sync.Mutex
	pending []Record
}

// Add queues records for the next flush.
func (p *Poster) Add(recs ...Record) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range recs {
		if r.Kind == KindGauge {
			// Only the newest value of a gauge matters.
			kept := p.pending[:0]
			for _, o := range p.pending {
				if o.Kind != KindGauge || o.Metric != r.Metric {
					kept = append(kept, o)
				}
			}
			p.pending = kept
		}
		if len(p.pending) >= DefaultMaxQueue {
			p.pending = p.pending[1:]
		}
		p.pending = append(p.pending, r)
	}
}

// Flush sends what is pending.
func (p *Poster) Flush(ctx context.Context) error {
	p.mu.Lock()
	batch := p.pending
	if len(batch) > maxPostRecords {
		batch = batch[:maxPostRecords]
	}
	p.pending = append([]Record(nil), p.pending[len(batch):]...)
	p.mu.Unlock()
	if len(batch) == 0 || p.Leader == nil {
		return nil
	}
	err := p.Leader.Call(ctx, p.Method, leader.NewRequestID(), PostRequest{Records: batch}, nil)
	if err != nil {
		p.mu.Lock()
		p.pending = append(batch, p.pending...)
		if over := len(p.pending) - DefaultMaxQueue; over > 0 {
			p.pending = p.pending[over:]
		}
		p.mu.Unlock()
	}
	return err
}

// Run flushes every Interval until ctx ends, and once more then.
func (p *Poster) Run(ctx context.Context) {
	runEvery(ctx, p.Interval, true, func(ctx context.Context) { _ = p.Flush(ctx) })
}

// Taker is a gateway replica's loop: it takes batches from the leader and
// hands them to Record.
type Taker struct {
	Leader   *leader.Client
	Interval time.Duration
	// Record is called with each batch the replica now owns.
	Record func(context.Context, TakeResponse)
}

// TakeOnce takes and records one batch.
func (t *Taker) TakeOnce(ctx context.Context) error {
	var out TakeResponse
	if err := t.Leader.Call(ctx, MethodTake, leader.NewRequestID(), TakeRequest{Max: DefaultTakeMax}, &out); err != nil {
		return err
	}
	if t.Record != nil {
		t.Record(ctx, out)
	}
	return nil
}

// Run takes every Interval until ctx ends. It takes nothing at the end: a
// replica shutting down could not record what it took.
func (t *Taker) Run(ctx context.Context) {
	runEvery(ctx, t.Interval, false, func(ctx context.Context) { _ = t.TakeOnce(ctx) })
}

func runEvery(ctx context.Context, iv time.Duration, final bool, fn func(context.Context)) {
	if iv <= 0 {
		iv = DefaultInterval
	}
	tk := time.NewTicker(iv)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			if final {
				fctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				fn(fctx)
				cancel()
			}
			return
		case <-tk.C:
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			fn(cctx)
			cancel()
		}
	}
}

// Pending is a copy of what the next flush sends (tests and diagnostics).
func (p *Poster) Pending() []Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Record(nil), p.pending...)
}
