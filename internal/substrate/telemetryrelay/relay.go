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
// The queues are in the leader's memory: records not taken when the leader
// restarts, or past their bounds, are lost (counted in Dropped and reported
// to the replica that takes next).
package telemetryrelay

import (
	"context"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
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

	// Egress: the callout's decision (the extproc.Event fields the gateway
	// exports on log.egress.allowed and log.egress.blocked).
	Host          string `json:"host,omitempty"`
	Path          string `json:"path,omitempty"`
	Decision      string `json:"decision,omitempty"`
	Category      string `json:"category,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Alert         bool   `json:"alert,omitempty"`
	BodyInspected bool   `json:"body_inspected,omitempty"`
	BodyOverCap   bool   `json:"body_over_cap,omitempty"`
	// Unregistered is the leader's mark on an egress record it could not
	// tie to a registration of its atespace (a deleted actor, one DefenseClaw
	// never registered, a registration lookup outage at the callout, or a UID
	// no registration of the atespace has): its atespace and actor name are
	// the callout's, from the egress gateway's verified SPIFFE ID, and it has
	// no UID and no profile (GAP-0581). What a poster sends here is ignored.
	Unregistered bool `json:"unregistered,omitempty"`

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
	// DefaultMaxQueue and DefaultMaxQueueBytes bound each of the leader's
	// two queues (egress decisions; lifecycle records and counts) in records
	// and in bytes.
	DefaultMaxQueue      = 50000
	DefaultMaxQueueBytes = 16 << 20
	maxPostRecords       = 2000
	DefaultTakeMax       = 2000
	// maxTakeBytes bounds one take's records in bytes (at least one record
	// is handed on).
	maxTakeBytes = 1 << 20
	// MaxFieldBytes is the longest text field a record keeps; a longer one
	// is cut at a character boundary (the callout cuts paths to the same
	// 512 bytes).
	MaxFieldBytes = 512
	// recordOverhead is what a queued record costs besides its text.
	recordOverhead = 128
	// maxTakeReplay answers of the newest takes are kept, each for
	// takeReplayTTL (longer than a leader client retries), so a retried take
	// gets the same records (GAP-0582).
	maxTakeReplay = 8
	takeReplayTTL = 2 * time.Minute
	// DefaultInterval is how often posters and takers call the leader.
	DefaultInterval = 3 * time.Second
)

// Store is the leader's queue. Egress decisions, which a busy callout posts
// by the thousand, have their own queue: past its bound the oldest egress
// records go, never a lifecycle record or a controller count (GAP-0580).
type Store struct {
	// MaxQueue bounds each queue in records (DefaultMaxQueue when 0), and
	// MaxQueueBytes in bytes (DefaultMaxQueueBytes when 0): past either the
	// oldest records of that queue go.
	MaxQueue      int
	MaxQueueBytes int64
	// Registrations are the leader's actor registrations. An egress record
	// names its actor from the registration of its atespace and UID, not
	// from what the callout sent; one with no such registration is kept,
	// marked Unregistered, without a UID or profile (GAP-0581). Nil keeps
	// the posted fields (tests).
	Registrations registry.Store

	mu sync.Mutex
	// life is lifecycle records and counts, egress the egress decisions.
	life, egress queue
	gauges       map[string]int64
	dropped      int64
	// taken is the newest takes' answers by request id, oldest first.
	taken []takenAnswer
}

type takenAnswer struct {
	id  string
	at  time.Time
	out TakeResponse
}

// queue is a bounded FIFO of records and their size.
type queue struct {
	recs  []Record
	bytes int64
}

// push appends r, first dropping the oldest records past maxN or maxBytes;
// it returns how many it dropped.
func (q *queue) push(r Record, maxN int, maxBytes int64) int64 {
	size := recordSize(r)
	var dropped int64
	for len(q.recs) > 0 && (len(q.recs) >= maxN || q.bytes+size > maxBytes) {
		q.bytes -= recordSize(q.recs[0])
		q.recs[0] = Record{}
		q.recs = q.recs[1:]
		dropped++
	}
	q.recs = append(q.recs, r)
	q.bytes += size
	return dropped
}

// take removes and returns up to n records and about maxBytes from the
// front; it never returns more than n, and returns one record at least
// when one is queued and n > 0.
func (q *queue) take(n int, maxBytes int64) ([]Record, int64) {
	k, used := 0, int64(0)
	for k < n && k < len(q.recs) {
		size := recordSize(q.recs[k])
		if k > 0 && used+size > maxBytes {
			break
		}
		used += size
		k++
	}
	out := append([]Record(nil), q.recs[:k]...)
	q.recs = append(q.recs[:0:0], q.recs[k:]...)
	q.bytes -= used
	return out, used
}

// recordSize is what r costs in the queue.
func recordSize(r Record) int64 {
	n := recordOverhead
	for _, f := range textFields(&r) {
		n += len(*f)
	}
	return int64(n)
}

// textFields are r's text fields.
func textFields(r *Record) []*string {
	return []*string{&r.Kind, &r.Atespace, &r.Actor, &r.UID, &r.ParentUID, &r.Profile, &r.Template, &r.Connector,
		&r.Driver, &r.BatchID, &r.RunMode, &r.UserID, &r.UserName, &r.Lifecycle, &r.Host, &r.Path, &r.Decision,
		&r.Category, &r.Reason, &r.Metric}
}

// cutRecord cuts each text field of r to MaxFieldBytes.
func cutRecord(r Record) Record {
	for _, f := range textFields(&r) {
		*f = cutText(*f, MaxFieldBytes)
	}
	return r
}

// cutText is s cut to at most max bytes at a character boundary. A cut
// value is a copy, so it does not keep a long original alive.
func cutText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	n := max
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.Clone(s[:n])
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
// negative value, are dropped. Text fields are cut to MaxFieldBytes.
func (s *Store) Add(recs ...Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	maxN, maxBytes := s.MaxQueue, s.MaxQueueBytes
	if maxN <= 0 {
		maxN = DefaultMaxQueue
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxQueueBytes
	}
	for _, r := range recs {
		q := &s.life
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
		case KindLifecycle:
		case KindEgress:
			q = &s.egress
		default:
			continue
		}
		s.dropped += q.push(cutRecord(r), maxN, maxBytes)
	}
}

// post queues the records of a batch that accept keeps, as it returns them.
func (s *Store) post(in PostRequest, accept func(Record) (Record, bool)) {
	recs := in.Records
	if len(recs) > maxPostRecords {
		recs = recs[:maxPostRecords]
	}
	kept := make([]Record, 0, len(recs))
	for _, r := range recs {
		if r, ok := accept(r); ok {
			kept = append(kept, r)
		}
	}
	s.Add(kept...)
}

// PostCounts implements MethodPostCounts.
func (s *Store) PostCounts(_ context.Context, in PostRequest) (struct{}, error) {
	s.post(in, func(r Record) (Record, bool) { return r, r.Kind == KindCount || r.Kind == KindGauge })
	return struct{}{}, nil
}

// PostEgress implements MethodPostEgress.
func (s *Store) PostEgress(ctx context.Context, in PostRequest) (struct{}, error) {
	s.post(in, func(r Record) (Record, bool) {
		if r.Kind != KindEgress {
			return r, false
		}
		return s.egressActor(ctx, r)
	})
	return struct{}{}, nil
}

// egressActor names r's actor from the registration of its atespace and
// UID: the registration's name, and its profile where the callout named no
// deciding policy (the callout's Profile is the name of the policy that
// decided, which can differ from the registration's profile). A record no
// registration matches (no UID: a deleted actor, an unregistered one, a
// lookup outage at the callout; or a UID the atespace has no registration
// for) keeps the atespace and actor name the callout read from the egress
// gateway's verified SPIFFE ID, loses its UID and profile and is marked
// Unregistered, so its refusal still reaches log.egress.blocked (GAP-0581).
// Stripping, not dropping, a record with an unknown UID: without the UID
// and profile it can't name another actor's registration, and a poster can
// already omit the UID, so a drop would protect nothing and would lose real
// refusals made on a stale cached UID. A record with no atespace or actor
// is dropped.
func (s *Store) egressActor(ctx context.Context, r Record) (Record, bool) {
	r.Unregistered = false
	if s.Registrations == nil {
		return r, true
	}
	if r.Atespace == "" || r.Actor == "" {
		return r, false
	}
	if r.UID != "" {
		reg, ok, err := s.Registrations.Get(ctx, r.Atespace, r.UID)
		if err == nil && ok && reg.Atespace == r.Atespace && reg.UID == r.UID && reg.Name != "" {
			r.Actor = reg.Name
			if r.Profile == "" {
				r.Profile = reg.Profile
			}
			return r, true
		}
	}
	r.UID, r.Profile, r.Unregistered = "", "", true
	return r, true
}

// Take implements MethodTake: lifecycle records and counts first, then
// egress decisions, at most in.Max records and about 1 MiB. A retry of a
// recent take (the same request id) gets the same answer.
func (s *Store) Take(ctx context.Context, in TakeRequest) (TakeResponse, error) {
	n := in.Max
	if n <= 0 || n > DefaultTakeMax {
		n = DefaultTakeMax
	}
	id, now := leader.RequestIDFrom(ctx), time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.taken[:0]
	for _, t := range s.taken {
		if now.Sub(t.at) < takeReplayTTL {
			kept = append(kept, t)
		}
	}
	clear(s.taken[len(kept):])
	s.taken = kept
	if id != "" {
		for _, t := range s.taken {
			if t.id == id {
				return t.out, nil
			}
		}
	}
	out := s.takeLocked(n)
	if id != "" {
		if len(s.taken) >= maxTakeReplay {
			s.taken[0] = takenAnswer{}
			s.taken = s.taken[1:]
		}
		s.taken = append(s.taken, takenAnswer{id: id, at: now, out: out})
	}
	return out, nil
}

func (s *Store) takeLocked(n int) TakeResponse {
	recs, used := s.life.take(n, maxTakeBytes)
	if rest := n - len(recs); rest > 0 && (len(recs) == 0 || used < maxTakeBytes) {
		more, _ := s.egress.take(rest, maxTakeBytes-used)
		recs = append(recs, more...)
	}
	out := TakeResponse{Records: recs, Dropped: s.dropped}
	if len(out.Records) == 0 {
		out.Records = nil
	}
	s.dropped = 0
	if len(s.gauges) > 0 {
		out.Gauges = make(map[string]int64, len(s.gauges))
		for k, v := range s.gauges {
			out.Gauges[k] = v
		}
	}
	return out
}

// Serve registers the methods on the leader server. A take's answer (up
// to 2,000 records) is not kept in the leader's replay cache, where every
// take, under a new request id, would push hook-call answers out before
// their replay window (GAP-0582); the store replays its newest takes
// itself.
func Serve(srv *leader.Server, s *Store) {
	srv.Handle(MethodPostCounts, leader.Typed(s.PostCounts))
	srv.Handle(MethodPostEgress, leader.Typed(s.PostEgress))
	srv.HandleRead(MethodTake, leader.Typed(s.Take))
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
		p.pending = append(p.pending, cutRecord(r))
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
