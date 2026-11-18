// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// Per-call reconciliation of native usage with the route-only listener
// (rel-1-0-10 GAP-0223, GAP-1227).
//
// An agent pointed at the route-only listener still reports each model call
// in its own OTLP stream (Engine.RecordNative). For such a call the listener
// record is the one counted: it carries the routing facts, the verified
// caller and the budget keys. The native record of the same call is a
// cross-check only. A native record of a call the listener did not record (a
// session started before routing enable, a managed user the guardian has not
// rendered, a call that went direct because gateway signing could not start,
// a request the listener forwarded without usage facts) is counted. The
// answer comes from what the listener recorded, never from the config, so a
// reload or a routing enable or disable between a call and its export
// changes nothing.
//
// Match: the provider request id when both sides carry one (the Anthropic
// request-id response header the listener forwarded, which Claude Code
// exports as request_id). Two different ids are two calls and never pair.
// When one side has no id, the token counts decide: both sides read them
// from the same provider usage block, so input and output must be present
// and equal on both sides, and every cache and reasoning count both report
// must be equal. A listener record without input and output counts never
// matches, so the native numbers of that call are counted. Each record pairs
// at most once. Only connectors whose native usage is imported are tracked.
//
// Order: an agent exports a call after it has the whole answer, and the
// listener begins its record before it sends the request upstream. When a
// native record arrives, the listener record of its call is either recorded
// or still in flight. A native record that matches nothing while a listener
// call of its connector that began before it is still in flight is parked
// until those calls end (a match drops it) or for reconcileGrace, and then
// counted. A listener record that ends after that and matches the counted
// native record is not enqueued again; its budget charge stays, because a
// native record carries no budget keys. That call's stored row is then the
// native one, without the routing facts.
//
// Residual double counts (a call counted twice is preferred over a call
// lost): the export arrives more than reconcileTTL after the call, the
// gateway restarted in between (the ledger is in memory), an entry was
// evicted at the caps, or the two sides report different counts and only
// one carries an id. When no side carries an id (Codex, Bedrock), two calls
// of one connector with equal counts within reconcileTTL may pair the wrong
// way round: the totals stay right while both exports arrive.
const (
	// reconcileTTL is how long an unmatched record, or a listener call in
	// flight, waits for its pair.
	reconcileTTL = 15 * time.Minute
	// reconcileGrace bounds how long a native record is parked.
	reconcileGrace = 30 * time.Second
	// reconcileMaxEntries bounds each list of one connector; the oldest
	// entry is evicted first.
	reconcileMaxEntries = 4096
	// reconcileMaxConnectors bounds the connectors tracked at once.
	reconcileMaxConnectors = 64
	reconcileMaxIDBytes    = 128
)

type reconcileEntry struct {
	id    string // provider request id, "" when unknown
	usage Usage
	at    time.Time
	used  bool
}

// entryQueue is a FIFO of entries, oldest first. A paired entry is marked
// used and dropped once it reaches the head, so push, pair and trim cost O(1)
// amortised; a search is linear.
type entryQueue struct {
	items []reconcileEntry
	head  int
}

func (q *entryQueue) size() int { return len(q.items) - q.head }

func (q *entryQueue) push(e reconcileEntry) {
	if q.size() >= reconcileMaxEntries {
		q.items[q.head] = reconcileEntry{}
		q.head++
	}
	q.items = append(q.items, e)
	q.compact()
}

// trim drops paired entries and entries older than cut from the head.
func (q *entryQueue) trim(cut time.Time) {
	for q.head < len(q.items) && (q.items[q.head].used || q.items[q.head].at.Before(cut)) {
		q.items[q.head] = reconcileEntry{}
		q.head++
	}
	q.compact()
}

func (q *entryQueue) compact() {
	if q.head == 0 || q.head < len(q.items)/2 {
		return
	}
	n := copy(q.items, q.items[q.head:])
	clear(q.items[n:])
	q.items, q.head = q.items[:n], 0
}

// take pairs the entry matching e and reports whether there was one.
func (q *entryQueue) take(e reconcileEntry) bool {
	live := q.items[q.head:]
	i := pickPair(len(live), func(i int) (reconcileEntry, bool) { return live[i], !live[i].used }, e)
	if i < 0 {
		return false
	}
	live[i].used = true
	return true
}

type parkedNative struct {
	entry   reconcileEntry
	rec     Record
	waitFor uint64 // the newest listener call that began before the record arrived
	timer   *time.Timer
}

type reconcileLedger struct {
	inflight map[uint64]time.Time // listener calls in flight, by begin time
	recorded entryQueue           // listener records not matched yet
	late     entryQueue           // native records counted while a listener call was in flight
	parked   []*parkedNative
}

// reconciler is the per-call ledger of one engine. The zero value is ready.
type reconciler struct {
	mu      sync.Mutex
	seq     uint64
	ledgers map[string]*reconcileLedger
	grace   time.Duration // 0: reconcileGrace
}

type nativeOutcome int

const (
	nativeCount nativeOutcome = iota
	nativeMatched
	nativeParked
)

// routeOnlyListener reports whether f is a call of the route-only listener.
func routeOnlyListener(f CallFacts) bool {
	return f.Listener == engine.ListenerRouteOnly && f.CallRole == RoleAgent
}

func reconcileConnector(connector string) string {
	return strings.ToLower(strings.TrimSpace(connector))
}

func boundReconcileID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) > reconcileMaxIDBytes {
		return ""
	}
	return id
}

// providerRequestID is the Anthropic request-id of an upstream answer, the
// id Claude Code exports as request_id. Other providers' ids are not read:
// no agent exports them, and an id one side lacks never blocks a match.
func providerRequestID(h http.Header) string {
	return boundReconcileID(h.Get("Request-Id"))
}

func (r *reconciler) ledger(connector string, create bool) *reconcileLedger {
	if l := r.ledgers[connector]; l != nil || !create {
		return l
	}
	if r.ledgers == nil {
		r.ledgers = map[string]*reconcileLedger{}
	}
	if len(r.ledgers) >= reconcileMaxConnectors {
		return nil
	}
	l := &reconcileLedger{inflight: map[uint64]time.Time{}}
	r.ledgers[connector] = l
	return l
}

func (r *reconciler) forget(connector string, l *reconcileLedger) {
	if len(l.inflight) == 0 && l.recorded.size() == 0 && l.late.size() == 0 && len(l.parked) == 0 {
		delete(r.ledgers, connector)
	}
}

// begin registers one route-only listener call in flight. 0: not tracked.
func (r *reconciler) begin(connector string) uint64 {
	if connector == "" {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	l := r.ledger(connector, true)
	if l == nil {
		return 0
	}
	now := time.Now()
	l.trim(now)
	if len(l.inflight) >= reconcileMaxEntries {
		return 0
	}
	r.seq++
	l.inflight[r.seq] = now
	return r.seq
}

// listenerEnd settles one tracked listener call. emit is false when a
// native record of the same call was counted already; release are the parked
// native records no listener call in flight can match any more.
func (r *reconciler) listenerEnd(connector string, seq uint64, requestID string, rec Record) (emit bool, release []Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l := r.ledgers[connector]
	if l == nil {
		return true, nil
	}
	delete(l.inflight, seq)
	now := time.Now()
	l.trim(now)
	emit = true
	if usageKeyed(rec.Usage) {
		q := reconcileEntry{id: requestID, usage: rec.Usage, at: now}
		if i := pickPair(len(l.parked), func(i int) (reconcileEntry, bool) { return l.parked[i].entry, true }, q); i >= 0 {
			l.parked[i].timer.Stop()
			l.parked = slices.Delete(l.parked, i, i+1)
		} else if l.late.take(q) {
			emit = false
		} else {
			l.recorded.push(q)
		}
	}
	release = l.releasable()
	r.forget(connector, l)
	return emit, release
}

// native decides one native record: matched (a listener record of the same
// call exists, not counted), parked (a listener call that may be the same
// call is in flight) or count.
func (r *reconciler) native(e *Engine, rec Record) nativeOutcome {
	connector := reconcileConnector(rec.Facts.Connector)
	if connector == "" || rec.Facts.CallRole != RoleAgent {
		return nativeCount
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	l := r.ledgers[connector]
	if l == nil {
		return nativeCount
	}
	now := time.Now()
	l.trim(now)
	q := reconcileEntry{id: boundReconcileID(rec.Facts.ModelResponseID), usage: rec.Usage, at: now}
	if l.recorded.take(q) {
		l.recorded.trim(now.Add(-reconcileTTL))
		r.forget(connector, l)
		return nativeMatched
	}
	if len(l.inflight) == 0 || len(l.parked) >= reconcileMaxEntries {
		r.forget(connector, l)
		return nativeCount
	}
	grace := r.grace
	if grace <= 0 {
		grace = reconcileGrace
	}
	p := &parkedNative{entry: q, rec: rec, waitFor: r.seq}
	p.timer = time.AfterFunc(grace, func() { r.expire(e, connector, p) })
	l.parked = append(l.parked, p)
	return nativeParked
}

// expire counts a parked native record whose grace ran out.
func (r *reconciler) expire(e *Engine, connector string, p *parkedNative) {
	r.mu.Lock()
	l := r.ledgers[connector]
	i := -1
	if l != nil {
		i = slices.Index(l.parked, p)
	}
	if i < 0 {
		r.mu.Unlock()
		return
	}
	l.parked = slices.Delete(l.parked, i, i+1)
	p.entry.at = time.Now()
	l.late.push(p.entry)
	r.mu.Unlock()
	e.countNative(p.rec)
}

// drain releases every parked native record (the engine is turned off).
func (r *reconciler) drain() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Record
	now := time.Now()
	for connector, l := range r.ledgers {
		for _, p := range l.parked {
			p.timer.Stop()
			p.entry.at = now
			l.late.push(p.entry)
			out = append(out, p.rec)
		}
		l.parked = nil
		r.forget(connector, l)
	}
	return out
}

// trim drops entries and listener calls in flight older than reconcileTTL,
// so a call that never ended cannot hold native records back for ever.
func (l *reconcileLedger) trim(now time.Time) {
	cut := now.Add(-reconcileTTL)
	l.recorded.trim(cut)
	l.late.trim(cut)
	for seq, began := range l.inflight {
		if began.Before(cut) {
			delete(l.inflight, seq)
		}
	}
}

// releasable removes and returns the parked records that waited for no
// listener call still in flight.
func (l *reconcileLedger) releasable() []Record {
	if len(l.parked) == 0 {
		return nil
	}
	oldest := uint64(math.MaxUint64)
	for seq := range l.inflight {
		oldest = min(oldest, seq)
	}
	var out []Record
	kept := l.parked[:0]
	for _, p := range l.parked {
		if p.waitFor < oldest {
			p.timer.Stop()
			out = append(out, p.rec)
			continue
		}
		kept = append(kept, p)
	}
	clear(l.parked[len(kept):])
	l.parked = kept
	return out
}

// pickPair finds the pair of q among n candidates (at returns candidate i
// and whether it may pair): the same provider request id first, then the
// oldest candidate with equal counts that does not carry a different id.
// -1: none.
func pickPair(n int, at func(int) (reconcileEntry, bool), q reconcileEntry) int {
	if q.id != "" {
		for i := 0; i < n; i++ {
			if c, ok := at(i); ok && c.id == q.id {
				return i
			}
		}
	}
	for i := 0; i < n; i++ {
		c, ok := at(i)
		if ok && (c.id == "" || q.id == "") && usageMatches(c.usage, q.usage) {
			return i
		}
	}
	return -1
}

// usageKeyed reports whether u carries the input and output counts a match
// needs.
func usageKeyed(u Usage) bool {
	return u.Has&(HasInput|HasOutput) == HasInput|HasOutput
}

// usageMatches reports whether two usage blocks are the same provider count:
// input and output equal, and every other count both carry equal.
func usageMatches(a, b Usage) bool {
	if !usageKeyed(a) || !usageKeyed(b) || a.Input != b.Input || a.Output != b.Output {
		return false
	}
	for _, c := range []struct {
		bit  Has
		x, y int64
	}{
		{HasCacheRead, a.CacheRead, b.CacheRead},
		{HasCacheCreation, a.CacheCreation, b.CacheCreation},
		{HasReasoning, a.Reasoning, b.Reasoning},
	} {
		if a.Has&c.bit != 0 && b.Has&c.bit != 0 && c.x != c.y {
			return false
		}
	}
	return true
}
