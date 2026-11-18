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
// Match: the provider request id when both sides carry it (the request-id
// response header the listener forwarded and the request_id Claude Code
// exports), else the token counts, which both sides read from the same
// provider usage block: input and output present and equal on both sides,
// and every cache and reasoning count both report equal. A listener record
// without input and output counts never matches, so the native numbers of
// that call are counted. Each record pairs at most once.
//
// Order: an agent exports a call after it has the whole answer, and the
// listener begins its record before it sends the request upstream. When a
// native record arrives, the listener record of its call is either recorded
// or still in flight. A native record that matches nothing while a listener
// call of its connector that began before it is still in flight is parked
// until those calls end (a match drops it) or for reconcileGrace, and then
// counted. A listener record that ends after that and matches the counted
// native record is not enqueued again; its budget charge stays, because a
// native record carries no budget keys.
const (
	// reconcileTTL is how long an unmatched record waits for its pair.
	reconcileTTL = 15 * time.Minute
	// reconcileGrace bounds how long a native record is parked.
	reconcileGrace = 30 * time.Second
	// reconcileMaxEntries bounds each list of one connector; the oldest
	// unmatched entry is evicted first.
	reconcileMaxEntries = 4096
	// reconcileMaxConnectors bounds the connectors tracked at once.
	reconcileMaxConnectors = 64
	reconcileMaxIDBytes    = 128
	// listenerRouteOnly is CallFacts.Listener of the route-only listener
	// (routing/engine.ListenerRouteOnly; this package imports nothing from it).
	listenerRouteOnly = "route_only"
)

type reconcileEntry struct {
	ids   [2]string
	usage Usage
	at    time.Time
}

type parkedNative struct {
	entry   reconcileEntry
	rec     Record
	waitFor uint64 // the newest listener call that began before the record arrived
	timer   *time.Timer
}

type reconcileLedger struct {
	inflight map[uint64]struct{}
	recorded []reconcileEntry // listener records not matched yet, oldest first
	late     []reconcileEntry // native records counted while a listener call was in flight
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

// providerRequestID is the provider request id of an upstream answer:
// request-id (Anthropic), x-request-id (OpenAI), x-amzn-requestid (Bedrock).
func providerRequestID(h http.Header) string {
	for _, key := range []string{"Request-Id", "X-Request-Id", "X-Amzn-Requestid"} {
		if id := boundReconcileID(h.Get(key)); id != "" {
			return id
		}
	}
	return ""
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
	l := &reconcileLedger{inflight: map[uint64]struct{}{}}
	r.ledgers[connector] = l
	return l
}

func (r *reconciler) forget(connector string, l *reconcileLedger) {
	if len(l.inflight) == 0 && len(l.recorded) == 0 && len(l.late) == 0 && len(l.parked) == 0 {
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
	if l == nil || len(l.inflight) >= reconcileMaxEntries {
		return 0
	}
	r.seq++
	l.inflight[r.seq] = struct{}{}
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
		q := reconcileEntry{ids: [2]string{requestID}, usage: rec.Usage, at: now}
		if i := pickParked(l.parked, q); i >= 0 {
			l.parked[i].timer.Stop()
			l.parked = slices.Delete(l.parked, i, i+1)
		} else if i := pickEntry(l.late, q); i >= 0 {
			l.late = slices.Delete(l.late, i, i+1)
			emit = false
		} else {
			l.recorded = appendReconcileEntry(l.recorded, q)
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
	q := reconcileEntry{
		ids:   [2]string{boundReconcileID(rec.Facts.ModelResponseID), boundReconcileID(rec.Facts.ModelRequestID)},
		usage: rec.Usage, at: now,
	}
	if i := pickEntry(l.recorded, q); i >= 0 {
		l.recorded = slices.Delete(l.recorded, i, i+1)
		r.forget(connector, l)
		return nativeMatched
	}
	if len(l.inflight) == 0 || len(l.parked) >= reconcileMaxEntries {
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
	l.late = appendReconcileEntry(l.late, p.entry)
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
			l.late = appendReconcileEntry(l.late, p.entry)
			out = append(out, p.rec)
		}
		l.parked = nil
		r.forget(connector, l)
	}
	return out
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

// trim drops entries older than reconcileTTL.
func (l *reconcileLedger) trim(now time.Time) {
	cut := now.Add(-reconcileTTL)
	trim := func(list []reconcileEntry) []reconcileEntry {
		n := 0
		for n < len(list) && list[n].at.Before(cut) {
			n++
		}
		return slices.Delete(list, 0, n)
	}
	l.recorded, l.late = trim(l.recorded), trim(l.late)
}

func appendReconcileEntry(list []reconcileEntry, entry reconcileEntry) []reconcileEntry {
	if len(list) >= reconcileMaxEntries {
		list = slices.Delete(list, 0, len(list)-reconcileMaxEntries+1)
	}
	return append(list, entry)
}

// pickEntry finds the pair of q: a shared provider request id first, then
// the oldest entry with the same token counts. -1: none.
func pickEntry(list []reconcileEntry, q reconcileEntry) int {
	for i := range list {
		if sharesReconcileID(list[i].ids, q.ids) {
			return i
		}
	}
	for i := range list {
		if usageMatches(list[i].usage, q.usage) {
			return i
		}
	}
	return -1
}

func pickParked(list []*parkedNative, q reconcileEntry) int {
	for i := range list {
		if sharesReconcileID(list[i].entry.ids, q.ids) {
			return i
		}
	}
	for i := range list {
		if usageMatches(list[i].entry.usage, q.usage) {
			return i
		}
	}
	return -1
}

func sharesReconcileID(a, b [2]string) bool {
	for _, x := range a {
		if x != "" && (x == b[0] || x == b[1]) {
			return true
		}
	}
	return false
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
