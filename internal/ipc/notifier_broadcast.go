// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"sync"
	"time"

	"github.com/google/uuid"

	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// Retention bounds for the notifier ring buffer used to replay
// HISTORY / TRANSIENT_AND_HISTORY records to freshly-connected
// subscribers.
//
// Under the deliver-and-forget contract the ring shrinks dynamically:
// once every currently-live subscriber has acked a record (see
// `subscribe`/`ackFn` docs below), the record leaves the ring
// immediately. These bounds are safety backstops for the "no
// subscriber at publish time" case — a fresh install before AVC
// starts, or a subscriber-less lab host — so the retained queue
// cannot grow without bound and stale records do not resurrect after
// a long AVC outage.
const (
	notifierRetentionMax = 10
	notifierRetentionTTL = 15 * time.Minute
	subscriberBufferSize = 32
)

// retainedRecord pairs a wire-ready NotificationRecord with the wall-
// clock time it was published, the set of currently-live subscribers
// that still owe an ack for it, and a bit that records whether the
// record has been acked by at least one subscriber. Eviction from the
// ring requires BOTH pending == empty AND ackedByAny == true — a
// subscriber cancelling without an ack releases the pending marker
// but does NOT count as delivery, so a churning consumer cannot
// silently drop records the retention window was supposed to protect.
type retainedRecord struct {
	record   *pb.NotificationRecord
	receipts time.Time
	// pending is the set of subscriber IDs (see subscriber.id) that
	// have not yet acked this record. Populated at publish time from
	// the subscribers that were live under b.mu at publish. A record
	// published while no subscribers exist has pending == nil (the
	// zero-length map is reserved for "everyone acked").
	pending map[uint64]struct{}
	// ackedByAny is true once at least one subscriber has invoked its
	// ackFn(seq) for this record. Combined with len(pending) == 0
	// this is the eviction gate. Without this flag a subscribe→
	// cancel-without-ack churn would leak "delivered" records the
	// caller never actually sent on the wire.
	ackedByAny bool
}

// broadcast is the in-process fan-out for user-visible notifications.
// Subscribers receive live records on a bounded buffered channel and
// (at subscribe time) a replay of retained HISTORY records. Slow
// subscribers are dropped, never blocked.
//
// Every record fanned out from here is stamped with:
//   - a fresh per-process UUID in NotificationRecord.notification_id
//   - a monotonically increasing sequence in NotificationRecord.sequence
//
// so reconnecting clients could historically dedup replayed retained
// records against records they had already seen. Under the deliver-
// and-forget contract added on 2026-07-22 the server drops delivered
// records from the ring automatically as subscribers ack them, so the
// wire dedup story is a safety net rather than the primary mechanism.
// Stamping is still done under b.mu at publish time so the retained
// ring and live subscribers observe the same identifiers.
type broadcast struct {
	nowFn func() time.Time
	// idFn mints per-record identifiers; production wiring uses
	// uuid.NewString. Tests replace it to keep assertions
	// deterministic without touching the production allocator.
	idFn func() string

	mu          sync.Mutex
	subscribers []*subscriber
	retained    []retainedRecord
	// nextSeq is the next value to stamp on NotificationRecord.sequence.
	// Starts at 1 and increments under b.mu.
	nextSeq uint64
	// nextSubID mints per-subscriber IDs (used as pending-map keys on
	// retainedRecord). Starts at 1 and increments under b.mu; a
	// subscriber's ID is never reused within a process lifetime, so
	// there is zero risk of a stale pending entry matching a fresh
	// subscriber.
	nextSubID uint64
}

type subscriber struct {
	id uint64
	ch chan *pb.NotificationRecord
}

func newBroadcast() *broadcast {
	return &broadcast{
		nowFn:     time.Now,
		idFn:      uuid.NewString,
		nextSeq:   1,
		nextSubID: 1,
	}
}

// subscribe returns:
//   - a channel that receives live NotificationRecords, pre-filled
//     with any retained HISTORY / TRANSIENT_AND_HISTORY records still
//     within the retention window that this subscriber has not been
//     shown yet.
//   - an ackFn(seq) that the caller MUST invoke once the record has
//     been successfully forwarded to the wire (typically after
//     stream.Send returns nil in service.WatchNotifications). Acks
//     shrink the retained ring: once every currently-live subscriber
//     has acked a record, the record leaves the ring and will not be
//     replayed to future subscribers.
//   - a cancel closure that MUST be invoked exactly once when the
//     subscriber exits. cancel removes the subscriber ID from every
//     retainedRecord.pending set, so records that were still awaiting
//     an ack from this subscriber can be evicted immediately if all
//     other subscribers have already acked them.
func (b *broadcast) subscribe() (<-chan *pb.NotificationRecord, func(uint64), func()) {
	b.mu.Lock()
	subID := b.nextSubID
	b.nextSubID++
	sub := &subscriber{id: subID, ch: make(chan *pb.NotificationRecord, subscriberBufferSize)}

	b.evictExpiredLocked()
	// Snapshot retained records under lock, then replay after unlock
	// so we do not hold b.mu during the initial fill (avoids blocking
	// concurrent publishers when the buffer is well-sized).
	//
	// A late subscriber joining an already-retained record ALWAYS
	// enters that record's pending set — regardless of whether
	// another subscriber has already acked it. Without this, the
	// following sequence loses R (reported as security finding):
	//
	//   1. Publish R while sub A + sub C are live: pending = {A, C}.
	//   2. A acks → pending = {C}, ackedByAny = true.
	//   3. B subscribes → gets R on replay. If we skipped adding B
	//      to pending on the grounds that ackedByAny is already
	//      true, B carries no ack obligation.
	//   4. C acks → pending = {} AND ackedByAny → R is evicted.
	//   5. B disconnects before stream.Send(R) landed on the wire.
	//   6. B's cancel had no pending marker to release; R is gone;
	//      the next subscriber does not see R.
	//
	// Adding B to pending in step 3 means step 5's cancel keeps R
	// retained until B (or a later subscriber) actually acks it.
	// This never wedges the ring in the churn case because
	// releasePendingLocked treats cancel-without-ack as "release the
	// marker but do not flip ackedByAny", so the invariant "drop
	// only when pending == {} AND ackedByAny" still evicts once any
	// live subscriber successfully acks.
	replay := make([]*pb.NotificationRecord, 0, len(b.retained))
	for i := range b.retained {
		if b.retained[i].pending == nil {
			b.retained[i].pending = make(map[uint64]struct{})
		}
		b.retained[i].pending[subID] = struct{}{}
		replay = append(replay, b.retained[i].record)
	}
	b.subscribers = append(b.subscribers, sub)
	b.mu.Unlock()

	for _, r := range replay {
		select {
		case sub.ch <- r:
		default:
			// Subscriber's buffer already full during replay — the
			// tail is more important than the head for a warm start,
			// so drop the oldest and try again.
			select {
			case <-sub.ch:
			default:
			}
			select {
			case sub.ch <- r:
			default:
			}
		}
	}

	ack := func(seq uint64) {
		b.ackSubscriber(subID, seq)
	}

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			// Hold b.mu across both slice mutation and channel
			// close so a concurrent publish cannot pick up this
			// subscriber and then send on its channel after
			// close. Also allocate a fresh backing array so any
			// reader that already copied the slice header sees
			// its own snapshot instead of a mutated one.
			b.mu.Lock()
			next := make([]*subscriber, 0, len(b.subscribers))
			for _, existing := range b.subscribers {
				if existing != sub {
					next = append(next, existing)
				}
			}
			b.subscribers = next
			// Remove this subscriber's pending marker from every
			// retained record. If a record is now fully acked
			// (pending set empty), evict it from the ring right
			// away — a disconnecting consumer must not wedge
			// records the remaining consumers have already seen.
			b.releasePendingLocked(subID)
			close(sub.ch)
			b.mu.Unlock()
		})
	}
	return sub.ch, ack, cancel
}

// ackSubscriber marks a specific sequence as delivered by a specific
// subscriber. Called by the ackFn closure returned from subscribe
// after the caller's stream.Send returns nil. Idempotent: acking a
// sequence twice, or acking a sequence that has already been fully
// delivered and evicted, is a no-op.
//
// A record leaves the ring when BOTH conditions hold:
//
//	len(pending) == 0    // no live subscriber still owes an ack
//	ackedByAny == true   // at least one subscriber successfully acked
//
// Both are required: a subscribe → cancel-without-ack cycle clears
// the pending marker (see releasePendingLocked) but does NOT flip
// ackedByAny, so the record survives for the next subscriber. Only a
// real ack (stream.Send succeeded) flips it.
func (b *broadcast) ackSubscriber(subID uint64, seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := b.retained[:0]
	for i := range b.retained {
		r := b.retained[i]
		if r.record != nil && r.record.Sequence == seq {
			if r.pending != nil {
				delete(r.pending, subID)
			}
			r.ackedByAny = true
			if len(r.pending) == 0 {
				// Fully delivered — drop from the ring.
				continue
			}
		}
		keep = append(keep, r)
	}
	b.retained = keep
}

// releasePendingLocked drops subID from every retained record's
// pending set and evicts records that are now fully delivered. A
// record whose pending set becomes empty is dropped ONLY if it was
// also acked by at least one subscriber (ackedByAny == true). A
// subscribe → cancel-without-ack cycle leaves the record retained so
// the next subscriber picks up the replay. Caller must hold b.mu.
func (b *broadcast) releasePendingLocked(subID uint64) {
	if len(b.retained) == 0 {
		return
	}
	keep := b.retained[:0]
	for i := range b.retained {
		r := b.retained[i]
		if r.pending != nil {
			delete(r.pending, subID)
		}
		if len(r.pending) == 0 && r.ackedByAny {
			// At least one subscriber has already acked (successful
			// stream.Send) AND no remaining live subscriber still
			// owes an ack — record is fully delivered, drop it.
			continue
		}
		keep = append(keep, r)
	}
	b.retained = keep
}

// publish fans out one record to every current subscriber and
// (when the presentation says so) records it in the retention ring.
// Slow subscribers are dropped by non-blocking send — the block
// path must never stall on a full IPC buffer.
//
// The fan-out runs under b.mu so a concurrent cancel cannot close
// a subscriber channel between our decision to send and the send
// itself. That serializes with subscribe/cancel but the per-send
// select is non-blocking, so publish still returns in bounded time
// even with dozens of subscribers.
func (b *broadcast) publish(rec *pb.NotificationRecord) {
	if rec == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.evictExpiredLocked()

	// Stamp identity + sequence under the lock so the retained ring
	// and every live subscriber see the same values. notification_id
	// and sequence take precedence over anything the caller pre-set —
	// the broadcast is the single source of truth for both.
	rec.NotificationId = b.idFn()
	rec.Sequence = b.nextSeq
	b.nextSeq++

	if isRetained(rec.Presentation) {
		var pending map[uint64]struct{}
		if len(b.subscribers) > 0 {
			// Seed the pending set from the live subscribers. Once
			// each acks the record leaves the ring; if a subscriber
			// cancels without acking, releasePendingLocked drops its
			// entry but leaves the record retained (ackedByAny stays
			// false), so the next subscriber picks up the replay.
			pending = make(map[uint64]struct{}, len(b.subscribers))
			for _, s := range b.subscribers {
				pending[s.id] = struct{}{}
			}
		}
		// pending == nil signals "cold-start queue" — no subscriber
		// was live at publish, so the record stays retained until a
		// subscriber connects (and gets a replay) or the TTL / cap
		// evict it. subscribe() populates the pending set from itself
		// on replay so a later ack correctly drops the record.
		b.retained = append(b.retained, retainedRecord{
			record:   rec,
			receipts: b.nowFn(),
			pending:  pending,
		})
		if len(b.retained) > notifierRetentionMax {
			b.retained = b.retainedTrimLocked(notifierRetentionMax)
		}
	}
	for _, s := range b.subscribers {
		select {
		case s.ch <- rec:
		default:
			// Slow subscriber — drop this record for that subscriber
			// only. Contract explicitly allows "consumer stops
			// receiving records and reconnects with bounded backoff".
		}
	}
}

// retainedTrimLocked trims b.retained down to at most maxSize entries.
// The cap is a hard bound (unbounded retention would let a stuck AVC
// balloon the ring), so if every remaining record is still mid-
// delivery to at least one subscriber we still have to drop the
// oldest. Caller must hold b.mu.
func (b *broadcast) retainedTrimLocked(maxSize int) []retainedRecord {
	if len(b.retained) <= maxSize {
		return b.retained
	}
	// Simple oldest-first eviction. The finer-grained "prefer to drop
	// records that a live subscriber never saw" heuristic would
	// prolong stale records at the cost of dropping fresh ones the
	// current subscriber hasn't seen yet — that's the wrong
	// trade-off. The deliver-and-forget path already keeps the ring
	// small in the happy case; when the cap actually kicks in the
	// subscriber-side ack cadence is degenerate anyway, and honest
	// oldest-first is easier to reason about.
	return b.retained[len(b.retained)-maxSize:]
}

// evictExpiredLocked drops retained records older than the TTL.
// Called under b.mu.
func (b *broadcast) evictExpiredLocked() {
	if len(b.retained) == 0 {
		return
	}
	cutoff := b.nowFn().Add(-notifierRetentionTTL)
	keep := b.retained[:0]
	for _, r := range b.retained {
		if r.receipts.After(cutoff) {
			keep = append(keep, r)
		}
	}
	b.retained = keep
}

// isRetained reports whether a record's presentation intent means it
// should be kept for reconnect replay. TRANSIENT-only records
// (approval prompts) are not replayed — they are ephemeral by design.
func isRetained(p pb.NotificationPresentation) bool {
	return p == pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY ||
		p == pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY
}
