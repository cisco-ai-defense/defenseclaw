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

	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// Retention bounds for the notifier ring buffer used to replay
// HISTORY / TRANSIENT_AND_HISTORY records to freshly-connected
// subscribers.
const (
	notifierRetentionMax = 10
	notifierRetentionTTL = 15 * time.Minute
	subscriberBufferSize = 32
)

// retainedRecord pairs a wire-ready NotificationRecord with the wall-
// clock time it was published so we can evict records older than
// notifierRetentionTTL at replay time.
type retainedRecord struct {
	record   *pb.NotificationRecord
	receipts time.Time
}

// broadcast is the in-process fan-out for user-visible notifications.
// Subscribers receive live records on a bounded buffered channel and
// (at subscribe time) a replay of retained HISTORY records. Slow
// subscribers are dropped, never blocked.
type broadcast struct {
	nowFn func() time.Time

	mu          sync.Mutex
	subscribers []*subscriber
	retained    []retainedRecord
}

type subscriber struct {
	ch chan *pb.NotificationRecord
}

func newBroadcast() *broadcast {
	return &broadcast{nowFn: time.Now}
}

// subscribe returns a channel that receives live NotificationRecords,
// pre-filled with any retained HISTORY / TRANSIENT_AND_HISTORY
// records still within the retention window. Callers MUST invoke
// cancel exactly once when the subscriber exits.
func (b *broadcast) subscribe() (<-chan *pb.NotificationRecord, func()) {
	sub := &subscriber{ch: make(chan *pb.NotificationRecord, subscriberBufferSize)}

	b.mu.Lock()
	b.evictExpiredLocked()
	// Snapshot retained records under lock, then replay after unlock
	// so we do not hold b.mu during the initial fill (avoids blocking
	// concurrent publishers when the buffer is well-sized).
	replay := make([]*pb.NotificationRecord, 0, len(b.retained))
	for _, r := range b.retained {
		replay = append(replay, r.record)
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

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			for i, existing := range b.subscribers {
				if existing == sub {
					b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
					break
				}
			}
			b.mu.Unlock()
			close(sub.ch)
		})
	}
	return sub.ch, cancel
}

// publish fans out one record to every current subscriber and
// (when the presentation says so) records it in the retention ring.
// Slow subscribers are dropped by non-blocking send — the block
// path must never stall on a full IPC buffer.
func (b *broadcast) publish(rec *pb.NotificationRecord) {
	if rec == nil {
		return
	}

	b.mu.Lock()
	b.evictExpiredLocked()
	if isRetained(rec.Presentation) {
		b.retained = append(b.retained, retainedRecord{record: rec, receipts: b.nowFn()})
		if len(b.retained) > notifierRetentionMax {
			// Drop the oldest to stay within the cap.
			b.retained = b.retained[len(b.retained)-notifierRetentionMax:]
		}
	}
	subs := make([]*subscriber, len(b.subscribers))
	copy(subs, b.subscribers)
	b.mu.Unlock()

	for _, s := range subs {
		select {
		case s.ch <- rec:
		default:
			// Slow subscriber — drop this record for that subscriber
			// only. Contract explicitly allows "consumer stops
			// receiving records and reconnects with bounded backoff".
		}
	}
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
