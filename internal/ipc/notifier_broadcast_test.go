// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"strconv"
	"sync"
	"testing"
	"time"

	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

func rec(title string, presentation pb.NotificationPresentation) *pb.NotificationRecord {
	return &pb.NotificationRecord{
		SchemaVersion: schemaVersion,
		Severity:      pb.NotificationSeverity_NOTIFICATION_SEVERITY_INFO,
		Presentation:  presentation,
		Title:         title,
	}
}

func drain(t *testing.T, ch <-chan *pb.NotificationRecord, n int, wait time.Duration) []*pb.NotificationRecord {
	t.Helper()
	got := make([]*pb.NotificationRecord, 0, n)
	deadline := time.After(wait)
	for len(got) < n {
		select {
		case r := <-ch:
			got = append(got, r)
		case <-deadline:
			return got
		}
	}
	return got
}

func TestBroadcastLivePublishAndCancel(t *testing.T) {
	b := newBroadcast()
	ch, cancel := b.subscribe()

	b.publish(rec("A", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT))
	b.publish(rec("B", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT))

	got := drain(t, ch, 2, time.Second)
	if len(got) != 2 || got[0].Title != "A" || got[1].Title != "B" {
		t.Fatalf("got %+v", titles(got))
	}

	cancel()
	if _, ok := <-ch; ok {
		t.Errorf("channel should be closed after cancel")
	}
}

func TestBroadcastReplaysHistoryOnSubscribe(t *testing.T) {
	b := newBroadcast()

	// Publish before any subscriber connects.
	b.publish(rec("hist-1", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	b.publish(rec("both-1", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY))
	b.publish(rec("transient-1", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT))

	ch, cancel := b.subscribe()
	defer cancel()

	got := drain(t, ch, 3, 500*time.Millisecond)
	names := titles(got)

	// Transient-1 must NOT be in the replay; history + both must be.
	if len(got) != 2 {
		t.Fatalf("expected 2 replay records, got %d: %v", len(got), names)
	}
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	if !seen["hist-1"] || !seen["both-1"] || seen["transient-1"] {
		t.Errorf("replay set = %v; expected {hist-1, both-1} only", names)
	}
}

func TestBroadcastEvictsExpiredRetention(t *testing.T) {
	b := newBroadcast()
	base := time.Unix(1_700_000_000, 0)
	b.nowFn = func() time.Time { return base }

	// Publish while "now" is base.
	b.publish(rec("old", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))

	// Advance the clock past the TTL and publish a new record so the
	// evictor runs.
	b.nowFn = func() time.Time { return base.Add(notifierRetentionTTL + time.Second) }
	b.publish(rec("fresh", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))

	ch, cancel := b.subscribe()
	defer cancel()

	got := drain(t, ch, 2, 500*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("expected 1 replay record after eviction, got %d: %v", len(got), titles(got))
	}
	if got[0].Title != "fresh" {
		t.Errorf("expected fresh record replayed, got %q", got[0].Title)
	}
}

func TestBroadcastCapsRetentionAtMax(t *testing.T) {
	b := newBroadcast()
	// Push twice the cap; the oldest should be evicted to keep the
	// buffer bounded.
	for i := 0; i < notifierRetentionMax*2; i++ {
		title := "r" + string(rune('a'+i%26))
		b.publish(rec(title, pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	}
	if got := len(b.retained); got != notifierRetentionMax {
		t.Errorf("retained cap: got %d want %d", got, notifierRetentionMax)
	}
}

func TestBroadcastDropsSlowSubscriber(t *testing.T) {
	b := newBroadcast()
	_, cancel := b.subscribe()
	defer cancel()

	// Never drain the subscriber. Publish more than the buffer
	// capacity — extra publishes should be dropped for the slow
	// subscriber and the call must not block.
	for i := 0; i < subscriberBufferSize*4; i++ {
		b.publish(rec("x", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT))
	}
	// If we got here without deadlock, the drop-on-full-buffer path is
	// exercised. Explicitly assert publish is non-blocking within a
	// short deadline.
	done := make(chan struct{})
	go func() {
		b.publish(rec("y", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("publish blocked on full subscriber buffer — must be non-blocking")
	}
}

// TestBroadcastStampsIdAndSequence asserts every published record
// receives a fresh id and a monotonically increasing sequence, and
// that retained records replayed to a late subscriber carry the
// SAME id + sequence as the original live publish so consumers can
// dedup replay against records they already saw.
func TestBroadcastStampsIdAndSequence(t *testing.T) {
	b := newBroadcast()
	// Deterministic id allocator so we can assert exact values.
	var idCounter int
	b.idFn = func() string {
		idCounter++
		return "id-" + strconv.Itoa(idCounter)
	}

	live, cancelLive := b.subscribe()
	defer cancelLive()

	b.publish(rec("first", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	b.publish(rec("second", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY))
	b.publish(rec("third", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))

	got := drain(t, live, 3, time.Second)
	if len(got) != 3 {
		t.Fatalf("live subscriber got %d records, want 3", len(got))
	}
	for i, r := range got {
		wantSeq := uint64(i + 1)
		wantID := "id-" + strconv.Itoa(i+1)
		if r.Sequence != wantSeq {
			t.Errorf("live[%d].Sequence = %d, want %d", i, r.Sequence, wantSeq)
		}
		if r.NotificationId != wantID {
			t.Errorf("live[%d].NotificationId = %q, want %q", i, r.NotificationId, wantID)
		}
	}

	// Late subscriber must receive retained replay with the SAME
	// ids and sequences. The dedup contract depends on this.
	late, cancelLate := b.subscribe()
	defer cancelLate()
	replay := drain(t, late, 3, 500*time.Millisecond)
	if len(replay) != 3 {
		t.Fatalf("late subscriber got %d replayed records, want 3", len(replay))
	}
	for i, r := range replay {
		wantSeq := uint64(i + 1)
		wantID := "id-" + strconv.Itoa(i+1)
		if r.Sequence != wantSeq {
			t.Errorf("replay[%d].Sequence = %d, want %d", i, r.Sequence, wantSeq)
		}
		if r.NotificationId != wantID {
			t.Errorf("replay[%d].NotificationId = %q, want %q", i, r.NotificationId, wantID)
		}
	}
}

// TestBroadcastConcurrentPublishCancel exercises the publish/cancel
// race under `go test -race`. Regression guard for the earlier
// implementation which released the mutex before sending, letting
// a concurrent cancel close the channel underneath publish and
// crash with "send on closed channel".
func TestBroadcastConcurrentPublishCancel(t *testing.T) {
	b := newBroadcast()

	const publishers = 4
	const subscribers = 8
	const iterations = 200

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Publishers hammer publish() in a tight loop.
	for i := 0; i < publishers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					b.publish(rec("burst", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT))
				}
			}
		}()
	}

	// Subscribers churn subscribe/cancel repeatedly.
	for i := 0; i < subscribers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, cancel := b.subscribe()
				// Immediately cancel — we're stress-testing the
				// close path, not consumption.
				cancel()
			}
		}()
	}

	// Give the loop a slice of wall-clock so the publishers pile
	// up while subscribers cancel underneath them, then stop.
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Any send-on-closed-channel panic is caught by the race
	// detector's crash handler; reaching this line is the assertion.
}

func titles(rs []*pb.NotificationRecord) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Title
	}
	return out
}
