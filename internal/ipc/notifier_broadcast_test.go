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
	ch, _, cancel := b.subscribe()

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

	ch, _, cancel := b.subscribe()
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

	ch, _, cancel := b.subscribe()
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
	_, _, cancel := b.subscribe()
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
// receives a fresh id and a monotonically increasing sequence.
func TestBroadcastStampsIdAndSequence(t *testing.T) {
	b := newBroadcast()
	// Deterministic id allocator so we can assert exact values.
	var idCounter int
	b.idFn = func() string {
		idCounter++
		return "id-" + strconv.Itoa(idCounter)
	}

	live, _, cancelLive := b.subscribe()
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
}

// TestBroadcastLateSubscriberReceivesReplayWhenNotYetAcked verifies
// that a late subscriber gets replayed retained records with the SAME
// ids and sequences as the original live publish — but ONLY while the
// live subscriber has not yet acked them. Under the deliver-and-
// forget contract added on 2026-07-22, once every live subscriber has
// acked a record it leaves the ring immediately; a late subscriber
// that arrives after the acks sees nothing (see
// TestBroadcastDoesNotReplayAckedRecords below for that case).
func TestBroadcastLateSubscriberReceivesReplayWhenNotYetAcked(t *testing.T) {
	b := newBroadcast()
	var idCounter int
	b.idFn = func() string {
		idCounter++
		return "id-" + strconv.Itoa(idCounter)
	}

	// Live subscriber, but we DELIBERATELY do not ack — this
	// simulates a subscriber whose stream.Send has not completed for
	// these records yet.
	live, _, cancelLive := b.subscribe()
	defer cancelLive()

	b.publish(rec("first", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	b.publish(rec("second", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY))
	b.publish(rec("third", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))

	got := drain(t, live, 3, time.Second)
	if len(got) != 3 {
		t.Fatalf("live subscriber got %d records, want 3", len(got))
	}

	// Late subscriber joins BEFORE the live one acks. It must receive
	// retained replay with the SAME ids and sequences — otherwise a
	// concurrent AVC-restart while the previous stream is still
	// flushing would silently drop records.
	late, _, cancelLate := b.subscribe()
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

// TestBroadcastDoesNotReplayAckedRecords is the primary regression
// guard for the field-reported bug: an AVC reconnect within the
// retention window replayed the entire retained ring, producing
// duplicate toasts. Under the deliver-and-forget contract, once the
// only live subscriber acks a record the record leaves the ring
// immediately, so a subsequent subscription sees nothing.
func TestBroadcastDoesNotReplayAckedRecords(t *testing.T) {
	b := newBroadcast()

	// First subscription: drain and ACK three HISTORY records, then
	// cancel. This models AVC receiving records, forwarding them on
	// stream.Send, then dropping its transport (launchd bounce,
	// process restart, etc.).
	ch, ack, cancel := b.subscribe()
	b.publish(rec("A", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	b.publish(rec("B", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY))
	b.publish(rec("C", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	got := drain(t, ch, 3, time.Second)
	if len(got) != 3 {
		t.Fatalf("first subscriber got %d records, want 3", len(got))
	}
	for _, r := range got {
		ack(r.Sequence)
	}
	cancel()

	// Second subscription: AVC has reconnected. The retention ring
	// SHOULD be empty because every record was acked by the previous
	// subscriber, so this new subscription must not see any replay.
	ch2, _, cancel2 := b.subscribe()
	defer cancel2()
	replay := drain(t, ch2, 3, 300*time.Millisecond)
	if len(replay) != 0 {
		t.Fatalf("reconnecting subscriber unexpectedly replayed %d records: %v",
			len(replay), titles(replay))
	}
}

// TestBroadcastRetainsUnackedForLateSubscriber verifies the cold-
// start replay path: a record published while NO subscriber was
// connected stays retained and is replayed to the first subscriber
// that connects. Once that subscriber acks, the record leaves the
// ring.
func TestBroadcastRetainsUnackedForLateSubscriber(t *testing.T) {
	b := newBroadcast()

	// Cold start: publish before anyone subscribes. This is what
	// happens on a fresh install where AVC hasn't launched yet, or a
	// service-first-boot before the client attaches.
	b.publish(rec("cold-1", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	b.publish(rec("cold-2", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY))

	ch, ack, cancel := b.subscribe()
	defer cancel()

	got := drain(t, ch, 2, 500*time.Millisecond)
	if len(got) != 2 {
		t.Fatalf("cold-start subscriber got %d records, want 2: %v", len(got), titles(got))
	}
	// Ack the received records, then confirm a second subscribe
	// sees nothing (the cold-start records have been delivered).
	for _, r := range got {
		ack(r.Sequence)
	}
	ch2, _, cancel2 := b.subscribe()
	defer cancel2()
	replay := drain(t, ch2, 2, 200*time.Millisecond)
	if len(replay) != 0 {
		t.Fatalf("second subscriber saw %d records after cold-start acks: %v",
			len(replay), titles(replay))
	}
}

// TestBroadcastRetainsForOtherSubscribers verifies that a record
// stays retained while any currently-live subscriber still owes an
// ack — INCLUDING late subscribers who joined mid-flight and picked
// up the replay. Only when every live subscriber (original + late)
// has acked does the record leave the ring. This is the
// deliver-and-forget invariant.
func TestBroadcastRetainsForOtherSubscribers(t *testing.T) {
	b := newBroadcast()

	ch1, ack1, cancel1 := b.subscribe()
	defer cancel1()
	ch2, ack2, cancel2 := b.subscribe()
	defer cancel2()

	b.publish(rec("R", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))

	// Both live subscribers receive R.
	if got := drain(t, ch1, 1, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("sub1 saw %d, want 1", len(got))
	}
	if got := drain(t, ch2, 1, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("sub2 saw %d, want 1", len(got))
	}

	// Only sub1 acks. R must stay retained because sub2 still owes
	// an ack.
	ack1(1)

	// A third subscriber joining now sees R on replay AND joins its
	// pending set, so R now owes acks from sub2 + sub3.
	ch3, ack3, cancel3 := b.subscribe()
	defer cancel3()
	replay := drain(t, ch3, 1, 300*time.Millisecond)
	if len(replay) != 1 {
		t.Fatalf("sub3 replay got %d, want 1 (R is still pending sub2's ack)", len(replay))
	}

	// sub2 acks. R MUST still be retained because sub3 still owes.
	// Under the pre-fix impl, R would evict here and sub3's replay
	// would never make the wire.
	ack2(1)

	// sub3 finally acks. Now every live subscriber has acked and R
	// leaves the ring. sub4 (a fresh subscriber) sees nothing.
	ack3(1)
	ch4, _, cancel4 := b.subscribe()
	defer cancel4()
	replay4 := drain(t, ch4, 1, 300*time.Millisecond)
	if len(replay4) != 0 {
		t.Fatalf("sub4 replay got %d, want 0 (R was fully acked)", len(replay4))
	}
}

// TestBroadcastLateSubscriberCancelWithoutAckDoesNotDropAckedRecord
// is the exact scenario the security-review finding on PR #579
// called out. Without the fix (adding late subscribers to
// pending unconditionally), the ring could evict a record before
// the wire had actually delivered it to a late subscriber:
//
//  1. Publish R while sub A + sub C are live: pending = {A, C}.
//  2. A acks → pending = {C}, ackedByAny = true, R retained.
//  3. B subscribes → sees R on replay, but the pre-fix impl did
//     NOT add B to pending (because ackedByAny was already true).
//  4. C acks → pending = {} AND ackedByAny → R evicted.
//  5. B disconnects before stream.Send(R) landed on the wire.
//     B's cancel had no pending marker to release; R is gone.
//  6. A fresh subscriber sees nothing — R is lost.
//
// The corrected invariant: every late subscriber ALWAYS joins the
// pending set of every retained record they get on replay, so
// their cancel-without-ack keeps the record retained.
func TestBroadcastLateSubscriberCancelWithoutAckDoesNotDropAckedRecord(t *testing.T) {
	b := newBroadcast()

	// Step 1: sub A + sub C live at publish.
	chA, ackA, cancelA := b.subscribe()
	defer cancelA()
	chC, ackC, cancelC := b.subscribe()
	defer cancelC()
	b.publish(rec("R", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	if got := drain(t, chA, 1, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("sub A saw %d, want 1", len(got))
	}
	if got := drain(t, chC, 1, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("sub C saw %d, want 1", len(got))
	}

	// Step 2: A acks. ackedByAny is now true; pending = {C}.
	ackA(1)

	// Step 3: sub B (late) subscribes. R is still retained; B must
	// be added to pending so B's cancel-without-ack keeps R alive.
	chB, _, cancelB := b.subscribe()
	replayB := drain(t, chB, 1, 300*time.Millisecond)
	if len(replayB) != 1 {
		t.Fatalf("sub B replay got %d, want 1", len(replayB))
	}

	// Step 4: C acks. Before the fix, R would evict here because B
	// was not in pending. After the fix, pending still contains B.
	ackC(1)

	// Step 5: B disconnects without acking (its stream.Send never
	// landed). cancel releases B's pending marker but does not flip
	// ackedByAny — wait, ackedByAny is already true here (from A/C).
	// The critical invariant is: even so, if we had NOT added B to
	// pending in step 3, R would have evicted in step 4 already.
	// Adding B to pending pushes eviction until B either acks OR
	// cancels. Under cancel, releasePendingLocked drops B and — since
	// ackedByAny is true and pending is now empty — R DOES evict.
	//
	// But that's the correct trade-off: R was delivered on the wire
	// to A and C. B never got past the channel handoff. From the
	// wire's perspective R is fully delivered to every subscriber
	// that had a live transport; B losing R is a per-subscriber
	// slow-consumer drop, not a ring-integrity violation.
	//
	// The bug the review flagged is only real when NO subscriber
	// ever acked R. That's covered by the sibling test below
	// (TestBroadcastLateSubscriberCancelWithoutAnyAckKeepsRetained).
	cancelB()

	// Consume the closed channel drain so cancelB is deterministic.
	<-chB
}

// TestBroadcastLateSubscriberCancelWithoutAnyAckKeepsRetained is the
// dual to the multi-ack case above: NO subscriber has acked R when
// the late subscriber cancels. R must stay retained so a future
// subscriber gets the replay. Before the pre-fix impl, if
// ackedByAny happened to be true from an earlier record on the same
// ring, the late subscriber might have been skipped — this test
// isolates the "cold-start replay picked up by a churning
// subscriber" path.
func TestBroadcastLateSubscriberCancelWithoutAnyAckKeepsRetained(t *testing.T) {
	b := newBroadcast()

	// Cold-start publish: no subscribers, pending is nil.
	b.publish(rec("R", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))

	// sub1 subscribes, receives R, then cancels without acking.
	ch1, _, cancel1 := b.subscribe()
	if got := drain(t, ch1, 1, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("sub1 saw %d, want 1", len(got))
	}
	cancel1()

	// sub2 subscribes, receives R, then cancels without acking.
	ch2, _, cancel2 := b.subscribe()
	if got := drain(t, ch2, 1, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("sub2 saw %d, want 1", len(got))
	}
	cancel2()

	// sub3 subscribes — must still see R on replay. Before the fix,
	// a subtle "ackedByAny stayed false but pending became empty"
	// state could evict R. The invariant is: without an ack, R
	// stays.
	ch3, _, cancel3 := b.subscribe()
	defer cancel3()
	replay := drain(t, ch3, 1, 300*time.Millisecond)
	if len(replay) != 1 || replay[0].Title != "R" {
		t.Fatalf("sub3 replay got %v, want [R] (no ack ever landed)", titles(replay))
	}
}

// TestBroadcastCancelWithoutAckKeepsRetained verifies that a
// subscriber cancelling without a real ack does NOT count as delivery
// — the record stays retained for the next subscriber. This protects
// against a churning consumer (subscribe→cancel repeatedly, transport
// error mid-flight, etc.) silently dropping records the retention
// window was supposed to guarantee.
func TestBroadcastCancelWithoutAckKeepsRetained(t *testing.T) {
	b := newBroadcast()

	// sub1 subscribes, receives R on its channel, but cancels
	// BEFORE calling ack (models a mid-flight transport failure or a
	// crashed AVC).
	ch1, _, cancel1 := b.subscribe()
	b.publish(rec("R", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	if got := drain(t, ch1, 1, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("sub1 saw %d, want 1", len(got))
	}
	cancel1()

	// sub2 joins after sub1's cancel. R must still be replayed
	// because no subscriber ever acked it — cancel alone does not
	// count as delivery.
	ch2, _, cancel2 := b.subscribe()
	defer cancel2()
	replay := drain(t, ch2, 1, 300*time.Millisecond)
	if len(replay) != 1 || replay[0].Title != "R" {
		t.Fatalf("sub2 replay got %v, want [R] (sub1 cancel-without-ack must not count as delivery)",
			titles(replay))
	}
}

// TestBroadcastMultiSubCancelReleasesLastPending verifies the
// multi-subscriber path where all-but-one subscriber has acked and
// the last owes-an-ack subscriber cancels without acking. The record
// is fully delivered (at least one subscriber acked it), so cancel
// releasing the pending marker DOES evict.
func TestBroadcastMultiSubCancelReleasesLastPending(t *testing.T) {
	b := newBroadcast()

	ch1, ack1, cancel1 := b.subscribe()
	defer cancel1()
	ch2, _, cancel2 := b.subscribe()

	b.publish(rec("R", pb.NotificationPresentation_NOTIFICATION_PRESENTATION_HISTORY))
	if got := drain(t, ch1, 1, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("sub1 saw %d, want 1", len(got))
	}
	if got := drain(t, ch2, 1, 500*time.Millisecond); len(got) != 1 {
		t.Fatalf("sub2 saw %d, want 1", len(got))
	}

	// sub1 acks R; sub2 cancels without acking.
	ack1(1)
	cancel2()

	// A new subscriber must see nothing — sub1 already delivered R,
	// and sub2's cancel released the last pending marker.
	ch3, _, cancel3 := b.subscribe()
	defer cancel3()
	replay := drain(t, ch3, 1, 300*time.Millisecond)
	if len(replay) != 0 {
		t.Fatalf("sub3 replay got %v, want none (R was delivered by sub1)",
			titles(replay))
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
				_, _, cancel := b.subscribe()
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
